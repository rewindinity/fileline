package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	fileline_config "fileline/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ErrInvalidKey is returned when a storage key is not a single, plain file name
var ErrInvalidKey = errors.New("storage: invalid key")

// Provider defines the interface for file storage operations.
type Provider interface {
	Save(ctx context.Context, key string, reader io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// StagedProvider is an optional extension of Provider for backends that support
// direct chunked staging at arbitrary byte offsets and zero-copy O(1) commit.
type StagedProvider interface {
	Provider
	CreateStaged(ctx context.Context, uploadID string, storageKey string, totalSize int64, chunkSize int64) (StagedUpload, error)
}

// StagedUpload represents an active staged chunked upload session.
type StagedUpload interface {
	// WriteChunk streams chunk content into the staged target at byte offset up to maxBytes.
	// Implementations must support concurrent calls for non-overlapping offsets.
	WriteChunk(ctx context.Context, chunkIndex int, offset int64, r io.Reader, maxBytes int64) (written int64, err error)
	// Commit verifies that total size matches expectedSize and moves the object live under storageKey.
	Commit(ctx context.Context, storageKey string, expectedSize int64) error
	// Abort cleans up any temporary staged data.
	Abort(ctx context.Context) error
}

// SeekableProvider is an optional extension of Provider for backends (such as local disk)
// that can return an io.ReadSeekCloser suitable for http.ServeContent (Range, conditional requests, and sendfile).
type SeekableProvider interface {
	Provider
	Open(ctx context.Context, key string) (io.ReadSeekCloser, error)
}

// RangedObject holds metadata and body from a ranged or head S3 object retrieval.
type RangedObject struct {
	Body          io.ReadCloser
	ContentLength int64
	ContentRange  string
	ETag          string
	LastModified  *s3ObjectTime
	IsPartial     bool
}

type s3ObjectTime = int64

// RangeProvider is an optional extension of Provider for remote object stores (such as S3)
// that support byte-range GET and HEAD operations without streaming the full object.
type RangeProvider interface {
	Provider
	GetRange(ctx context.Context, key string, rangeHeader string) (*RangedObject, error)
	Head(ctx context.Context, key string) (*RangedObject, error)
}

// LocalProvider implements Provider for local disk storage.
type LocalProvider struct {
	basePath string
}

// NewLocalProvider creates a new local storage provider.
func NewLocalProvider(basePath string) (*LocalProvider, error) {
	if err := os.MkdirAll(basePath, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create upload directory: %w", err)
	}
	return &LocalProvider{basePath: basePath}, nil
}

// validateLocalKey accepts only a single path component
func validateLocalKey(key string) error {
	if key == "" || key == "." || key == ".." || strings.ContainsAny(key, "/\\\x00") {
		return fmt.Errorf("%w: %q", ErrInvalidKey, key)
	}
	return nil
}

// openRoot opens the storage directory as an os.Root
func (p *LocalProvider) openRoot(key string) (*os.Root, error) {
	if err := validateLocalKey(key); err != nil {
		return nil, err
	}
	return os.OpenRoot(p.basePath)
}

func (p *LocalProvider) Save(ctx context.Context, key string, reader io.Reader) error {
	root, err := p.openRoot(key)
	if err != nil {
		return err
	}
	defer root.Close()

	// O_EXCL: never overwrite an existing object.
	out, err := root.OpenFile(key, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, reader); err != nil {
		out.Close()
		_ = root.Remove(key)
		return err
	}
	if err := out.Close(); err != nil {
		_ = root.Remove(key)
		return err
	}
	return nil
}

// Open opens a stored file and returns an io.ReadSeekCloser (*os.File) confined to basePath via os.Root.
func (p *LocalProvider) Open(ctx context.Context, key string) (io.ReadSeekCloser, error) {
	root, err := p.openRoot(key)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(key)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (p *LocalProvider) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return p.Open(ctx, key)
}

func (p *LocalProvider) Delete(ctx context.Context, key string) error {
	root, err := p.openRoot(key)
	if err != nil {
		return err
	}
	defer root.Close()
	err = root.Remove(key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

func (p *LocalProvider) CreateStaged(ctx context.Context, uploadID string, storageKey string, totalSize int64, chunkSize int64) (StagedUpload, error) {
	if err := validateLocalKey(uploadID); err != nil {
		return nil, err
	}
	if err := validateLocalKey(storageKey); err != nil {
		return nil, err
	}
	root, err := p.openRoot(uploadID)
	if err != nil {
		return nil, err
	}
	tempName := ".tmp_upload_" + uploadID
	f, err := root.OpenFile(tempName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("failed to create staged file: %w", err)
	}
	if totalSize > 0 {
		_ = f.Truncate(totalSize)
	}
	l := &localStagedUpload{
		root:      root,
		file:      f,
		tempName:  tempName,
		totalSize: totalSize,
	}
	l.cond = sync.NewCond(&l.mu)
	return l, nil
}

type localStagedUpload struct {
	mu        sync.Mutex
	cond      *sync.Cond
	root      *os.Root
	file      *os.File
	tempName  string
	totalSize int64
	closed    bool
	active    int
}

func (l *localStagedUpload) WriteChunk(ctx context.Context, chunkIndex int, offset int64, r io.Reader, maxBytes int64) (int64, error) {
	l.mu.Lock()
	if l.closed || l.file == nil {
		l.mu.Unlock()
		return 0, errors.New("staged upload closed")
	}
	f := l.file
	l.active++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.active--
		l.cond.Broadcast()
		l.mu.Unlock()
	}()

	bufPtr := copyBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer copyBufPool.Put(bufPtr)

	var totalWritten int64
	limit := maxBytes
	if limit > 0 {
		limit = maxBytes + 1
	}

	for {
		if err := ctx.Err(); err != nil {
			return totalWritten, err
		}
		readSize := len(buf)
		if limit > 0 && int64(readSize) > limit-totalWritten {
			readSize = int(limit - totalWritten)
			if readSize <= 0 {
				break
			}
		}
		nr, rErr := r.Read(buf[:readSize])
		if nr > 0 {
			nw, wErr := f.WriteAt(buf[:nr], offset+totalWritten)
			totalWritten += int64(nw)
			if wErr != nil {
				return totalWritten, fmt.Errorf("failed to write chunk at offset %d: %w", offset+totalWritten, wErr)
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			return totalWritten, rErr
		}
	}
	return totalWritten, nil
}

func (l *localStagedUpload) Commit(ctx context.Context, storageKey string, expectedSize int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("staged upload already completed or closed")
	}
	l.closed = true
	for l.active > 0 {
		l.cond.Wait()
	}

	if err := validateLocalKey(storageKey); err != nil {
		if l.file != nil {
			_ = l.file.Close()
		}
		if l.root != nil {
			_ = l.root.Remove(l.tempName)
			_ = l.root.Close()
		}
		return err
	}

	fi, err := l.file.Stat()
	if err != nil {
		_ = l.file.Close()
		_ = l.root.Remove(l.tempName)
		_ = l.root.Close()
		return fmt.Errorf("failed to stat staged file: %w", err)
	}
	if fi.Size() != expectedSize {
		_ = l.file.Close()
		_ = l.root.Remove(l.tempName)
		_ = l.root.Close()
		return fmt.Errorf("staged file size mismatch: got %d, want %d", fi.Size(), expectedSize)
	}

	_ = l.file.Sync()
	if err := l.file.Close(); err != nil {
		_ = l.root.Remove(l.tempName)
		_ = l.root.Close()
		return fmt.Errorf("failed to close staged file: %w", err)
	}

	if err := l.root.Rename(l.tempName, storageKey); err != nil {
		_ = l.root.Remove(l.tempName)
		_ = l.root.Close()
		return fmt.Errorf("failed to commit staged file: %w", err)
	}
	return l.root.Close()
}

func (l *localStagedUpload) Abort(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	for l.active > 0 {
		l.cond.Wait()
	}
	if l.file != nil {
		_ = l.file.Close()
	}
	if l.root != nil {
		_ = l.root.Remove(l.tempName)
		_ = l.root.Close()
	}
	return nil
}

// DiskFallbackStagedUpload implements StagedUpload for storage providers that do not
// support zero-copy staged renames. It streams chunks via WriteAt to a single temp file
// and streams it to provider.Save on Commit.
type DiskFallbackStagedUpload struct {
	mu         sync.Mutex
	cond       *sync.Cond
	tempFile   *os.File
	tempPath   string
	totalSize  int64
	targetProv Provider
	closed     bool
	active     int
}

func NewDiskFallbackStagedUpload(tempDir string, uploadID string, storageKey string, totalSize int64, targetProv Provider) (*DiskFallbackStagedUpload, error) {
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return nil, err
	}
	tempPath := filepath.Join(tempDir, ".tmp_fallback_"+uploadID)
	f, err := os.OpenFile(tempPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if totalSize > 0 {
		_ = f.Truncate(totalSize)
	}
	d := &DiskFallbackStagedUpload{
		tempFile:   f,
		tempPath:   tempPath,
		totalSize:  totalSize,
		targetProv: targetProv,
	}
	d.cond = sync.NewCond(&d.mu)
	return d, nil
}

func (d *DiskFallbackStagedUpload) WriteChunk(ctx context.Context, chunkIndex int, offset int64, r io.Reader, maxBytes int64) (int64, error) {
	d.mu.Lock()
	if d.closed || d.tempFile == nil {
		d.mu.Unlock()
		return 0, errors.New("staged upload closed")
	}
	f := d.tempFile
	d.active++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.active--
		d.cond.Broadcast()
		d.mu.Unlock()
	}()

	bufPtr := copyBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer copyBufPool.Put(bufPtr)

	var totalWritten int64
	limit := maxBytes
	if limit > 0 {
		limit = maxBytes + 1
	}

	for {
		if err := ctx.Err(); err != nil {
			return totalWritten, err
		}
		readSize := len(buf)
		if limit > 0 && int64(readSize) > limit-totalWritten {
			readSize = int(limit - totalWritten)
			if readSize <= 0 {
				break
			}
		}
		nr, rErr := r.Read(buf[:readSize])
		if nr > 0 {
			nw, wErr := f.WriteAt(buf[:nr], offset+totalWritten)
			totalWritten += int64(nw)
			if wErr != nil {
				return totalWritten, fmt.Errorf("failed to write chunk at offset %d: %w", offset+totalWritten, wErr)
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			return totalWritten, rErr
		}
	}
	return totalWritten, nil
}

func (d *DiskFallbackStagedUpload) Commit(ctx context.Context, storageKey string, expectedSize int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("staged upload already completed or closed")
	}
	d.closed = true
	for d.active > 0 {
		d.cond.Wait()
	}

	defer func() {
		if d.tempFile != nil {
			_ = d.tempFile.Close()
		}
		_ = os.Remove(d.tempPath)
	}()

	fi, err := d.tempFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat staged file: %w", err)
	}
	if fi.Size() != expectedSize {
		return fmt.Errorf("staged file size mismatch: got %d, want %d", fi.Size(), expectedSize)
	}
	if _, err := d.tempFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek staged file: %w", err)
	}
	return d.targetProv.Save(ctx, storageKey, d.tempFile)
}

func (d *DiskFallbackStagedUpload) Abort(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	for d.active > 0 {
		d.cond.Wait()
	}
	if d.tempFile != nil {
		_ = d.tempFile.Close()
	}
	_ = os.Remove(d.tempPath)
	return nil
}

// S3Provider implements Provider for S3 compatible storage.
type S3Provider struct {
	client *s3.Client
	bucket string
}

const s3OperationTimeout = 15 * time.Minute

func validateS3Endpoint(endpoint string, useSSL, allowInsecure bool) error {
	if endpoint == "" {
		return nil
	}
	if strings.Contains(endpoint, "://") {
		return fmt.Errorf("S3 endpoint must be a host:port without a scheme")
	}
	u, err := url.Parse("https://" + endpoint)
	if err != nil || u.Host != endpoint || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid S3 endpoint")
	}
	if !useSSL && !allowInsecure {
		return errors.New("S3 endpoint must use HTTPS unless allow_insecure_s3_dev is enabled")
	}
	return nil
}

func s3Context(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s3OperationTimeout)
}

// NewS3Provider creates a new S3 storage provider.
func NewS3Provider(ctx context.Context, cfg *fileline_config.Config) (*S3Provider, error) {
	if err := validateS3Endpoint(cfg.S3Endpoint, cfg.S3UseSSL, cfg.AllowInsecureS3); err != nil {
		return nil, err
	}
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if cfg.S3Endpoint != "" {
			schema := "https"
			if !cfg.S3UseSSL {
				schema = "http"
			}
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           fmt.Sprintf("%s://%s", schema, cfg.S3Endpoint),
				SigningRegion: cfg.S3Region,
			}, nil
		}
		// fallback to default
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})

	awsCfg, err := aws_config.LoadDefaultConfig(ctx,
		aws_config.WithRegion(cfg.S3Region),
		aws_config.WithEndpointResolverWithOptions(resolver),
		aws_config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.S3AccessKey, cfg.S3SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load s3 config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true // Many S3-compatible providers require this
	})

	return &S3Provider{
		client: client,
		bucket: cfg.S3Bucket,
	}, nil
}

func NewS3ProviderFromDrive(ctx context.Context, drive fileline_config.Drive) (*S3Provider, error) {
	if err := validateS3Endpoint(drive.S3Endpoint, drive.S3UseSSL, drive.AllowInsecureS3); err != nil {
		return nil, err
	}
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if drive.S3Endpoint != "" {
			schema := "https"
			if !drive.S3UseSSL {
				schema = "http"
			}
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           fmt.Sprintf("%s://%s", schema, drive.S3Endpoint),
				SigningRegion: drive.S3Region,
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})
	awsCfg, err := aws_config.LoadDefaultConfig(ctx,
		aws_config.WithRegion(drive.S3Region),
		aws_config.WithEndpointResolverWithOptions(resolver),
		aws_config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(drive.S3AccessKey, drive.S3SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load s3 config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	return &S3Provider{
		client: client,
		bucket: drive.S3Bucket,
	}, nil
}

func (p *S3Provider) Save(ctx context.Context, key string, reader io.Reader) error {
	_, err := p.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
		Body:   reader,
	})
	return err
}

func (p *S3Provider) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := p.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

func (p *S3Provider) GetRange(ctx context.Context, key string, rangeHeader string) (*RangedObject, error) {
	in := &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	}
	if rangeHeader != "" {
		in.Range = aws.String(rangeHeader)
	}
	out, err := p.client.GetObject(ctx, in)
	if err != nil {
		return nil, err
	}
	ro := &RangedObject{
		Body:      out.Body,
		IsPartial: rangeHeader != "" && aws.ToString(out.ContentRange) != "",
	}
	if out.ContentLength != nil {
		ro.ContentLength = *out.ContentLength
	}
	if out.ContentRange != nil {
		ro.ContentRange = *out.ContentRange
	}
	if out.ETag != nil {
		ro.ETag = *out.ETag
	}
	return ro, nil
}

func (p *S3Provider) Head(ctx context.Context, key string) (*RangedObject, error) {
	out, err := p.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	ro := &RangedObject{}
	if out.ContentLength != nil {
		ro.ContentLength = *out.ContentLength
	}
	if out.ETag != nil {
		ro.ETag = *out.ETag
	}
	return ro, nil
}

func (p *S3Provider) Delete(ctx context.Context, key string) error {
	_, err := p.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	return err
}

func (p *S3Provider) CreateStaged(ctx context.Context, uploadID string, storageKey string, totalSize int64, chunkSize int64) (StagedUpload, error) {
	if chunkSize >= 5*1024*1024 && totalSize >= 5*1024*1024 {
		out, err := p.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(p.bucket),
			Key:    aws.String(storageKey),
		})
		if err == nil && out.UploadId != nil {
			s := &s3MultipartStagedUpload{
				client:    p.client,
				bucket:    p.bucket,
				key:       storageKey,
				uploadID:  *out.UploadId,
				totalSize: totalSize,
				parts:     make(map[int]string),
			}
			s.cond = sync.NewCond(&s.mu)
			return s, nil
		}
	}
	fallbackDir := os.TempDir()
	if envDir := strings.TrimSpace(os.Getenv("FL_CHUNKS_DIR")); envDir != "" {
		fallbackDir = envDir
	}
	return NewDiskFallbackStagedUpload(fallbackDir, uploadID, storageKey, totalSize, p)
}

type s3MultipartStagedUpload struct {
	mu        sync.Mutex
	cond      *sync.Cond
	client    *s3.Client
	bucket    string
	key       string
	uploadID  string
	totalSize int64
	chunkSize int64
	parts     map[int]string
	closed    bool
	active    int
}

type s3CountingReader struct {
	r io.Reader
	n int64
}

func (cr *s3CountingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

func (s *s3MultipartStagedUpload) WriteChunk(ctx context.Context, chunkIndex int, offset int64, r io.Reader, maxBytes int64) (int64, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, errors.New("upload closed")
	}
	s.active++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.cond.Broadcast()
		s.mu.Unlock()
	}()

	partNum := int32(chunkIndex + 1)
	limit := maxBytes
	if limit > 0 {
		limit = maxBytes + 1
	}
	cr := &s3CountingReader{r: io.LimitReader(r, limit)}
	opCtx, cancel := s3Context(ctx)
	defer cancel()
	out, err := s.client.UploadPart(opCtx, &s3.UploadPartInput{
		Bucket:     aws.String(s.bucket),
		Key:        aws.String(s.key),
		UploadId:   aws.String(s.uploadID),
		PartNumber: &partNum,
		Body:       cr,
	})
	if err != nil {
		return cr.n, err
	}
	if out.ETag != nil {
		s.mu.Lock()
		s.parts[chunkIndex] = *out.ETag
		s.mu.Unlock()
	}
	return cr.n, nil
}

func (s *s3MultipartStagedUpload) Commit(ctx context.Context, storageKey string, expectedSize int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("upload already completed or closed")
	}
	s.closed = true
	for s.active > 0 {
		s.cond.Wait()
	}

	var completedParts []types.CompletedPart
	for idx := 0; idx < len(s.parts); idx++ {
		etag, ok := s.parts[idx]
		if !ok {
			_ = s.abortLocked(ctx)
			return fmt.Errorf("missing part %d for s3 multipart upload", idx)
		}
		pNum := int32(idx + 1)
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: &pNum,
			ETag:       aws.String(etag),
		})
	}

	opCtx, cancel := s3Context(ctx)
	defer cancel()
	_, err := s.client.CompleteMultipartUpload(opCtx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(s.key),
		UploadId: aws.String(s.uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		_ = s.abortLocked(ctx)
		return err
	}
	return nil
}

func (s *s3MultipartStagedUpload) abortLocked(ctx context.Context) error {
	opCtx, cancel := s3Context(ctx)
	defer cancel()
	_, err := s.client.AbortMultipartUpload(opCtx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(s.key),
		UploadId: aws.String(s.uploadID),
	})
	return err
}

func (s *s3MultipartStagedUpload) Abort(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for s.active > 0 {
		s.cond.Wait()
	}
	return s.abortLocked(ctx)
}

// NewProvider creates a new storage provider based on configuration.
func NewProvider(ctx context.Context, cfg *fileline_config.Config) (Provider, error) {
	if cfg.StorageType == "s3" {
		return NewS3Provider(ctx, cfg)
	}
	// default to local
	path := cfg.LocalStoragePath
	if path == "" {
		path = "./uploads"
	}
	return NewLocalProvider(path)
}

func NewProviderFromDrive(ctx context.Context, drive fileline_config.Drive) (Provider, error) {
	if drive.Type == "s3" {
		return NewS3ProviderFromDrive(ctx, drive)
	}
	path := drive.LocalStoragePath
	if path == "" {
		path = "./uploads"
	}
	return NewLocalProvider(path)
}
