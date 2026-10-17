package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	fileline_config "fileline/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ErrInvalidKey is returned when a storage key is not a single, plain file name
var ErrInvalidKey = errors.New("storage: invalid key")

// Provider defines the interface for file storage operations.
type Provider interface {
	Save(ctx context.Context, key string, reader io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
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

func (p *LocalProvider) Get(ctx context.Context, key string) (io.ReadCloser, error) {
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

// S3Provider implements Provider for S3 compatible storage.
type S3Provider struct {
	client *s3.Client
	bucket string
}

// NewS3Provider creates a new S3 storage provider.
func NewS3Provider(ctx context.Context, cfg *fileline_config.Config) (*S3Provider, error) {
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

func (p *S3Provider) Delete(ctx context.Context, key string) error {
	_, err := p.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	return err
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
