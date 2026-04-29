package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fileline/models"

	"github.com/jlaffaye/ftp"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func sanitizeStoragePath(storagePath string) (string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(strings.TrimSpace(storagePath), "\\", "/"))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." {
		return "", errors.New("invalid storage path")
	}
	if strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, "/../") {
		return "", errors.New("storage path traversal is not allowed")
	}
	return clean, nil
}

func localRoot(drive models.StorageDrive) string {
	root := strings.TrimSpace(drive.LocalPath)
	if root == "" {
		root = models.UploadsDir
	}
	return root
}

func localFilePath(drive models.StorageDrive, storagePath string) (string, error) {
	clean, err := sanitizeStoragePath(storagePath)
	if err != nil {
		return "", err
	}
	return filepath.Join(localRoot(drive), filepath.FromSlash(clean)), nil
}

func joinRemotePrefix(prefix string, storagePath string) (string, error) {
	clean, err := sanitizeStoragePath(storagePath)
	if err != nil {
		return "", err
	}
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return clean, nil
	}
	return path.Join(prefix, clean), nil
}

func parseHostPort(host string, port int, defaultPort int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if port <= 0 {
		port = defaultPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func newS3Client(drive models.StorageDrive) (*minio.Client, string, error) {
	endpoint := strings.TrimSpace(drive.S3Endpoint)
	secure := drive.S3UseSSL
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, "", err
		}
		endpoint = parsed.Host
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			secure = true
		case "http":
			secure = false
		}
	}
	if endpoint == "" {
		return nil, "", errors.New("missing S3 endpoint")
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(drive.S3AccessKey, drive.S3SecretKey, ""),
		Secure: secure,
		Region: strings.TrimSpace(drive.S3Region),
	})
	if err != nil {
		return nil, "", err
	}
	objectKey, err := joinRemotePrefix(drive.S3PathPrefix, "")
	if err != nil {
		// joinRemotePrefix does not accept empty path; ignore and derive later.
		objectKey = strings.Trim(strings.TrimSpace(drive.S3PathPrefix), "/")
	}
	return client, objectKey, nil
}

func newFTPClient(drive models.StorageDrive) (*ftp.ServerConn, error) {
	addr := parseHostPort(drive.FTPHost, drive.FTPPort, 21)
	if addr == "" {
		return nil, errors.New("missing FTP host")
	}
	conn, err := ftp.Dial(addr, ftp.DialWithTimeout(10*time.Second))
	if err != nil {
		return nil, err
	}
	if err := conn.Login(drive.FTPUsername, drive.FTPPassword); err != nil {
		_ = conn.Quit()
		return nil, err
	}
	return conn, nil
}

func ftpMkdirAll(conn *ftp.ServerConn, dir string) {
	dir = path.Clean("/" + strings.TrimSpace(dir))
	if dir == "/" || dir == "." {
		return
	}
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	current := ""
	for _, part := range parts {
		current += "/" + part
		_ = conn.MakeDir(current)
	}
}

func newSFTPClient(drive models.StorageDrive) (*ssh.Client, *sftp.Client, error) {
	addr := parseHostPort(drive.SFTPHost, drive.SFTPPort, 22)
	if addr == "" {
		return nil, nil, errors.New("missing SFTP host")
	}
	config := &ssh.ClientConfig{
		User:            drive.SFTPUsername,
		Auth:            []ssh.AuthMethod{ssh.Password(drive.SFTPPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	sshClient, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		return nil, nil, err
	}
	return sshClient, sftpClient, nil
}

type wrappedReadCloser struct {
	reader io.ReadCloser
	close  func() error
}

func (w *wrappedReadCloser) Read(p []byte) (int, error) {
	return w.reader.Read(p)
}

func (w *wrappedReadCloser) Close() error {
	readErr := w.reader.Close()
	closeErr := w.close()
	if readErr != nil {
		return readErr
	}
	return closeErr
}

// Put writes an object into the selected storage drive.
func Put(ctx context.Context, drive models.StorageDrive, storagePath string, body io.Reader, size int64) error {
	clean, err := sanitizeStoragePath(storagePath)
	if err != nil {
		return err
	}
	switch drive.Type {
	case "", models.StorageTypeLocal:
		targetPath, err := localFilePath(drive, clean)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		dst, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		defer dst.Close()
		_, err = io.Copy(dst, body)
		return err
	case models.StorageTypeS3:
		client, prefix, err := newS3Client(drive)
		if err != nil {
			return err
		}
		objectKey := clean
		if prefix != "" {
			objectKey = path.Join(prefix, clean)
		}
		if size <= 0 {
			size = -1
		}
		_, err = client.PutObject(ctx, drive.S3Bucket, objectKey, body, size, minio.PutObjectOptions{})
		return err
	case models.StorageTypeFTP:
		conn, err := newFTPClient(drive)
		if err != nil {
			return err
		}
		defer conn.Quit()
		fullPath, err := joinRemotePrefix(drive.FTPBasePath, clean)
		if err != nil {
			return err
		}
		fullPath = path.Clean("/" + fullPath)
		ftpMkdirAll(conn, path.Dir(fullPath))
		return conn.Stor(fullPath, body)
	case models.StorageTypeSFTP:
		sshClient, sftpClient, err := newSFTPClient(drive)
		if err != nil {
			return err
		}
		defer sshClient.Close()
		defer sftpClient.Close()
		fullPath, err := joinRemotePrefix(drive.SFTPBasePath, clean)
		if err != nil {
			return err
		}
		fullPath = path.Clean("/" + fullPath)
		if err := sftpClient.MkdirAll(path.Dir(fullPath)); err != nil {
			return err
		}
		dst, err := sftpClient.Create(fullPath)
		if err != nil {
			return err
		}
		defer dst.Close()
		_, err = io.Copy(dst, body)
		return err
	default:
		return fmt.Errorf("unsupported drive type: %s", drive.Type)
	}
}

// Open opens an object from the selected storage drive for streaming to clients.
func Open(ctx context.Context, drive models.StorageDrive, storagePath string) (io.ReadCloser, error) {
	clean, err := sanitizeStoragePath(storagePath)
	if err != nil {
		return nil, err
	}
	switch drive.Type {
	case "", models.StorageTypeLocal:
		targetPath, err := localFilePath(drive, clean)
		if err != nil {
			return nil, err
		}
		return os.Open(targetPath)
	case models.StorageTypeS3:
		client, prefix, err := newS3Client(drive)
		if err != nil {
			return nil, err
		}
		objectKey := clean
		if prefix != "" {
			objectKey = path.Join(prefix, clean)
		}
		object, err := client.GetObject(ctx, drive.S3Bucket, objectKey, minio.GetObjectOptions{})
		if err != nil {
			return nil, err
		}
		if _, statErr := object.Stat(); statErr != nil {
			_ = object.Close()
			return nil, statErr
		}
		return object, nil
	case models.StorageTypeFTP:
		conn, err := newFTPClient(drive)
		if err != nil {
			return nil, err
		}
		fullPath, err := joinRemotePrefix(drive.FTPBasePath, clean)
		if err != nil {
			_ = conn.Quit()
			return nil, err
		}
		reader, err := conn.Retr(path.Clean("/" + fullPath))
		if err != nil {
			_ = conn.Quit()
			return nil, err
		}
		return &wrappedReadCloser{
			reader: reader,
			close:  conn.Quit,
		}, nil
	case models.StorageTypeSFTP:
		sshClient, sftpClient, err := newSFTPClient(drive)
		if err != nil {
			return nil, err
		}
		fullPath, err := joinRemotePrefix(drive.SFTPBasePath, clean)
		if err != nil {
			_ = sftpClient.Close()
			_ = sshClient.Close()
			return nil, err
		}
		file, err := sftpClient.Open(path.Clean("/" + fullPath))
		if err != nil {
			_ = sftpClient.Close()
			_ = sshClient.Close()
			return nil, err
		}
		return &wrappedReadCloser{
			reader: file,
			close: func() error {
				sftpErr := sftpClient.Close()
				sshErr := sshClient.Close()
				if sftpErr != nil {
					return sftpErr
				}
				return sshErr
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported drive type: %s", drive.Type)
	}
}

// Delete removes an object from the selected storage drive.
func Delete(ctx context.Context, drive models.StorageDrive, storagePath string) error {
	clean, err := sanitizeStoragePath(storagePath)
	if err != nil {
		return err
	}
	switch drive.Type {
	case "", models.StorageTypeLocal:
		targetPath, err := localFilePath(drive, clean)
		if err != nil {
			return err
		}
		if err := os.Remove(targetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	case models.StorageTypeS3:
		client, prefix, err := newS3Client(drive)
		if err != nil {
			return err
		}
		objectKey := clean
		if prefix != "" {
			objectKey = path.Join(prefix, clean)
		}
		return client.RemoveObject(ctx, drive.S3Bucket, objectKey, minio.RemoveObjectOptions{})
	case models.StorageTypeFTP:
		conn, err := newFTPClient(drive)
		if err != nil {
			return err
		}
		defer conn.Quit()
		fullPath, err := joinRemotePrefix(drive.FTPBasePath, clean)
		if err != nil {
			return err
		}
		if err := conn.Delete(path.Clean("/" + fullPath)); err != nil && !strings.Contains(err.Error(), "550") {
			return err
		}
		return nil
	case models.StorageTypeSFTP:
		sshClient, sftpClient, err := newSFTPClient(drive)
		if err != nil {
			return err
		}
		defer sshClient.Close()
		defer sftpClient.Close()
		fullPath, err := joinRemotePrefix(drive.SFTPBasePath, clean)
		if err != nil {
			return err
		}
		if err := sftpClient.Remove(path.Clean("/" + fullPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported drive type: %s", drive.Type)
	}
}
