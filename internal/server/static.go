package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"fileline/internal/logger"
	"fileline/web"
)

type cachedStaticAsset struct {
	rawContent        []byte
	singleLineContent []byte
	gzipContent       []byte
	contentType       string
	etag              string
	isCompressible    bool
}

// initStaticCache pre-computes single-line optimizations and pre-compresses static assets with gzip at server startup.
func (s *Server) initStaticCache() {
	staticFS := web.Static()
	cache := make(map[string]*cachedStaticAsset)

	err := fs.WalkDir(staticFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}

		cleanPath := filepath.ToSlash(path)
		raw, readErr := fs.ReadFile(staticFS, path)
		if readErr != nil {
			logger.Error("Failed to read static asset %s: %v", path, readErr)
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		cType := mime.TypeByExtension(ext)
		if cType == "" {
			switch ext {
			case ".woff2":
				cType = "font/woff2"
			case ".woff":
				cType = "font/woff"
			case ".svg":
				cType = "image/svg+xml"
			case ".css":
				cType = "text/css; charset=utf-8"
			case ".js":
				cType = "text/javascript; charset=utf-8"
			default:
				cType = "application/octet-stream"
			}
		}

		// Generate single-line representation while preserving comments
		var singleLine []byte
		switch ext {
		case ".css":
			singleLine = formatCSSSingleLine(raw)
		case ".js":
			singleLine = formatJSSingleLine(raw)
		case ".html", ".htm":
			singleLine = formatHTMLSingleLine(raw)
		case ".svg", ".xml":
			singleLine = formatXMLSingleLine(raw)
		default:
			singleLine = raw
		}

		// Check if file is compressible with gzip (font, css, html, txt, js, svg, etc.)
		isCompressible := strings.HasPrefix(cType, "text/") ||
			cType == "text/css; charset=utf-8" ||
			cType == "text/javascript; charset=utf-8" ||
			cType == "application/javascript" ||
			cType == "image/svg+xml" ||
			cType == "application/json" ||
			cType == "application/xml" ||
			strings.HasPrefix(cType, "font/") ||
			ext == ".css" || ext == ".js" || ext == ".html" || ext == ".txt" ||
			ext == ".svg" || ext == ".woff" || ext == ".woff2" || ext == ".ttf" ||
			ext == ".eot" || ext == ".otf" || ext == ".json"

		var gzipBytes []byte
		if isCompressible {
			var gzBuf bytes.Buffer
			gw, err := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
			if err == nil {
				contentToCompress := singleLine
				if len(contentToCompress) == 0 {
					contentToCompress = raw
				}
				_, _ = gw.Write(contentToCompress)
				_ = gw.Close()
				gzipBytes = gzBuf.Bytes()
			}
		}

		hash := sha256.Sum256(raw)
		etag := fmt.Sprintf("\"%x\"", hash[:8])

		cache[cleanPath] = &cachedStaticAsset{
			rawContent:        raw,
			singleLineContent: singleLine,
			gzipContent:       gzipBytes,
			contentType:       cType,
			etag:              etag,
			isCompressible:    isCompressible,
		}
		return nil
	})

	if err != nil {
		logger.Error("Failed to walk static directory: %v", err)
	}
	s.staticCache = cache
}

// staticHandler serves cached static assets with ETag validation, single-line response, and configurable gzip compression.
func (s *Server) staticHandler(w http.ResponseWriter, r *http.Request) {
	cleanPath := strings.Trim(r.URL.Path, "/")
	if cleanPath == "" {
		http.NotFound(w, r)
		return
	}

	asset, ok := s.staticCache[cleanPath]
	if !ok {
		// Prevent directory traversal or listing
		staticFS := web.Static()
		if fi, err := fs.Stat(staticFS, cleanPath); err == nil && fi.IsDir() {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("ETag", asset.etag)
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Content-Type", asset.contentType)

	// Conditional HTTP request (304 Not Modified)
	if match := r.Header.Get("If-None-Match"); match != "" && match == asset.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	s.mu.RLock()
	gzipEnabled := s.cfg == nil || s.cfg.GzipEnabled
	minifyEnabled := s.cfg == nil || s.cfg.MinifyResponses
	s.mu.RUnlock()

	// Gzip compression for static files (font, css, html, txt, js, etc.) if enabled and requested
	if gzipEnabled && len(asset.gzipContent) > 0 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(asset.gzipContent)))
		_, _ = w.Write(asset.gzipContent)
		return
	}

	// Serve single-line (or raw) content
	body := asset.rawContent
	if minifyEnabled && len(asset.singleLineContent) > 0 {
		body = asset.singleLineContent
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}
