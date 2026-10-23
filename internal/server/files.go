package server

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/storage"

	"github.com/mileusna/useragent"
)

// classifyUserAgent categorizes the user-agent string into:
// "bot", "tablet", "mobile", "pc", or "unknown"
func classifyUserAgent(uaStr string) string {
	ua := useragent.Parse(uaStr)
	switch {
	case ua.Bot:
		return "bot"
	case ua.Tablet:
		return "tablet"
	case ua.Mobile:
		return "mobile"
	case ua.Desktop:
		return "pc"
	default:
		return "unknown"
	}
}

// isSocialMediaBot returns true if the User-Agent belongs to a social media crawler/scraper
// (Discord, Twitter/X, Telegram, Facebook, Slack, WhatsApp, Pinterest, etc.) or a bot.
func isSocialMediaBot(uaStr string) bool {
	lower := strings.ToLower(uaStr)
	socialSignatures := []string{
		"discordbot",
		"twitterbot",
		"facebookexternalhit",
		"telegrambot",
		"slackbot",
		"whatsapp",
		"linkedinbot",
		"vkshare",
		"embedly",
		"pinterest",
		"redditbot",
		"applebot",
		"skypeuripreview",
		"mastodon",
		"bluesky",
	}
	for _, sig := range socialSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	ua := useragent.Parse(uaStr)
	return ua.Bot
}

// detectMediaInfo determines the media category ("image", "video", "audio", "other") and MIME type.
func detectMediaInfo(filename string) (string, string) {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".png":
		return "image", "image/png"
	case ".jpg", ".jpeg":
		return "image", "image/jpeg"
	case ".gif":
		return "image", "image/gif"
	case ".webp":
		return "image", "image/webp"
	case ".avif":
		return "image", "image/avif"
	case ".bmp":
		return "image", "image/bmp"
	case ".ico":
		return "image", "image/x-icon"
	case ".svg":
		return "other", "application/octet-stream"
	case ".mp4", ".m4v":
		return "video", "video/mp4"
	case ".webm":
		return "video", "video/webm"
	case ".mov":
		return "video", "video/quicktime"
	case ".ogv":
		return "video", "video/ogg"
	case ".mkv":
		return "video", "video/x-matroska"
	case ".avi":
		return "video", "video/x-msvideo"
	case ".mp3":
		return "audio", "audio/mpeg"
	case ".wav":
		return "audio", "audio/wav"
	case ".ogg", ".opus":
		return "audio", "audio/ogg"
	case ".flac":
		return "audio", "audio/flac"
	case ".m4a", ".aac":
		return "audio", "audio/mp4"
	case ".pdf":
		return "other", "application/pdf"
	}
	if m := mime.TypeByExtension(ext); m != "" {
		baseType, _, err := mime.ParseMediaType(m)
		if err != nil {
			baseType = m
		}
		if strings.HasPrefix(baseType, "image/") && baseType != "image/svg+xml" {
			return "image", baseType
		}
		if strings.HasPrefix(baseType, "video/") {
			return "video", baseType
		}
		if strings.HasPrefix(baseType, "audio/") {
			return "audio", baseType
		}
		return "other", baseType
	}
	return "other", "application/octet-stream"
}

// isSafeInlineMIME reports whether mimeType is on the explicit safe allowlist for inline display
func isSafeInlineMIME(mimeType string) bool {
	baseType, _, err := mime.ParseMediaType(mimeType)
	if err != nil {
		baseType = strings.ToLower(strings.TrimSpace(mimeType))
	}
	switch baseType {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/bmp", "image/x-icon", "image/vnd.microsoft.icon":
		return true
	case "application/pdf":
		return true
	}
	if strings.HasPrefix(baseType, "video/") || strings.HasPrefix(baseType, "audio/") {
		return true
	}
	return false
}

// formatContentDisposition builds a safe Content-Disposition header value using mime.FormatMediaType
func formatContentDisposition(disposition, filename string) string {
	if filename == "" {
		filename = "download"
	}
	if cd := mime.FormatMediaType(disposition, map[string]string{"filename": filename}); cd != "" {
		return cd
	}
	return disposition
}

func resolveEmbedColor(owner *db.User, cfg *config.Config) string {
	if owner == nil {
		return "#1d9bf0"
	}
	if owner.EmbedConfig.UseAccentColor {
		if owner.Accent != "" && owner.Accent != "global" {
			return owner.Accent
		}
		if cfg != nil && cfg.CustomAccentHex != "" {
			return cfg.CustomAccentHex
		}
		return "#2563eb"
	}
	if owner.EmbedConfig.Color != "" {
		return owner.EmbedConfig.Color
	}
	return "#1d9bf0"
}

func sanitizeRequestHost(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') &&
			r != '.' && r != '-' && r != ':' && r != '[' && r != ']' {
			return ""
		}
	}
	return h
}

func requestBaseURL(r *http.Request, cfg *config.Config) string {
	scheme := "http"
	if cfg != nil && (cfg.SSL || cfg.ReverseProxy) {
		scheme = "https"
	} else if r != nil && r.TLS != nil {
		scheme = "https"
	} else if isTrustedProxyRequest(r, cfg) {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			switch strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0])) {
			case "https":
				scheme = "https"
			case "http":
				scheme = "http"
			}
		}
	}

	host := ""
	if cfg != nil && strings.TrimSpace(cfg.Domain) != "" && cfg.Domain != "localhost" {
		host = strings.TrimSpace(cfg.Domain)
		if !strings.Contains(host, ":") && !cfg.ReverseProxy && cfg.Port != 0 && cfg.Port != 80 && cfg.Port != 443 {
			host = fmt.Sprintf("%s:%d", host, cfg.Port)
		}
	} else if r != nil && r.URL != nil && r.URL.Host != "" && sanitizeRequestHost(r.URL.Host) == r.Host {
		host = r.Host
	} else if cfg != nil && strings.TrimSpace(cfg.Domain) != "" {
		host = strings.TrimSpace(cfg.Domain)
		if !strings.Contains(host, ":") && !cfg.ReverseProxy && cfg.Port != 0 && cfg.Port != 80 && cfg.Port != 443 {
			host = fmt.Sprintf("%s:%d", host, cfg.Port)
		}
	} else {
		host = "localhost"
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func buildEmbedStrings(f *db.File, owner *db.User, mediaType string) (displayName, siteName, ogSiteName, embedTitle, embedDesc string) {
	displayName = f.OriginalName
	if f.CustomName != "" {
		displayName = f.CustomName
	}
	if owner == nil {
		return displayName, "FileLine", "FileLine", displayName, ""
	}
	ec := owner.EmbedConfig
	siteName = ec.SiteName
	formattedSize := logger.FormatBytes(f.Size)
	formattedDate := f.UploadedAt.Format("2006-01-02 15:04")

	var metaParts []string
	if ec.ShowSize {
		metaParts = append(metaParts, "📦 "+formattedSize)
	}
	if ec.ShowDate {
		metaParts = append(metaParts, "🕒 "+formattedDate)
	}
	metaLine := strings.Join(metaParts, "  •  ")

	var descLines []string
	if ec.CustomText != "" {
		descLines = append(descLines, ec.CustomText)
	}
	if metaLine != "" {
		descLines = append(descLines, metaLine)
	}
	embedDesc = strings.Join(descLines, "\n")

	if ec.ShowTitle {
		embedTitle = displayName
	} else if ec.CustomText != "" {
		embedTitle = ec.CustomText
	} else if siteName != "" {
		embedTitle = siteName
	} else {
		embedTitle = "FileLine"
	}

	ogSiteName = siteName
	if mediaType == "video" && metaLine != "" {
		if ogSiteName != "" {
			ogSiteName = ogSiteName + "  •  " + metaLine
		} else {
			ogSiteName = metaLine
		}
	}
	return displayName, siteName, ogSiteName, embedTitle, embedDesc
}

func (s *Server) oembedHandler(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Query().Get("f")
	if urlPath == "" {
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	database := s.db
	cfg := s.cfg
	s.mu.RUnlock()

	f, err := db.GetFileByURL(r.Context(), database, urlPath)
	if err != nil || f.IsPrivate {
		http.NotFound(w, r)
		return
	}

	owner, _ := db.GetUserByID(r.Context(), database, f.UserID)
	nameForExt := f.OriginalName
	if nameForExt == "" {
		nameForExt = f.URLPath
	}
	mediaType, _ := detectMediaInfo(nameForExt)
	_, siteName, ogSiteName, embedTitle, _ := buildEmbedStrings(f, owner, mediaType)

	providerName := siteName
	if mediaType == "video" && ogSiteName != "" {
		providerName = ogSiteName
	}

	authorName := ""
	if owner != nil && owner.EmbedConfig.ShowAuthor && owner.Username != "" {
		authorName = "@" + owner.Username
	}

	baseURL := requestBaseURL(r, cfg)
	resp := map[string]interface{}{
		"version":       "1.0",
		"type":          "rich",
		"title":         embedTitle,
		"provider_name": providerName,
		"provider_url":  baseURL,
	}
	if authorName != "" {
		resp["author_name"] = authorName
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

func fileCacheControl(f *db.File) string {
	if f != nil && f.IsPrivate {
		return "private, no-store"
	}
	return "public, max-age=3600"
}

func fileETag(f *db.File) string {
	if f == nil || f.StoragePath == "" {
		return ""
	}
	return `"` + f.StoragePath + `"`
}

func isNotModified(r *http.Request, etag string, lastModified time.Time) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		for _, candidate := range strings.Split(inm, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" || (etag != "" && strings.TrimPrefix(candidate, "W/") == etag) {
				return true
			}
		}
		return false
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" && !lastModified.IsZero() {
		if t, err := http.ParseTime(ims); err == nil {
			if !lastModified.Truncate(time.Second).After(t.Truncate(time.Second)) {
				return true
			}
		}
	}
	return false
}

func (s *Server) serveFileHandler(w http.ResponseWriter, r *http.Request) {
	if user, ok := s.parseSession(r); ok && user != nil {
		r = r.WithContext(withUser(r.Context(), user))
	}

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Range, Content-Type, Accept-Encoding")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges, Content-Disposition")
		w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	urlPath := strings.TrimPrefix(r.URL.Path, "/f/")
	if urlPath == "" {
		s.render404(w, r)
		return
	}

	s.mu.RLock()
	database := s.db
	cfg := s.cfg
	s.mu.RUnlock()

	f, err := db.GetFileByURL(r.Context(), database, urlPath)
	if err != nil {
		s.render404(w, r)
		return
	}

	if f.IsPrivate {
		user, _ := userFrom(r.Context())
		if user == nil || (user.ID != f.UserID && user.Role != "admin") {
			s.render404(w, r)
			return
		}
	}

	isRaw := r.URL.Query().Get("raw") == "1" || r.URL.Query().Get("download") == "1"
	isDownload := r.URL.Query().Get("download") == "1"

	var owner *db.User
	if database != nil {
		owner, _ = db.GetUserByID(r.Context(), database, f.UserID)
	}
	embedEnabled := false
	if owner != nil && owner.EmbedConfig.Enabled {
		isBot := isSocialMediaBot(r.UserAgent())
		if isBot && owner.EmbedConfig.SocialMedia {
			embedEnabled = true
		} else if !isBot && owner.EmbedConfig.DirectVisit {
			embedEnabled = true
		}
	}

	// Record read statistics if enabled on GET (avoid double counting when raw=1 is sub-requested by embed view, or when a browser sends sub-range probes after byte 0)
	if f.StatsEnabled && r.Method == http.MethodGet {
		rangeHdr := strings.TrimSpace(r.Header.Get("Range"))
		isFollowupRange := rangeHdr != "" && !strings.HasPrefix(rangeHdr, "bytes=0-")
		if !(embedEnabled && isRaw) && !isFollowupRange {
			uaStr := r.UserAgent()
			devType := classifyUserAgent(uaStr)
			s.recordRead(db.ReadEvent{
				FileID:     f.ID,
				DeviceType: devType,
				ReadAt:     time.Now().UTC(),
			})
		}
	}

	nameForExt := f.OriginalName
	if nameForExt == "" {
		nameForExt = f.URLPath
	}
	mediaType, mimeType := detectMediaInfo(nameForExt)

	if embedEnabled && !isRaw {
		baseURL := requestBaseURL(r, cfg)
		escapedPath := url.PathEscape(f.URLPath)
		pageURL := fmt.Sprintf("%s/f/%s", baseURL, escapedPath)
		rawURL := fmt.Sprintf("%s/f/%s?raw=1", baseURL, escapedPath)
		downloadURL := fmt.Sprintf("%s/f/%s?raw=1&download=1", baseURL, escapedPath)
		oembedURL := fmt.Sprintf("%s/oembed?f=%s", baseURL, url.QueryEscape(f.URLPath))

		displayName, siteName, ogSiteName, embedTitle, embedDesc := buildEmbedStrings(f, owner, mediaType)
		embedColor := resolveEmbedColor(owner, cfg)

		w.Header().Del("X-Frame-Options")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors *; object-src 'none'; base-uri 'self'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: *; media-src 'self' data: blob: *; connect-src 'self' *; font-src 'self' data:")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		s.renderTemplate(w, r, "embed_file.html", map[string]interface{}{
			"Config":           cfg,
			"File":             f,
			"DisplayName":      displayName,
			"EmbedColor":       embedColor,
			"SiteName":         siteName,
			"OGSiteName":       ogSiteName,
			"EmbedTitle":       embedTitle,
			"EmbedDescription": embedDesc,
			"CustomText":       owner.EmbedConfig.CustomText,
			"Author":           owner.Username,
			"FormattedSize":    logger.FormatBytes(f.Size),
			"FormattedDate":    f.UploadedAt.Format("2006-01-02 15:04"),
			"ShowTitle":        owner.EmbedConfig.ShowTitle,
			"ShowSize":         owner.EmbedConfig.ShowSize,
			"ShowDate":         owner.EmbedConfig.ShowDate,
			"ShowAuthor":       owner.EmbedConfig.ShowAuthor,
			"MediaType":        mediaType,
			"MimeType":         mimeType,
			"PageURL":          pageURL,
			"RawURL":           rawURL,
			"DownloadURL":      downloadURL,
			"OEmbedURL":        oembedURL,
		})
		return
	}

	s.mu.RLock()
	st := s.getProvider(f.StorageType)
	s.mu.RUnlock()
	if st == nil {
		s.render404(w, r)
		return
	}

	// Provide original filename for download if custom_name is used, otherwise original
	downloadName := f.OriginalName
	if f.CustomName != "" {
		downloadName = f.CustomName
	}
	logger.Debug("Serving file: '/f/%s' (id=%d, original_name='%s', size=%s)", urlPath, f.ID, downloadName, logger.FormatBytes(f.Size))

	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Accept-Ranges", "bytes")

	disposition := "attachment"
	servedMime := "application/octet-stream"
	if !isDownload && isSafeInlineMIME(mimeType) {
		disposition = "inline"
		servedMime = mimeType
	}
	h.Set("Content-Type", servedMime)
	h.Set("Content-Disposition", formatContentDisposition(disposition, downloadName))

	isMedia := strings.HasPrefix(servedMime, "video/") || strings.HasPrefix(servedMime, "audio/")
	if isMedia {
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Range, Content-Type, Accept-Encoding")
		h.Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges, Content-Disposition")
		h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	} else {
		h.Set("Cross-Origin-Resource-Policy", "same-site")
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'")
	}
	if etag := fileETag(f); etag != "" {
		h.Set("ETag", etag)
	}
	h.Set("Cache-Control", fileCacheControl(f))

	dw := newDeadlineExtendingResponseWriter(w, transferBudget(f.Size))

	// Fast path for seekable storage (e.g. LocalProvider): http.ServeContent handles
	// Range, If-Range, If-Modified-Since, If-None-Match, HEAD, and sendfile(2) zero-copy.
	if sp, ok := st.(storage.SeekableProvider); ok {
		rsc, err := sp.Open(r.Context(), f.StoragePath)
		if err != nil {
			s.render404(w, r)
			return
		}
		defer rsc.Close()
		http.ServeContent(dw, r, downloadName, f.UploadedAt.UTC(), rsc)
		return
	}

	// S3 / RangeProvider path
	h.Set("Accept-Ranges", "bytes")
	if !f.UploadedAt.IsZero() {
		h.Set("Last-Modified", f.UploadedAt.UTC().Format(http.TimeFormat))
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && isNotModified(r, h.Get("ETag"), f.UploadedAt) {
		h.Del("Content-Type")
		h.Del("Content-Length")
		h.Del("Content-Disposition")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if rp, ok := st.(storage.RangeProvider); ok {
		if r.Method == http.MethodHead {
			ro, err := rp.Head(r.Context(), f.StoragePath)
			if err != nil {
				s.render404(w, r)
				return
			}
			size := ro.ContentLength
			if size <= 0 {
				size = f.Size
			}
			if size > 0 {
				h.Set("Content-Length", fmt.Sprintf("%d", size))
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		rangeHeader := strings.TrimSpace(r.Header.Get("Range"))
		ro, err := rp.GetRange(r.Context(), f.StoragePath, rangeHeader)
		if err != nil {
			s.render404(w, r)
			return
		}
		defer ro.Body.Close()
		if ro.ContentRange != "" {
			h.Set("Content-Range", ro.ContentRange)
		}
		if ro.ContentLength > 0 {
			h.Set("Content-Length", fmt.Sprintf("%d", ro.ContentLength))
		} else if f.Size > 0 && !ro.IsPartial {
			h.Set("Content-Length", fmt.Sprintf("%d", f.Size))
		}
		if ro.IsPartial {
			dw.WriteHeader(http.StatusPartialContent)
		} else {
			dw.WriteHeader(http.StatusOK)
		}
		if _, err := io.Copy(dw, ro.Body); err != nil {
			logger.Debug("File stream aborted or failed for '/f/%s': %v", urlPath, err)
		}
		return
	}

	// Generic Provider fallback
	if r.Method == http.MethodHead {
		if f.Size > 0 {
			h.Set("Content-Length", fmt.Sprintf("%d", f.Size))
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	reader, err := st.Get(r.Context(), f.StoragePath)
	if err != nil {
		s.render404(w, r)
		return
	}
	defer reader.Close()
	if f.Size > 0 {
		h.Set("Content-Length", fmt.Sprintf("%d", f.Size))
	}
	if _, err := io.Copy(dw, reader); err != nil {
		logger.Debug("File stream aborted or failed for '/f/%s': %v", urlPath, err)
	}
}

func (s *Server) filesHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username

	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	if filter != "others" {
		filter = "own"
	}

	searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	opts := db.FilePageOpts{
		Limit:  50,
		Search: searchQuery,
	}

	if user.Role == "admin" {
		if filter == "others" {
			opts.ExcludeUserID = user.ID
		} else {
			opts.UserID = user.ID
		}
	} else {
		filter = "own"
		opts.UserID = user.ID
	}

	cursorStr := strings.TrimSpace(r.URL.Query().Get("cursor"))
	if cursorStr != "" {
		if curTS, curID, err := db.DecodeCursor(cursorStr); err == nil {
			opts.CursorTS = &curTS
			opts.CursorID = curID
		}
	}

	page, err := db.GetFilesPage(r.Context(), database, opts)
	if err != nil {
		s.internalError(w, r, "Failed to load files from database", err)
		return
	}

	if user.Role == "admin" && len(page.Files) > 0 {
		if allUsers, err := db.GetAllUsers(r.Context(), database); err == nil {
			userMap := make(map[int]string, len(allUsers))
			for _, u := range allUsers {
				userMap[u.ID] = u.Username
			}
			for _, f := range page.Files {
				if uname, ok := userMap[f.UserID]; ok {
					f.OwnerUsername = uname
				}
			}
		}
	}

	var nextURL, prevURL string
	if page.HasNext {
		v := url.Values{}
		v.Set("cursor", page.NextCursor)
		if searchQuery != "" {
			v.Set("q", searchQuery)
		}
		if user.Role == "admin" && filter != "" {
			v.Set("filter", filter)
		}
		nextURL = "/files?" + v.Encode()
	}
	if cursorStr != "" {
		v := url.Values{}
		if searchQuery != "" {
			v.Set("q", searchQuery)
		}
		if user.Role == "admin" && filter != "" {
			v.Set("filter", filter)
		}
		if len(v) > 0 {
			prevURL = "/files?" + v.Encode()
		} else {
			prevURL = "/files"
			if user.Role == "admin" && filter != "" {
				prevURL += "?filter=" + filter
			}
		}
	}

	var drives []config.DriveView
	if user.Role == "admin" && s.cfg != nil {
		drives = s.cfg.SanitizedDrives()
		if len(drives) == 0 {
			drives = []config.DriveView{
				{
					ID:      "default",
					Name:    "Default Storage",
					Type:    s.cfg.StorageType,
					Enabled: true,
				},
			}
		}
	}

	s.renderTemplate(w, r, "files.html", map[string]interface{}{
		"Title":        "All Files",
		"Username":     username,
		"User":         user,
		"Drives":       drives,
		"Files":        page.Files,
		"HasNext":      page.HasNext,
		"NextURL":      nextURL,
		"HasPrev":      cursorStr != "",
		"PrevURL":      prevURL,
		"SearchQuery":  searchQuery,
		"ActiveFilter": filter,
	})
}

func (s *Server) editFileHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username

	if r.Method == http.MethodGet {
		id := queryInt(r, "id", 0)
		f, err := db.GetFileByID(r.Context(), database, id)
		if err != nil {
			s.render404(w, r)
			return
		}
		if user.Role != "admin" && f.UserID != user.ID {
			s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
			return
		}
		var stats *db.FileStats
		if f.StatsEnabled {
			stats, _ = db.GetFileStats(r.Context(), database, f.ID)
		}
		s.renderTemplate(w, r, "edit_file.html", map[string]interface{}{
			"Title":    "Edit File",
			"Username": username,
			"User":     user,
			"File":     f,
			"Stats":    stats,
		})
		return
	}

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
		if err := r.ParseForm(); err != nil {
			if isMaxBytesError(err) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Invalid form submission", http.StatusBadRequest)
			return
		}
		id := formInt(r, "id", 0)
		f, err := db.GetFileByID(r.Context(), database, id)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		if user.Role != "admin" && f.UserID != user.ID {
			s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
			return
		}
		var stats *db.FileStats
		if f.StatsEnabled {
			stats, _ = db.GetFileStats(r.Context(), database, f.ID)
		}
		customName := strings.TrimSpace(r.FormValue("custom_name"))
		if len(customName) > maxCustomNameLen {
			s.renderTemplate(w, r, "edit_file.html", map[string]interface{}{
				"Title":    "Edit File",
				"Username": username,
				"User":     user,
				"File":     f,
				"Stats":    stats,
				"Error":    "Custom name too long",
			}, http.StatusBadRequest)
			return
		}
		urlPath := strings.TrimSpace(r.FormValue("url_path"))
		explicitURLPath := urlPath != ""
		if !explicitURLPath {
			urlPath = slugifyURLPath(f.OriginalName)
			if urlPath == "" {
				urlPath = f.URLPath
			}
		}
		if err := validateURLPath(urlPath); err != nil {
			s.renderTemplate(w, r, "edit_file.html", map[string]interface{}{
				"Title":    "Edit File",
				"Username": username,
				"User":     user,
				"File":     f,
				"Stats":    stats,
				"Error":    err.Error(),
			}, http.StatusBadRequest)
			return
		}
		isPrivate := r.FormValue("is_private") == "on"
		statsEnabled := r.FormValue("stats_enabled") == "on"
		resetStats := r.FormValue("reset_stats") == "1" || r.FormValue("action") == "reset_stats"

		// Reset stats if stats setting changed (activated or deactivated) or manual reset requested
		if statsEnabled != f.StatsEnabled || resetStats {
			if err := db.ResetFileStats(r.Context(), database, id); err != nil {
				logger.Error("Failed to reset stats for file id=%d: %v", id, err)
			} else {
				logger.Action("User '%s' reset statistics for file id=%d (stats_enabled: %t -> %t)", username, id, f.StatsEnabled, statsEnabled)
			}
		}

		if err := db.UpdateFile(r.Context(), database, id, customName, urlPath, isPrivate, statsEnabled); err != nil {
			if isUniqueConstraintError(err) {
				if !explicitURLPath {
					urlPath = appendRandomURLPathSuffix(urlPath)
					if retryErr := db.UpdateFile(r.Context(), database, id, customName, urlPath, isPrivate, statsEnabled); retryErr == nil {
						logger.Action("User '%s' updated file id=%d (custom_name='%s', url_path='%s', private=%t, stats=%t)", username, id, customName, urlPath, isPrivate, statsEnabled)
						http.Redirect(w, r, "/files", http.StatusFound)
						return
					}
				}
				s.renderTemplate(w, r, "edit_file.html", map[string]interface{}{
					"Title":    "Edit File",
					"Username": username,
					"User":     user,
					"File":     f,
					"Stats":    stats,
					"Error":    "URL path already in use",
				}, http.StatusConflict)
				return
			}
			s.internalError(w, r, "Failed to update file in database", err)
			return
		}
		logger.Action("User '%s' updated file id=%d (custom_name='%s', url_path='%s', private=%t, stats=%t)", username, id, customName, urlPath, isPrivate, statsEnabled)

		if resetStats {
			http.Redirect(w, r, fmt.Sprintf("/edit?id=%d", id), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/files", http.StatusFound)
	}
}

func (s *Server) deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}

	id := formInt(r, "id", 0)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	f, err := db.GetFileByID(r.Context(), database, id)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := user.Username
	if user.Role != "admin" && f.UserID != user.ID {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	s.mu.RLock()
	st := s.getProvider(f.StorageType)
	s.mu.RUnlock()
	if err := st.Delete(r.Context(), f.StoragePath); err != nil {
		logger.Error("Failed to delete file from storage: %v", err)
	}
	if err := db.DeleteFile(r.Context(), database, id); err != nil {
		s.internalError(w, r, "Failed to delete file from database", err)
		return
	}
	logger.Action("User '%s' deleted file id=%d ('%s')", username, id, f.OriginalName)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) fileStatsAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := queryInt(r, "id", 0)
	if id <= 0 {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	f, err := db.GetFileByID(r.Context(), database, id)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != "admin" && f.UserID != user.ID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var stats *db.FileStats
	if f.StatsEnabled {
		stats, err = db.GetFileStats(r.Context(), database, f.ID)
		if err != nil {
			s.internalError(w, r, "Failed to load file stats", err)
			return
		}
	} else {
		stats = &db.FileStats{}
	}

	displayName := f.OriginalName
	if f.CustomName != "" {
		displayName = f.CustomName
	}

	lastReadFormatted := ""
	if stats.LastReadAt != nil {
		lastReadFormatted = stats.LastReadAt.Format("Jan 02, 2006 15:04")
	}

	res := map[string]interface{}{
		"id":                  f.ID,
		"name":                displayName,
		"url_path":            f.URLPath,
		"stats_enabled":       f.StatsEnabled,
		"total_reads":         stats.TotalReads,
		"reads_24h":           stats.Reads24h,
		"last_read_at":        stats.LastReadAt,
		"last_read_formatted": lastReadFormatted,
		"mobile":              stats.Mobile,
		"pc":                  stats.PC,
		"tablet":              stats.Tablet,
		"bots":                stats.Bots,
		"unknown":             stats.Unknown,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
