package handlers

import (
	"log"
	"net/http"
	"sync/atomic"

	"fileline/database"
)

var debugMode atomic.Bool

func SetDebug(enabled bool) {
	debugMode.Store(enabled)
}

/**
  Debugf logs debug messages if debug mode is enabled.
  @param format - The format string for the log message.
  @param args - The arguments for the log message.
*/
func Debugf(format string, args ...interface{}) {
	if !debugMode.Load() {
		return
	}
	log.Printf("DEBUG "+format, args...)
}

/**
  RenderHTTPError renders an error page for the given HTTP status code and message.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @param status - The HTTP status code to render.
  @param message - An optional message to include on the error page.
*/
func RenderHTTPError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if message == "" {
		message = http.StatusText(status)
	}
	if status != http.StatusNotFound {
		log.Printf("HTTP %d %s %s: %s", status, r.Method, r.URL.Path, message)
		Debugf("Rendering %d page for %s", status, r.URL.Path)
	}

	templateName := "error.html"
	switch status {
	case http.StatusForbidden:
		templateName = "403.html"
	case http.StatusNotFound:
		templateName = "404.html"
	case http.StatusInternalServerError:
		templateName = "500.html"
	}

	data := map[string]interface{}{
		"Status":     status,
		"StatusText": http.StatusText(status),
		"Message":    message,
		"Settings":   database.GetSettings(),
		"T":          T(),
	}
	if status == http.StatusForbidden {
		data["ErrorMessage"] = message
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := Templates.ExecuteTemplate(w, templateName, data); err != nil {
		log.Printf("ERROR: failed to render %s: %v", templateName, err)
		http.Error(w, http.StatusText(status), status)
	}
}
