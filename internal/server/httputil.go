package server

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// queryInt parses an integer URL query parameter or returns fallback if absent or invalid.
func queryInt(r *http.Request, key string, fallback int) int {
	if r == nil {
		return fallback
	}
	val := r.URL.Query().Get(key)
	if val == "" {
		return fallback
	}
	if n, err := strconv.Atoi(val); err == nil {
		return n
	}
	return fallback
}

// formInt parses an integer form value or returns fallback if absent or invalid.
func formInt(r *http.Request, key string, fallback int) int {
	if r == nil {
		return fallback
	}
	val := r.FormValue(key)
	if val == "" {
		return fallback
	}
	if n, err := strconv.Atoi(val); err == nil {
		return n
	}
	return fallback
}

// respondJSON writes a JSON response with status code and Content-Type header.
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
