package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"fileline/internal/config"
	"fileline/internal/db"
)

func TestHealthHandler(t *testing.T) {
	// Setup in-memory sqlite for testing
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	srv := New(cfg, database)
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := `{"status": "ok"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}