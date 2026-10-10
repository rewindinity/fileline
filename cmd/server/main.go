package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/server"
	"fileline/internal/translations"
)

func main() {
	envOnly := flag.Bool("env-only", false, "Use only environment variables for configuration")
	flag.Parse()
	// Load translations
	if err := translations.Load(); err != nil {
		log.Printf("Warning: failed to load translations: %v", err)
	}
	// Initialize configuration
	cfg, err := config.Load("config.json", *envOnly)
	if err != nil {
		log.Printf("No config.json found or invalid, using default unconfigured state: %v", err)
		defaultCfg := config.DefaultConfig()
		defaultCfg.EnvOnly = *envOnly
		cfg = &defaultCfg
	}

	os.MkdirAll("data", 0755)

	// Root context for application lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Server
	srv := server.New(cfg, nil)

	// Attempt to initialize Database if configured
	if cfg.DBType != "" {
		database, err := db.InitDB(ctx, cfg)
		if err != nil {
			log.Printf("Warning: configured database failed to initialize: %v", err)
		} else {
			// Run migrations automatically
			if err := db.Migrate(ctx, database, cfg.DBType); err != nil {
				log.Fatalf("Database migration failed: %v", err)
			}
			log.Printf("Successfully connected to %s database and migrated", cfg.DBType)

			// Inject database into server
			srv = server.New(cfg, database) // Recreate to inject DB, or we can use a SetDB method.
			// Wait, recreating is fine since we haven't started it yet.
		}
	} else {
		log.Println("Database not configured. Starting in Setup mode.")
	}

	serverErrors := make(chan error, 1)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on port %d...", cfg.Port)
		serverErrors <- srv.Start()
	}()

	// Channel to listen for OS signals for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Error starting server: %v", err)
		}

	case sig := <-shutdown:
		log.Printf("Received shutdown signal: %v. Starting graceful shutdown...", sig)
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
			// If shutdown fails, attempt a force exit
			if err := srv.Shutdown(context.Background()); err != nil {
				log.Fatalf("Forced shutdown failed: %v", err)
			}
		}
	}
	log.Println("Server stopped successfully")
}
