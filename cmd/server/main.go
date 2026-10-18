package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/server"
	"fileline/internal/translations"
)

func runHealthCheck(cfg *config.Config) int {
	port := 8080
	if cfg != nil && cfg.Port > 0 {
		port = cfg.Port
	}
	scheme := "http"
	if cfg != nil && cfg.SSL {
		scheme = "https"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%d/health", scheme, port))
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func main() {
	envOnly := flag.Bool("env-only", false, "Use only environment variables for configuration")
	debug := flag.Bool("debug", false, "Enable debug mode with detailed HTTP and audit logs")
	healthCheck := flag.Bool("healthcheck", false, "Probe local /health endpoint and exit (for container HEALTHCHECK)")
	flag.BoolVar(debug, "d", false, "Enable debug mode (shorthand)")
	flag.Parse()

	if *healthCheck {
		cfg, _ := config.Load("config.json", *envOnly)
		os.Exit(runHealthCheck(cfg))
	}

	// Initialize configuration (fail closed on parse/read errors)
	cfg, err := config.Load("config.json", *envOnly)
	if err != nil {
		logger.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}
	if err := cfg.EnsureJWTKey("config.json"); err != nil {
		logger.Error("Invalid JWT signing key configuration: %v", err)
		os.Exit(1)
	}

	if *debug {
		cfg.Debug = true
	}
	logger.SetDebug(cfg.Debug)

	if cfg.Debug {
		logger.Debug("Debug mode enabled")
	}

	// Load translations
	if err := translations.Load(); err != nil {
		logger.Error("Failed to load translations: %v", err)
	}

	os.MkdirAll("data", 0755)

	// Root context for application lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Attempt to initialize Database if configured (fail closed on error)
	var database *sql.DB
	if cfg.DBType != "" {
		var err error
		database, err = db.InitDB(ctx, cfg)
		if err != nil {
			logger.Error("Configured database failed to initialize: %v", err)
			os.Exit(1)
		}
		// Run migrations automatically
		if err := db.Migrate(ctx, database, cfg.DBType); err != nil {
			logger.Error("Database migration failed: %v", err)
			os.Exit(1)
		}
		logger.Debug("Successfully connected to %s database and migrated", cfg.DBType)
	}

	// Initialize Server
	srv := server.New(cfg, database)

	// Check setup state and generate a one-time setup token when not yet configured
	configured, err := srv.CheckConfigured(ctx)
	if err != nil {
		logger.Error("Failed to verify setup state: %v", err)
		os.Exit(1)
	}
	if !configured {
		token := srv.EnableSetupToken()
		logger.Info("Instance is not yet configured. Starting in Setup mode.")
		logger.Info("One-time setup token: %s", token)
	}

	serverErrors := make(chan error, 1)

	// Start server in a goroutine
	go func() {
		logger.Info("Starting server on port %d...", cfg.Port)
		serverErrors <- srv.Start()
	}()

	// Channel to listen for OS signals for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Error starting server: %v", err)
			os.Exit(1)
		}

	case sig := <-shutdown:
		logger.Info("Received shutdown signal: %v. Starting graceful shutdown...", sig)
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful shutdown failed: %v", err)
			// If shutdown fails, attempt a force exit
			if err := srv.Shutdown(context.Background()); err != nil {
				logger.Error("Forced shutdown failed: %v", err)
				os.Exit(1)
			}
		}
	}
	logger.Info("Server stopped successfully")
}
