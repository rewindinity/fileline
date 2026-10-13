package main

import (
	"context"
	"errors"
	"flag"
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

func main() {
	envOnly := flag.Bool("env-only", false, "Use only environment variables for configuration")
	debug := flag.Bool("debug", false, "Enable debug mode with detailed HTTP and audit logs")
	flag.BoolVar(debug, "d", false, "Enable debug mode (shorthand)")
	flag.Parse()

	// Initialize configuration
	cfg, err := config.Load("config.json", *envOnly)
	if err != nil {
		defaultCfg := config.DefaultConfig()
		defaultCfg.EnvOnly = *envOnly
		cfg = &defaultCfg
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

	// Initialize Server
	srv := server.New(cfg, nil)

	// Attempt to initialize Database if configured
	if cfg.DBType != "" {
		database, err := db.InitDB(ctx, cfg)
		if err != nil {
			logger.Error("Configured database failed to initialize: %v", err)
		} else {
			// Run migrations automatically
			if err := db.Migrate(ctx, database, cfg.DBType); err != nil {
				logger.Error("Database migration failed: %v", err)
				os.Exit(1)
			}
			logger.Debug("Successfully connected to %s database and migrated", cfg.DBType)
			// Inject database into server
			srv = server.New(cfg, database)
		}
	} else {
		logger.Info("Database not configured. Starting in Setup mode.")
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
