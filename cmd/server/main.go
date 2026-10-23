package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/server"
	"fileline/internal/translations"
)

var version = "dev"

func resolveConfigPath() string {
	if v, ok := os.LookupEnv("FL_CONFIG_PATH"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if _, err := os.Stat("config.json"); err == nil {
		return "config.json"
	}
	if _, err := os.Stat("data/config.json"); err == nil {
		return "data/config.json"
	}
	return "data/config.json"
}

func runHealthCheck(cfg *config.Config) int {
	port := 8080
	if cfg != nil && cfg.Port > 0 {
		port = cfg.Port
	}
	scheme := "http"
	if cfg != nil && cfg.SSL {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
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
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.BoolVar(&showVersion, "v", false, "Print version and exit (shorthand)")

	var envOnly bool
	flag.BoolVar(&envOnly, "envonly", false, "Use only environment variables for configuration")
	flag.BoolVar(&envOnly, "env-only", false, "Use only environment variables for configuration (alias)")

	configPath := resolveConfigPath()
	flag.StringVar(&configPath, "config", configPath, "Path to configuration file")
	flag.StringVar(&configPath, "c", configPath, "Path to configuration file (shorthand)")

	debug := flag.Bool("debug", false, "Enable debug mode with detailed HTTP and audit logs")
	healthCheck := flag.Bool("healthcheck", false, "Probe local /health endpoint and exit (for container HEALTHCHECK)")
	flag.BoolVar(debug, "d", false, "Enable debug mode (shorthand)")
	flag.Parse()

	if showVersion {
		fmt.Printf("FileLine %s\n", version)
		os.Exit(0)
	}

	if v, ok := os.LookupEnv("FL_ENV_ONLY"); ok {
		if b, err := strconv.ParseBool(v); err == nil && b {
			envOnly = true
		}
	}

	if *healthCheck {
		cfg, _ := config.Load(configPath, envOnly)
		os.Exit(runHealthCheck(cfg))
	}

	// Initialize configuration (fail closed on parse/read errors)
	cfg, err := config.Load(configPath, envOnly)
	if err != nil {
		logger.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}
	if cfg.DataKey != "" {
		db.SetDataKey(cfg.DataKey)
	}
	if err := cfg.EnsureJWTKey(configPath); err != nil {
		logger.Error("Invalid JWT signing key configuration: %v", err)
		os.Exit(1)
	}
	if err := cfg.EnsureDataKey(configPath); err != nil {
		logger.Error("Invalid data encryption key configuration: %v", err)
		os.Exit(1)
	}

	if *debug {
		cfg.Debug = true
	}
	if os.Getenv("FL_DATA_KEY") == "" && cfg.DataKey == "" {
		logger.Debug("FL_DATA_KEY not set; using persistent key in data directory")
	}
	logger.SetDebug(cfg.Debug)

	if cfg.Debug {
		logger.Debug("Debug mode enabled")
	}

	// Load translations
	if err := translations.Load(); err != nil {
		logger.Error("Failed to load translations: %v", err)
	}

	_ = os.MkdirAll("data", 0o750)
	if cfg.LocalStoragePath != "" {
		_ = os.MkdirAll(cfg.LocalStoragePath, 0o750)
	}
	if cfg.ChunksDir != "" {
		_ = os.MkdirAll(cfg.ChunksDir, 0o700)
	}

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
	srv.SetConfigPath(configPath)

	// Check setup state and generate a one-time setup token when not yet configured
	configured, err := srv.CheckConfigured(ctx)
	if err != nil {
		logger.Error("Failed to verify setup state: %v", err)
		os.Exit(1)
	}
	if !configured {
		token := srv.EnableSetupToken()
		scheme := "http"
		if cfg.SSL {
			scheme = "https"
		}
		logger.Info("========================================================================")
		logger.Info("  FileLine is ready for initial configuration!")
		logger.Info("  Open in your browser: %s://localhost:%d/setup", scheme, cfg.Port)
		logger.Info("  One-time setup token: %s", token)
		logger.Info("========================================================================")
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
