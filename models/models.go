package models

import "time"

// Config defines runtime/application configuration loaded from config.json.
type Config struct {
	Port          int    `json:"port"`
	Domain        string `json:"domain,omitempty"`
	SSLEnabled    bool   `json:"ssl_enabled"`
	CertBase64    string `json:"cert_base64,omitempty"`
	KeyBase64     string `json:"key_base64,omitempty"`
	DatabaseType  string `json:"database_type"`   // "sqlite", "mongodb", "postgresql"
	IsBehindProxy bool   `json:"is_behind_proxy"` // Use X-Real-IP/X-Forwarded-For headers
	// MongoDB configuration
	MongoURL string `json:"mongo_url,omitempty"`
	// PostgreSQL configuration
	PgHost     string `json:"pg_host,omitempty"`     // format: "host:port"
	PgUser     string `json:"pg_user,omitempty"`     // format: "user:password"
	PgDatabase string `json:"pg_database,omitempty"` // database name
}

// User is the single account used to manage the FileLine instance.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    string    `json:"created_at"`
	TwoFAEnabled bool      `json:"two_fa_enabled"`
	TwoFASecret  string    `json:"two_fa_secret,omitempty"`
	BackupCode   string    `json:"backup_code,omitempty"` // For account recovery
	Passkeys     []Passkey `json:"passkeys,omitempty"`    // WebAuthn credentials
}

// Passkey stores the persisted data required for WebAuthn authentication.
type Passkey struct {
	ID              []byte `json:"id"`               // Credential ID
	PublicKey       []byte `json:"public_key"`       // Public key
	AttestationType string `json:"attestation_type"` // Attestation type
	AAGUID          []byte `json:"aaguid"`           // Authenticator AAGUID
	SignCount       uint32 `json:"sign_count"`       // Signature counter
	Name            string `json:"name"`             // User-friendly name
	CreatedAt       string `json:"created_at"`       // Creation timestamp
	BackupEligible  bool   `json:"backup_eligible"`  // Backup eligible flag
	BackupState     bool   `json:"backup_state"`     // Backup state flag
}

// AppSettings controls UI preferences and upload behavior defaults.
type AppSettings struct {
	Theme          string `json:"theme"`            // "dark-blue", "dark-green", "dark-orange", "dark-purple", "light"
	AccentColor    string `json:"accent_color"`     // hex color
	Language       string `json:"language"`         // "en", "pl"
	ChunkSizeBytes int64  `json:"chunk_size_bytes"` // chunk size for uploads
	ChunkThreshold int64  `json:"chunk_threshold"`  // files above this use chunked upload (bytes)
	MaxFileSize    int64  `json:"max_file_size"`    // maximum file size in bytes (0 = unlimited)
	CustomLogo     string `json:"custom_logo"`      // base64 encoded custom logo (optional)
}

// ChunkUpload tracks server-side state for an in-progress chunked transfer.
type ChunkUpload struct {
	ID          string `json:"id"`
	FileName    string `json:"file_name"`
	TotalSize   int64  `json:"total_size"`
	TotalChunks int    `json:"total_chunks"`
	Received    []bool `json:"received"`
	IsPrivate   bool   `json:"is_private"`
	CustomLink  string `json:"custom_link"`
	TempDir     string `json:"temp_dir"`
	CreatedAt   string `json:"created_at"`
}

// FileEntry stores metadata for one uploaded file object.
type FileEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Link       string `json:"link"`
	Size       int64  `json:"size"`
	UploadedAt string `json:"uploaded_at"`
	IsPrivate  bool   `json:"is_private"`
}

// SessionData stores authentication state for one browser session.
type SessionData struct {
	Expiry   time.Time
	Needs2FA bool
	Username string
}

const (
	// Config/storage file locations.
	ConfigFile   = "config.json"
	DBFileSQLite = "database.sqlite"
	UploadsDir   = "uploads"
	ChunksDir    = "chunks"
	SessionName  = "fileline_session"
	// Upload defaults are intentionally conservative for broad compatibility.
	DefaultChunkSize      = 10 * 1024 * 1024  // 10MB chunks
	DefaultChunkThreshold = 100 * 1024 * 1024 // 100MB threshold
)
