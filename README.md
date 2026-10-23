# FileLine

<p align="center">
  <img src="web/static/logo.svg" alt="FileLine Logo" width="120" height="120">
</p>

<p align="center">
  <strong>Fast, self-hosted, secure file sharing platform built with Go.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#running-with-docker-compose-recommended">Docker Compose</a> •
  <a href="#running-with-systemd-linux-service">Systemd</a> •
  <a href="#running-as-standalone-binary">Standalone Binary</a> •
  <a href="#web-setup-wizard">Web Setup</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#storage--databases">Storage & Databases</a> •
  <a href="#reverse-proxy-https">Reverse Proxy</a> •
  <a href="#building-from-source">Build from Source</a>
</p>

---

## Features

- **🚀 Single Static Binary**: Zero runtime dependencies. HTML, CSS, JavaScript, and fonts are compiled directly into the binary via `embed.FS`.
- **⚡ 3-Minute Web Setup Wizard**: No manual configuration files required on first boot. Configure everything right from your browser.
- **🔒 Secure Authentication**: Hardware Passkeys (**WebAuthn / FIDO2**), **TOTP 2FA** (Google Authenticator, Bitwarden), and emergency recovery codes.
- **📦 Dual Database Support**: Embedded **SQLite** with Write-Ahead Logging (zero setup) or production **PostgreSQL**.
- **📁 Flexible Storage**: Store files locally or connect to S3-compatible cloud storage (**Cloudflare R2**, **MinIO**, **AWS S3**, **Wasabi**, **Backblaze B2**).
- **🧩 Resumable Chunked Uploads**: Transfer multi-gigabyte files reliably with client-side chunking without browser or server memory bloat.
- **👥 Multi-User & Quotas**: Create subuser accounts with custom storage quotas and drive permissions.
- **🎨 Rich Media Embeds**: Shareable links generate rich preview cards for Discord, Twitter/X, and Telegram with customizable themes and accents.
- **🛡️ Bot Privacy Protection**: Automatic bot indexing defense (`noindex, nofollow`, `robots.txt`) to keep shares private.

---

## Running with Docker Compose (Recommended)

Docker Compose is the easiest and quickest way to deploy FileLine.

### 1. Create `docker-compose.yml`

```yaml
services:
  fileline:
    image: ghcr.io/rewindinity/fileline:latest
    container_name: fileline
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
      - ./chunks:/app/chunks
```

### 2. Start the Service

```bash
docker compose up -d
```

### 3. Retrieve Your Setup Token

Check the container logs to find the one-time setup token:

```bash
docker compose logs -f
```

Navigate to `http://<SERVER_IP>:8080/setup` to finish onboarding.

---

## Running with Systemd (Linux Service)

For bare-metal servers or Linux VPS instances, running FileLine as a standard systemd service is straightforward.

### 1. Create a System User & Directories

```bash
# Create a dedicated system user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/fileline fileline

# Create application directories
sudo mkdir -p /var/lib/fileline/data /var/lib/fileline/uploads /var/lib/fileline/chunks
sudo chown -R fileline:fileline /var/lib/fileline

# Place the compiled binary
sudo cp fileline /usr/local/bin/fileline
sudo chmod 755 /usr/local/bin/fileline
```

### 2. Create the Service File

Create `/etc/systemd/system/fileline.service`:

```ini
[Unit]
Description=FileLine File Sharing Service
After=network.target

[Service]
Type=simple
User=fileline
Group=fileline
WorkingDirectory=/var/lib/fileline
ExecStart=/usr/local/bin/fileline -config /var/lib/fileline/data/config.json
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### 3. Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fileline
```

Check the logs to grab your one-time setup token:

```bash
journalctl -u fileline -f
```

---

## Running as Standalone Binary

For local testing or quick evaluation:

```bash
# 1. Download release binary (Linux x86_64 example)
curl -LO https://github.com/rewindinity/fileline/releases/latest/download/fileline-linux-amd64
chmod +x fileline-linux-amd64
mv fileline-linux-amd64 fileline

# 2. Run
./fileline
```

FileLine will automatically generate default directories, encryption keys, and print the setup URL to your console.

---

## Web Setup Wizard

Once FileLine is started (via Docker, Systemd, or binary):

1. Open `http://localhost:8080/setup` (or `http://<YOUR_SERVER_IP>:8080/setup`).
2. Paste the **One-time setup token** printed in your console or container logs.
3. Choose your database (**SQLite** is ready out of the box; PostgreSQL is also supported).
4. Select your storage type (**Local Disk** or S3 Object Storage).
5. Set your administrator username and password, then click **Complete Setup**.
6. Done! Log in and start sharing files.

---

## Configuration

FileLine resolves its configuration from `data/config.json` (or via `-config <path>` / `FL_CONFIG_PATH`). Most settings can be adjusted through the web admin panel under **Settings**, or configured directly in the JSON file or via environment variables.

### Basic `config.json`

For most standalone or single-user instances:

```json
{
  "port": 8080,
  "domain": "files.example.com",
  "storage_type": "local",
  "local_storage_path": "./uploads",
  "chunks_dir": "./chunks",
  "max_upload_size_mb": 2048,
  "theme": "dark-blue",
  "accent": "blue",
  "default_language": "en"
}
```

### Advanced `config.json`

For production environments, reverse proxies, S3 cloud storage, multi-drive arrays, and performance tuning:

```json
{
  "db_type": "sqlite",
  "sqlite_url": "data/database.sqlite",
  "postgres_url": "",
  "port": 8080,
  "domain": "files.example.com",
  "ssl": false,
  "ssl_cert_path": "",
  "ssl_key_path": "",
  "reverse_proxy": true,
  "trusted_proxies": ["127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "allow_insecure_http_dev": false,
  "storage_type": "local",
  "local_storage_path": "./uploads",
  "chunks_dir": "./chunks",
  "max_upload_size_mb": 4096,
  "chunk_threshold_mb": 50,
  "chunk_size_mb": 10,
  "s3_endpoint": "",
  "s3_region": "",
  "s3_bucket": "",
  "s3_access_key": "",
  "s3_secret_key": "",
  "s3_use_ssl": true,
  "drives": [
    {
      "id": "nvme_drive",
      "name": "Fast Local NVMe",
      "type": "local",
      "enabled": true,
      "local_storage_path": "/mnt/nvme/uploads"
    },
    {
      "id": "r2_cold",
      "name": "Cloudflare R2 Cold Storage",
      "type": "s3",
      "enabled": true,
      "s3_endpoint": "https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
      "s3_region": "auto",
      "s3_bucket": "archive-bucket",
      "s3_access_key": "YOUR_R2_KEY",
      "s3_secret_key": "YOUR_R2_SECRET",
      "s3_use_ssl": true
    }
  ],
  "theme": "dark-blue",
  "accent": "blue",
  "custom_accent_hex": "#2563eb",
  "custom_logo": "/static/logo.svg",
  "default_language": "en",
  "block_indexing": true,
  "gzip_enabled": true,
  "minify_responses": true,
  "debug": false
}
```

### Full Configuration Reference

| Parameter            | Type       | Default                  | Description                                                                                          |
| :------------------- | :--------- | :----------------------- | :--------------------------------------------------------------------------------------------------- |
| `db_type`            | `string`   | `"sqlite"`               | Database backend: `"sqlite"` or `"postgres"`. When empty, boots into setup wizard.                   |
| `sqlite_url`         | `string`   | `"data/database.sqlite"` | Path to SQLite database file. Automatically uses WAL mode.                                           |
| `postgres_url`       | `string`   | `""`                     | PostgreSQL connection string (e.g. `postgres://user:pass@host:5432/db?sslmode=disable`).             |
| `port`               | `integer`  | `8080`                   | Port the HTTP(S) server listens on.                                                                  |
| `domain`             | `string`   | `"localhost"`            | Canonical domain or IP. Required for WebAuthn/Passkey registration and share link generation.        |
| `ssl`                | `boolean`  | `false`                  | Enables built-in TLS listener (requires `ssl_cert_path` and `ssl_key_path`).                         |
| `ssl_cert_path`      | `string`   | `""`                     | Path to TLS certificate file (`fullchain.pem`).                                                      |
| `ssl_key_path`       | `string`   | `""`                     | Path to TLS private key file (`privkey.pem`).                                                        |
| `reverse_proxy`      | `boolean`  | `false`                  | Enables processing of `X-Forwarded-*` headers when placed behind Caddy, Nginx, or Traefik.           |
| `trusted_proxies`    | `[]string` | `[]`                     | CIDR blocks of trusted reverse proxies. Prevents IP spoofing in brute-force rate limiters.           |
| `storage_type`       | `string`   | `"local"`                | Primary storage backend: `"local"` or `"s3"`.                                                        |
| `local_storage_path` | `string`   | `"./uploads"`            | Directory for stored files (sandboxed with Go 1.24+ `os.Root` to prevent path traversal).            |
| `chunks_dir`         | `string`   | `"./chunks"`             | Directory used for temporary chunk assembly during large uploads.                                    |
| `max_upload_size_mb` | `integer`  | `1024`                   | Maximum upload size in megabytes (`0` for unlimited).                                                |
| `chunk_threshold_mb` | `integer`  | `50`                     | Files larger than this threshold are uploaded in chunks by the browser.                              |
| `chunk_size_mb`      | `integer`  | `10`                     | Size of each upload chunk in megabytes.                                                              |
| `s3_endpoint`        | `string`   | `""`                     | S3 API endpoint URL (for Cloudflare R2, MinIO, AWS S3, Wasabi, B2).                                  |
| `s3_region`          | `string`   | `""`                     | S3 region (e.g. `auto`, `us-east-1`, `eu-central-1`).                                                |
| `s3_bucket`          | `string`   | `""`                     | S3 bucket name.                                                                                      |
| `s3_access_key`      | `string`   | `""`                     | S3 access key ID.                                                                                    |
| `s3_secret_key`      | `string`   | `""`                     | S3 secret access key.                                                                                |
| `s3_use_ssl`         | `boolean`  | `true`                   | Whether to communicate with S3 over HTTPS.                                                           |
| `drives`             | `[]object` | `[]`                     | Secondary storage drives. Subusers can be allocated to specific drives with quotas.                  |
| `theme`              | `string`   | `"dark-blue"`            | Visual theme: `"dark-blue"`, `"dark"`, `"light"`, `"purple"`, `"emerald"`, `"nord"`.                 |
| `accent`             | `string`   | `"blue"`                 | UI accent color name.                                                                                |
| `custom_accent_hex`  | `string`   | `"#2563eb"`              | Custom HEX accent color code.                                                                        |
| `custom_logo`        | `string`   | `"/static/logo.svg"`     | Path or URL to custom logo image.                                                                    |
| `default_language`   | `string`   | `"en"`                   | Default interface language (`"en"`, `"pl"`, `"de"`, `"fr"`, `"es"`, `"it"`, `"nl"`, `"cz"`, `"sk"`). |
| `block_indexing`     | `boolean`  | `true`                   | Emits `X-Robots-Tag: noindex, nofollow` and serves a restrictive `robots.txt` to block web crawlers. |
| `gzip_enabled`       | `boolean`  | `true`                   | Compresses HTTP responses with gzip.                                                                 |
| `minify_responses`   | `boolean`  | `true`                   | Dynamically minifies HTML, CSS, and JS output for faster loading.                                    |
| `debug`              | `boolean`  | `false`                  | Enables verbose HTTP debug and audit logging.                                                        |

### Environment Variables Matrix

All settings can be overridden via environment variables (or configured purely with env vars using `FL_ENV_ONLY=true`):

| Environment Variable    | Equivalent JSON Key  | Description                                                                |
| :---------------------- | :------------------- | :------------------------------------------------------------------------- |
| `FL_CONFIG_PATH`        | _(none)_             | Custom path to configuration file (default: `data/config.json`)            |
| `FL_ENV_ONLY`           | _(none)_             | When `true`, ignores `config.json` and configures exclusively via env vars |
| `FL_PORT`               | `port`               | HTTP listen port                                                           |
| `FL_DOMAIN`             | `domain`             | Canonical domain name                                                      |
| `FL_DB_TYPE`            | `db_type`            | `"sqlite"` or `"postgres"`                                                 |
| `FL_SQLITE_URL`         | `sqlite_url`         | SQLite database file path                                                  |
| `FL_POSTGRES_URL`       | `postgres_url`       | PostgreSQL connection string                                               |
| `FL_STORAGE_TYPE`       | `storage_type`       | `"local"` or `"s3"`                                                        |
| `FL_LOCAL_STORAGE_PATH` | `local_storage_path` | Local upload storage path                                                  |
| `FL_CHUNKS_DIR`         | `chunks_dir`         | Chunk staging directory                                                    |
| `FL_MAX_UPLOAD_SIZE_MB` | `max_upload_size_mb` | Maximum allowed upload size (MB)                                           |
| `FL_CHUNK_THRESHOLD_MB` | `chunk_threshold_mb` | Chunking threshold (MB)                                                    |
| `FL_CHUNK_SIZE_MB`      | `chunk_size_mb`      | Upload chunk size (MB)                                                     |
| `FL_REVERSE_PROXY`      | `reverse_proxy`      | Enable reverse proxy mode (`true`/`false`)                                 |
| `FL_TRUSTED_PROXIES`    | `trusted_proxies`    | Comma-separated list of trusted proxy CIDRs                                |
| `FL_SSL`                | `ssl`                | Enable built-in TLS (`true`/`false`)                                       |
| `FL_SSL_CERT_PATH`      | `ssl_cert_path`      | TLS certificate path                                                       |
| `FL_SSL_KEY_PATH`       | `ssl_key_path`       | TLS private key path                                                       |
| `FL_JWT_KEY`            | `jwt_key`            | 256-bit secret for signing session JWT tokens                              |
| `FL_DATA_KEY`           | `data_key`           | 256-bit AES-GCM secret for encrypting 2FA secrets at rest                  |
| `FL_BLOCK_INDEXING`     | `block_indexing`     | Block search engine indexing (`true`/`false`)                              |
| `FL_DEBUG`              | `debug`              | Verbose debug logging (`true`/`false`)                                     |

### CLI Flags

| Flag             | Shorthand   | Description                                                                             |
| :--------------- | :---------- | :-------------------------------------------------------------------------------------- |
| `-config <path>` | `-c <path>` | Path to configuration file (default: `data/config.json`)                                |
| `-envonly`       | `-env-only` | Rely strictly on environment variables, ignoring `config.json`                          |
| `-healthcheck`   | _(none)_    | Queries `/health` and returns exit code `0` (healthy) or `1` (for Docker health checks) |
| `-debug`         | `-d`        | Enable verbose HTTP debug output and security audit logs                                |
| `-version`       | `-v`        | Print the FileLine version and exit                                                     |

---

## Storage & Databases

### S3-Compatible Object Storage

FileLine natively supports S3 providers like Cloudflare R2, MinIO, or AWS S3. You can configure them during the setup wizard or via `config.json`:

```json
{
  "storage_type": "s3",
  "s3_endpoint": "https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
  "s3_region": "auto",
  "s3_bucket": "my-bucket",
  "s3_access_key": "YOUR_ACCESS_KEY",
  "s3_secret_key": "YOUR_SECRET_KEY",
  "s3_use_ssl": true
}
```

### PostgreSQL Database

For larger teams or multi-node setups, FileLine supports PostgreSQL:

```json
{
  "db_type": "postgres",
  "postgres_url": "postgres://user:password@localhost:5432/fileline?sslmode=disable"
}
```

Migrations are executed automatically on application launch.

---

## Reverse Proxy (HTTPS)

When exposing FileLine to the internet, putting it behind a reverse proxy provides HTTPS encryption.

### Option A: Caddy

Caddy automatically provisions and renews SSL certificates:

```caddy
files.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

In `data/config.json`:

```json
{
  "domain": "files.example.com",
  "reverse_proxy": true,
  "trusted_proxies": ["127.0.0.1/32"]
}
```

### Option B: Nginx

```nginx
server {
    listen 80;
    server_name files.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name files.example.com;

    ssl_certificate /etc/letsencrypt/live/files.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/files.example.com/privkey.pem;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        # Disable buffering for chunked streaming
        proxy_request_buffering off;
        proxy_buffering off;
    }
}
```

---

## Building from Source

### Prerequisites

- **Go 1.24** or newer
- Git

```bash
git clone https://github.com/rewindinity/fileline.git
cd fileline

# Compile for your current host
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o fileline ./cmd/server
```

### Cross-Compilation Examples

You can cross-compile FileLine for all supported targets without external toolchains:

```bash
# Linux (amd64)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o fileline-linux-amd64 ./cmd/server

# Linux (arm64 - Raspberry Pi, ARM VPS)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o fileline-linux-arm64 ./cmd/server

# Windows (amd64)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o fileline-windows-amd64.exe ./cmd/server

# macOS (Apple Silicon arm64 - M1/M2/M3/M4)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o fileline-macos-arm64 ./cmd/server
```

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
