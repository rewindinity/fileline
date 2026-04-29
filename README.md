# FileLine

FileLine is a lightweight self-hosted file host for quickly sharing files with public or private links.

## Features

- Fast setup (single binary + `config.json`)
- Public and private file links
- 2FA (TOTP)
- Passkey login (WebAuthn)
- Password reset with one-time recovery code
- Theme, accent color, and custom logo
- Responsive UI (desktop/mobile/tablet)
- Chunked upload for large files
- Multi-drive storage: local disk (default), optional S3/FTP/SFTP drives

## Supported databases

| Database       | Best use case                                   |
| -------------- | ----------------------------------------------- |
| **SQLite**     | Small/single-node deployments, easiest startup  |
| **PostgreSQL** | Production workloads, higher write concurrency  |
| **MongoDB**    | Production workloads, flexible document storage |

## Project structure

```text
fileline/
├── main.go                 # Server entrypoint and route wiring
├── auth/                   # Sessions, CSRF, rate limiting, upload limiting
├── database/               # Database backends (sqlite, postgresql, mongodb) + config loading
├── handlers/               # HTTP handlers (setup, auth, files, settings, APIs)
├── models/                 # Shared data models and constants
├── templates/              # HTML templates
├── static/                 # CSS, JS, fonts, logos
├── storage/                # Storage backends (local, S3, FTP, SFTP)
├── translations/           # UI translations (en, pl, de, fr, cz)
├── uploads/                # Uploaded files (runtime data)
└── chunks/                 # Temporary chunk-upload data (runtime data)
```

## Running FileLine

### Option 1: Use prebuilt binaries

Download from [Releases](https://github.com/rewindinity/fileline/releases), then run:

```bash
# Linux / macOS
chmod +x fileline-linux-amd64
./fileline-linux-amd64

# Windows
fileline-windows-amd64.exe
```

### Option 2: Build from source

Requirements: Go (version from `go.mod`)

```bash
git clone https://github.com/rewindinity/fileline.git
cd fileline
go build -o fileline .
./fileline

# Enable verbose request/debug logging
./fileline --debug
```

### Option 3: Docker (public image)

Public image:

`ghcr.io/rewindinity/fileline:latest`

```bash
docker pull ghcr.io/rewindinity/fileline:latest
docker run -d \
  --name fileline \
  -p 8080:8080 \
  -v "$(pwd)/fileline-data:/app" \
  --restart unless-stopped \
  ghcr.io/rewindinity/fileline:latest
```

### Option 4: Docker Compose

Use the public image:

```bash
docker compose up -d
```

This stores runtime data in `./fileline-data` (including `config.json`, `database.sqlite`, `uploads/`, and `chunks/`).

For local development with local source files mounted:

```bash
docker compose -f docker-compose-dev.yml up
```

After startup, open:

`http://localhost:8080/setup`

## Configuration (`config.json`)

`config.json` is created automatically on first run with defaults:

```json
{
  "port": 8080,
  "database_type": "sqlite"
}
```

### Common fields

| Field             | Type   | Default  | Notes                                           |
| ----------------- | ------ | -------- | ----------------------------------------------- |
| `port`            | int    | `8080`   | HTTP/HTTPS listen port                          |
| `domain`          | string | empty    | Public domain; recommended for passkeys and TLS |
| `ssl_enabled`     | bool   | `false`  | Enable built-in HTTPS                           |
| `cert_base64`     | string | empty    | Base64-encoded PEM certificate                  |
| `key_base64`      | string | empty    | Base64-encoded PEM private key                  |
| `is_behind_proxy` | bool   | `false`  | Trust `X-Real-IP` / `X-Forwarded-For` headers   |
| `database_type`   | string | `sqlite` | `sqlite`, `postgresql`, or `mongodb`            |

### Database fields by backend

| Backend      | Required fields                     |
| ------------ | ----------------------------------- |
| `sqlite`     | none                                |
| `postgresql` | `pg_host`, `pg_user`, `pg_database` |
| `mongodb`    | `mongo_url`                         |

`postgresql` field format:

- `pg_host`: `host:port` (example: `localhost:5432`)
- `pg_user`: `user:password` (example: `fileline:secret`)
- `pg_database`: database name (example: `fileline`)

### Database configuration examples

#### SQLite

```json
{
  "port": 8080,
  "database_type": "sqlite"
}
```

SQLite data is stored in `database.sqlite` in the working directory.

#### PostgreSQL

```json
{
  "port": 8080,
  "database_type": "postgresql",
  "pg_host": "localhost:5432",
  "pg_user": "fileline:secret",
  "pg_database": "fileline"
}
```

#### MongoDB

```json
{
  "port": 8080,
  "database_type": "mongodb",
  "mongo_url": "mongodb://localhost:27017/fileline"
}
```

With authentication:

```json
{
  "port": 8080,
  "database_type": "mongodb",
  "mongo_url": "mongodb://fileline:secret@localhost:27017/fileline?authSource=admin"
}
```

### Reverse proxy setup example

```json
{
  "port": 8080,
  "ssl_enabled": false,
  "is_behind_proxy": true,
  "database_type": "sqlite"
}
```

Example nginx config:

```nginx
server {
    listen 443 ssl;
    server_name files.example.com;

    ssl_certificate     /etc/letsencrypt/live/files.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/files.example.com/privkey.pem;

    client_max_body_size 10G;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

### Built-in HTTPS (without reverse proxy)

```json
{
  "port": 443,
  "domain": "files.example.com",
  "ssl_enabled": true,
  "cert_base64": "<base64-pem-cert>",
  "key_base64": "<base64-pem-key>",
  "is_behind_proxy": false,
  "database_type": "sqlite"
}
```

## Storage drives

FileLine always includes a local `local` drive (stored in `uploads/`).

You can add optional external drives in **Settings -> Storage Drives**:

- S3 (`s3-main`)
- FTP (`ftp-main`)
- SFTP (`sftp-main`)

When at least one external drive is configured, the upload form shows an **Upload Drive** selector.
All uploads/downloads/deletes are proxied through FileLine; links remain `/f/<link>` regardless of backend.

## Custom translations

Translations are embedded into the binary from `translations/*.json` (`go:embed`), so adding a new language requires a source rebuild.

1. Copy `translations/en.json` to a new file like `translations/de.json`.
2. Keep the same JSON structure and keys, and translate only the values for example:
   `"uploading": "your translation",`
3. Add a display label for the language itself within the settings object into all translation files:

```
"settings": {
  "language_de": "Deutsch"
}
```

4. You need to inform the Go backend about the new file and allow the new language code.

- `translations/i18n.go`: Add the new filename to the files slice inside the _Load()_ function:
  `files := []string{"en.json", "pl.json", "de.json", "fr.json", "cz.json"}`
- Validation: Add the language code (e.g., "de") to the validLangs slice in both:
  - `handlers/setup.go`
  - `handlers/settings.go`

5. Update UI Templates (Frontend)
   Add the new language option to the selection menus in your HTML templates.

- `templates/setup.html`:
  - `<option value="de" {{if eq .Lang "de"}}selected{{end}}>Deutsch</option>`
- `templates/settings.html`:
  - `<option value="de" {{if eq .Settings.Language "de"}}selected{{end}}> {{if .T.settings}}{{index .T.settings "language_de"}}{{else}}Deutsch{{end}} </option>`

6. Rebuild and restart:

```bash
go build -o fileline .
./fileline
```

## TODO

- [x] Add better error handler and debug handler
- [x] Better error pages
- [x] More file storage options like S3, FTP/SFTP, WebDav etc
- [x] Add docker support (via docker image)
- [x] Custom translation instructions and more languages
- [ ] UI improvements
