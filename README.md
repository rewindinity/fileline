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
- Local disk file storage (`uploads/`)

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
├── translations/           # UI translations (en, pl)
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
git clone https://github.com/<your-user>/fileline.git
cd fileline
go build -o fileline .
./fileline
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

## TODO

- [ ] Add better error handler and debug handler
- [ ] Better error pages
- [ ] More file storage options like S3, FTP/SFTP, WebDav etc
- [ ] Add docker support (via docker image)
- [ ] Custom translation instructions and more languages
- [ ] UI improvements
