![Logo](gh.png)
# iExported
View your iMessage chat history right from your browser.

## Key Features
- Familiar Apple-like interface with native dark mode support.
- Single pane view of conversations across all exports.
- Incredible performance, can handle thousands of conversations across multiple exports.
- Instant search across all conversations and all exports.
- Pretty phone number and group name rendering.
- Functions entirely offline and features password protection.

## Use Cases
- **Export Viewer:** View your iMessage chat history right from your browser, from your phone or desktop.
- **Sharing:** Share your iMessage chat history with another person.
- **Storage Savings:** Export your iMessage chat history, delete it, and recall conversations from your browser.
- **Backup:** Backup your iMessage chat history in case something goes wrong.

## The "Why"
I created iExported to break the dependence between iMessage history and iCloud storage.

After I accumulated over 5GB of iMessage data, I was stuck: I either had to delete all my precious conversations or pay for an iCloud+ subscription. While services like Immich give an excellent alternative to iCloud Photos, no equivalent exists for iMessage. Existing tools like ReagentX’s exporter are great for data extraction, but they lack a centralized interface to view the data, especially on mobile devices.

iExported fills this specific gap for messages. It is a self-hosted web application that provides a centralized, mobile-friendly view of your entire chat history. It’s designed to be expandable, so you can seamlessly add new exports as your device storage fills up again. Now, I can access my messages on any device without being tied to my computer or a subscription.

## Installation

### Prerequisites
- You need at least one iMessage in HTML format created using [ReagentX/imessage-exporter](https://github.com/ReagentX/imessage-exporter).
- All exports must be placed within a single parent directory (the folder you mount to the container), with each export stored as its own dedicated subfolder.

### Docker Compose (recommended)
The image is published on Docker Hub as `octiwhale/iexported`.

#### 1) Prepare a data folder
iExported reads snapshots from a data folder mounted to `/root/data`.

#### 2) Generate a password hash (recommended)
iExported accepts either plaintext or bcrypt, but bcrypt is strongly recommended.

```bash
htpasswd -bnBC 10 "" "your_password" | tr -d ':\n'
```

Copy the output hash and set it as `AUTH_PASSWORD`.

#### 3) Create an env file (recommended)
Create a `.env` file next to your Compose file to securely store your secrets.

```bash
AUTH_PASSWORD=<bcrypt-hash>
AUTH_SECRET=<long-random-secret>
LOG_LEVEL=warn
# Set to 1 only if served over HTTPS (e.g. behind a reverse proxy)
# HTTPS_ENABLED=1
```

#### 4) Run with Docker Compose
```yaml
services:
  iexported:
    image: octiwhale/iexported:latest
    container_name: iexported
    ports:
      - "8765:8765"
    environment:
      AUTH_PASSWORD: "${AUTH_PASSWORD}"
      AUTH_SECRET: "${AUTH_SECRET}"
      LOG_LEVEL: "${LOG_LEVEL:-warn}"
      # Set to 1 only if served over HTTPS (e.g. behind a reverse proxy)
      # HTTPS_ENABLED: "${HTTPS_ENABLED:-0}"
    volumes:
      - /path/to/data:/root/data:ro
    healthcheck:
      test: ["CMD", "./iexported", "--healthcheck"]
      interval: 10s
      timeout: 5s
      retries: 5
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    restart: unless-stopped
```

Open:
`http://localhost:8765`

### Docker (single container)
If you prefer a plain `docker run`, this is equivalent.

```bash
docker run --rm \
  -p 8765:8765 \
  -e AUTH_PASSWORD='<bcrypt-hash>' \
  -e AUTH_SECRET='<long-random-secret>' \
  -e LOG_LEVEL=warn \
  -v /path/to/data:/root/data:ro \
  octiwhale/iexported:latest
```

## Building from source

### Build the Docker image locally
Download the source and build the Docker image:
```bash
docker build -t iexported:local .
```

Then change your Compose service to:
```yaml
services:
  iexported:
    image: iexported:local
```

### Build and run locally (Go)
```bash
go build -o iexported ./main.go
AUTH_PASSWORD='<bcrypt-hash>' \
AUTH_SECRET='<long-random-secret>' \
LOG_LEVEL=warn \
./iexported
```

The app expects your exports at `/root/data` when running in the container. When running locally, you can either:
- Provide your exports by bind-mounting into the container (recommended), or
- Run in a compatible environment where `/root/data` exists and contains your exports.


## Environment Variables
| Variable | Required | Description |
| --- | --- | --- |
| `AUTH_PASSWORD` | Yes | Password for login. Can be plaintext or bcrypt hash (recommended). |
| `AUTH_SECRET` | No (recommended) | Secret used to sign auth cookies. If not set, a random in-memory secret is generated and sessions will break after restart. |
| `LOG_LEVEL` | No | `error`, `warn`, `info`, `debug` (default: `warn`). |
| `HTTPS_ENABLED` | No | Set to `1`/`true` to mark cookies as `Secure` when served over HTTPS. |
| `DEPLOY_PATH` | No | Base path when deploying under a subpath (e.g. `/iexported/`). Used to generate `manifest.json` start URL/scope. |

## Reverse Proxy (HTTPS)
iExported does not support HTTPS natively. It is recommended to serve iExported behind a reverse proxy for HTTPS. If you're just running it locally or on your home network, you'll probably be fine without HTTPS.

If you enable HTTPS at the proxy, also set:
`HTTPS_ENABLED=1`

### Caddy
```caddy
iexported.example.com {
  reverse_proxy 127.0.0.1:8765
}
```

### Nginx
```nginx
server {
  server_name iexported.example.com;

  location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

### Apache
```apache
<VirtualHost *:80>
  ServerName iexported.example.com

  ProxyPreserveHost On
  ProxyPass / http://127.0.0.1:8765/
  ProxyPassReverse / http://127.0.0.1:8765/
</VirtualHost>