#!/bin/sh
set -e

DEPLOY_PATH="${DEPLOY_PATH:-/}"

# Normalize: ensure leading slash
case "$DEPLOY_PATH" in
  /*) : ;;
  *) DEPLOY_PATH="/${DEPLOY_PATH}" ;;
esac
# Normalize: ensure trailing slash
case "$DEPLOY_PATH" in
  */) : ;;
  *) DEPLOY_PATH="${DEPLOY_PATH}/" ;;
esac

# Paths
STATIC_DIR="/root/static"
MANIFEST_PATH="${STATIC_DIR}/manifest.json"

# Create static dir if missing
mkdir -p "$STATIC_DIR"

# Generate manifest.json dynamically
cat > "$MANIFEST_PATH" <<EOF
{
  "name": "iExported",
  "short_name": "iExported",
  "description": "Viewer for iMessage exports",
  "start_url": "${DEPLOY_PATH}",
  "scope": "${DEPLOY_PATH}",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#007aff",
  "orientation": "portrait-primary",
  "icons": [
    {
      "src": "${DEPLOY_PATH}manifest-192x192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "maskable"
    },
    {
      "src": "${DEPLOY_PATH}manifest-512x512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "maskable"
    }
  ],
  "categories": ["productivity"]
}

EOF

# If INFO logging is enabled, print the manifest path
if [ "${LOG_LEVEL}" = "info" ]; then
    echo "Generated manifest.json"
fi

# Start the application
exec /root/iexported
