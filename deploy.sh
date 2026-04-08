#!/usr/bin/env bash

set -euo pipefail

# ---- CONFIG ----
APP_NAME="my_rust_app"                 # binary name
SERVICE_NAME="my_rust_app.service"     # systemd service
BUILD_DIR="target/release"
DEST_PATH="/usr/local/bin/$APP_NAME"   # where systemd expects the binary

# ---- BUILD ----
echo "==> Building release binary..."
cargo build --release

# ---- VERIFY BUILD OUTPUT ----
if [[ ! -f "$BUILD_DIR/$APP_NAME" ]]; then
  echo "Error: build artifact not found at $BUILD_DIR/$APP_NAME"
  exit 1
fi

# ---- STOP SERVICE ----
echo "==> Stopping systemd service: $SERVICE_NAME"
sudo systemctl stop "$SERVICE_NAME"

# ---- COPY BINARY ----
echo "==> Deploying binary to $DEST_PATH"
sudo cp "$BUILD_DIR/$APP_NAME" "$DEST_PATH"
sudo chmod +x "$DEST_PATH"

# Optional: ensure correct ownership
# sudo chown root:root "$DEST_PATH"

# ---- START SERVICE ----
echo "==> Starting systemd service: $SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"

# ---- STATUS ----
echo "==> Service status:"
sudo systemctl status "$SERVICE_NAME" --no-pager

echo "==> Deployment complete."
