#!/usr/bin/env bash

set -euo pipefail

# ---- CONFIG ----
APP_NAME="rust-server"
SERVICE_NAME="printedin3d-rs.service"
APP_USER="printedin3d"
APP_GROUP="printedin3d"
APP_DIR="/opt/printedin3d"
BUILD_DIR="target/release"
DEST_PATH="/usr/local/bin/$APP_NAME"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

# ---- BUILD ----
echo "==> Building release binary locally from current repo..."
cargo build --release

# ---- VERIFY BUILD OUTPUT ----
if [[ ! -f "$BUILD_DIR/$APP_NAME" ]]; then
  echo "Error: build artifact not found at $BUILD_DIR/$APP_NAME"
  exit 1
fi

# ---- BOOTSTRAP USER + APP DIR ----
echo "==> Ensuring service user/group exist..."
if ! getent group "$APP_GROUP" >/dev/null; then
  sudo groupadd --system "$APP_GROUP"
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  sudo useradd --system --gid "$APP_GROUP" --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

echo "==> Ensuring runtime directory exists at $APP_DIR"
sudo mkdir -p "$APP_DIR"
sudo chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
sudo chmod 755 "$APP_DIR"

# ---- INSTALL BINARY ----
echo "==> Installing binary to $DEST_PATH"
sudo install -m 755 "$BUILD_DIR/$APP_NAME" "$DEST_PATH"

# ---- INSTALL/UPDATE SYSTEMD UNIT ----
echo "==> Writing systemd unit: $SERVICE_PATH"
sudo tee "$SERVICE_PATH" >/dev/null <<EOF
[Unit]
Description=PrintedIn3D Rust Backend
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
ExecStart=$DEST_PATH
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# ---- RELOAD + ENABLE + RESTART ----
echo "==> Reloading systemd daemon"
sudo systemctl daemon-reload

echo "==> Enabling service on boot"
sudo systemctl enable "$SERVICE_NAME"

echo "==> Restarting service"
sudo systemctl restart "$SERVICE_NAME"

# ---- STATUS ----
echo "==> Service status:"
sudo systemctl status "$SERVICE_NAME" --no-pager

echo "==> Done. Backend is configured to start on boot."
