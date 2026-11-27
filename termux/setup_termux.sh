#!/data/data/com.termux/files/usr/bin/bash
# Install WebScout + the server on Termux (run once).
# If you have your modified copy on GitHub:  ZS_REPO=https://github.com/<you>/<repo>.git bash setup_termux.sh
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_URL="${ZS_REPO:-https://github.com/yossfyasen-byte/webscout-engine.git}"

echo "[1/5] Installing packages..."
pkg update -y && pkg upgrade -y
pkg install -y python git rust clang make binutils pkg-config libffi openssl openssl-tool libsqlite termux-tools
termux-setup-storage 2>/dev/null || true

echo "[2/5] Downloading the scanner..."
if [ ! -d "$HOME/webscout-engine" ]; then
  git clone "$REPO_URL" "$HOME/webscout-engine"
else
  echo "Scanner already present, skipping download."
fi

echo "[3/5] Python libraries (this may take a while)..."
pip install -r "$HOME/webscout-engine/requirements.txt"

echo "[4/5] Copying the server..."
mkdir -p "$HOME/webscout-ui"
cp "$HERE/zs_server.py" "$HOME/webscout-ui/"

echo "[5/5] Allowing the app to start the server..."
mkdir -p "$HOME/.termux"
touch "$HOME/.termux/termux.properties"
if ! grep -q '^allow-external-apps' "$HOME/.termux/termux.properties"; then
  echo 'allow-external-apps = true' >> "$HOME/.termux/termux.properties"
fi
termux-reload-settings 2>/dev/null || true

echo
echo "Done. Open the WebScout app."
echo "Or start it manually:  cd ~/webscout-ui && python zs_server.py"
