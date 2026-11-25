#!/data/data/com.termux/files/usr/bin/bash
# تثبيت ZeroSpecter + السيرفر على تيرمكس (مرة وحدة).
# إذا عندك نسختك المعدّلة على GitHub:  ZS_REPO=https://github.com/<you>/<repo>.git bash setup_termux.sh
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_URL="${ZS_REPO:-https://github.com/AlmunharifHamoudi/zerospecter.git}"

echo "[1/5] تثبيت الحزم..."
pkg update -y && pkg upgrade -y
pkg install -y python git rust clang make binutils pkg-config libffi openssl libsqlite

echo "[2/5] تحميل الأداة..."
if [ ! -d "$HOME/zerospecter" ]; then
  git clone "$REPO_URL" "$HOME/zerospecter"
else
  echo "الأداة موجودة مسبقاً، تخطّيت التحميل."
fi

echo "[3/5] مكتبات بايثون (ممكن تاخد وقت)..."
pip install -r "$HOME/zerospecter/requirements.txt"

echo "[4/5] نسخ السيرفر..."
mkdir -p "$HOME/zerospecter-ui"
cp "$HERE/zs_server.py" "$HOME/zerospecter-ui/"

echo "[5/5] السماح للتطبيق بتشغيل السيرفر..."
mkdir -p "$HOME/.termux"
touch "$HOME/.termux/termux.properties"
if ! grep -q '^allow-external-apps' "$HOME/.termux/termux.properties"; then
  echo 'allow-external-apps = true' >> "$HOME/.termux/termux.properties"
fi
termux-reload-settings 2>/dev/null || true

echo
echo "خلص. افتح تطبيق ZeroSpecter."
echo "أو شغّل يدوياً:  cd ~/zerospecter-ui && python zs_server.py"
