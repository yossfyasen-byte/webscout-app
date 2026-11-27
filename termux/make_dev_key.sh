#!/data/data/com.termux/files/usr/bin/bash
# Run ONCE on YOUR phone. Creates the private key that signs activation keys.
# Keep the private key secret: never upload it, never put it in the app.
set -e
DIR="$HOME/.webscout-dev"
mkdir -p "$DIR"
if [ -f "$DIR/license_private.pem" ]; then
  echo "Private key already exists: $DIR/license_private.pem"
else
  openssl genrsa -out "$DIR/license_private.pem" 2048 2>/dev/null
  chmod 600 "$DIR/license_private.pem"
  echo "Private key created: $DIR/license_private.pem"
fi
echo
echo "Public key. Paste it as PUBLIC_KEY_B64 in License.java, then rebuild the APK:"
openssl rsa -in "$DIR/license_private.pem" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n'
echo
