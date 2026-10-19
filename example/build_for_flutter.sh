#!/usr/bin/env bash
# Builds libsnapstore_auth and stages it next to a Flutter app's Linux
# executable so the FFI client (snapstore_auth_dart) finds it at runtime.
#
# Usage: ./example/build_for_flutter.sh <path/to/flutter-app>
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="${1:?usage: build_for_flutter.sh <path/to/flutter-app>}"
[ -d "$APP_DIR" ] || { echo "no such dir: $APP_DIR" >&2; exit 1; }

cd "$REPO_DIR"
cargo build --release
SO="target/release/libsnapstore_auth.so"
[ -f "$SO" ] || { echo "missing $SO" >&2; exit 1; }

# Stage next to the app sources and any existing build output trees.
mkdir -p "$APP_DIR/linux/rust"
cp -f "$SO" "$APP_DIR/linux/rust/libsnapstore_auth.so"
echo ">> staged: $APP_DIR/linux/rust/libsnapstore_auth.so"
for cfg in debug release; do
  dst="$APP_DIR/build/linux/x64/$cfg"
  if [ -d "$dst" ]; then
    cp -f "$SO" "$dst/libsnapstore_auth.so"
    echo ">> staged: $dst/libsnapstore_auth.so"
  fi
done
echo ">> done. For tests/CI without staging set:"
echo "   SNAPSTORE_AUTH_LIB=$REPO_DIR/$SO"
