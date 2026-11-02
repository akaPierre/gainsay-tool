#!/usr/bin/env sh
# Builds a standalone Gainsay for Linux/macOS: dist/gainsay/ with its own Java runtime, a tarball,
# and optionally a native package:  ./packaging/package.sh [deb|rpm|pkg]
set -eu
cd "$(dirname "$0")/.."

VERSION=0.1.0
JAR="gainsay-$VERSION.jar"
MODULES=java.base,java.desktop,java.sql,java.logging

command -v jpackage >/dev/null 2>&1 || { echo "jpackage not found: install a JDK 21+ and put its bin on PATH" >&2; exit 1; }

echo "1/3 Building and testing the jar..."
mvn -q -B package

rm -rf target/jpackage-input dist/gainsay
mkdir -p target/jpackage-input dist
cp "target/$JAR" target/jpackage-input/

set -- --name gainsay --app-version "$VERSION" --vendor Gainsay \
  --description "Cross-examines security settings against observed network traffic (read-only, passive)." \
  --input target/jpackage-input --main-jar "$JAR" --main-class dev.gainsay.cli.Main \
  --add-modules "$MODULES" --jlink-options "--strip-debug --no-header-files --no-man-pages" \
  --java-options "--enable-native-access=ALL-UNNAMED" --dest dist

echo "2/3 Creating the app image (bundled Java runtime)..."
TYPE="${PKG_TYPE:-}"
jpackage --type app-image "$@"
OS="$(uname -s | tr 'A-Z' 'a-z')"
APP=dist/gainsay
[ -d "$APP" ] || APP=dist/gainsay.app
cp LICENSE NOTICE README.md SECURITY.md "$APP/"
tar -C dist -czf "dist/gainsay-$VERSION-$OS-$(uname -m).tar.gz" "$(basename "$APP")"

if [ -n "$TYPE" ]; then
  echo "3/3 Creating a $TYPE package..."
  jpackage --type "$TYPE" "$@"
else
  echo "3/3 Skipping native package (set PKG_TYPE=deb|rpm|pkg)."
fi

# Checksums for every published file, in sha256sum format.
(cd dist && for f in *.tar.gz *.deb *.rpm *.pkg; do
  [ -f "$f" ] || continue
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
done) > "dist/SHA256SUMS-$OS.txt"

echo
echo "Done. Run: dist/gainsay/bin/gainsay audit   (macOS: dist/gainsay.app/Contents/MacOS/gainsay)"
