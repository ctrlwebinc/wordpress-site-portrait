#!/usr/bin/env bash
# Builds the distributable plugin (committed files minus export-ignore entries)
# into build/site-portrait and build/site-portrait.zip.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build && mkdir -p build
git archive --format=tar --prefix=site-portrait/ HEAD | tar -x -C build
(cd build && zip -qr site-portrait.zip site-portrait)
echo "build/site-portrait.zip"
