#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the distributable plugin (committed files minus export-ignore entries)
# into build/ctrlweb-site-portrait and build/ctrlweb-site-portrait.zip.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build && mkdir -p build
git archive --format=tar --prefix=ctrlweb-site-portrait/ HEAD | tar -x -C build
(cd build && zip -qr ctrlweb-site-portrait.zip ctrlweb-site-portrait)
echo "build/ctrlweb-site-portrait.zip"
