#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs Plugin Check (PCP) on the distributable build with the flags used by
# the WordPress.org review, inside WordPress Playground (no local server).
set -euo pipefail
cd "$(dirname "$0")/.."
bin/build-zip.sh >/dev/null
npx wp-playground-cli php \
  --blueprint=tests/pcp-blueprint.json \
  --mount="$PWD/build/site-portrait:/wordpress/wp-content/plugins/site-portrait" \
  --quiet \
  -- /tmp/wp-cli.phar plugin check site-portrait \
  --categories=plugin_repo --format=json \
  --error-severity=7 --warning-severity=6 \
  --include-low-severity-errors --exclude-checks=prefixing
