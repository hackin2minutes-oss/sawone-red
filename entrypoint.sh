#!/bin/sh
# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
# Entrypoint for the Sawone Red GitHub Action. Inputs arrive as INPUT_* variables.
set -eu

CONFIG="${INPUT_CONFIG:-sawone-red.yaml}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
SARIF_OUTPUT="${INPUT_SARIF_OUTPUT:-sawone-red.sarif}"
REPORT_DIR="${INPUT_REPORT_DIR:-sawone-red-reports}"

exec sawone-red run \
  --config "$CONFIG" \
  --fail-on "$FAIL_ON" \
  --output-dir "$REPORT_DIR" \
  --sarif "$SARIF_OUTPUT"
