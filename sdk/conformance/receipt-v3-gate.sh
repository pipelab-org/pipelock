#!/usr/bin/env bash
# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
exec python3 "$(dirname "${BASH_SOURCE[0]}")/receipt_v3_gate.py" "$@"
