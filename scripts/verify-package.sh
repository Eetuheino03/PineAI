#!/usr/bin/env bash

set -euo pipefail

package_path=${1:-}
bundle_path=${2:-}
if [[ -z "$package_path" || ! -f "$package_path" ]]; then
    echo "Usage: $0 PineAI-X.Y.Z.tar.gz [PineAI.umd.js]" >&2
    exit 2
fi

arguments=(verify --archive "$package_path")
if [[ -n "$bundle_path" ]]; then
    if [[ ! -f "$bundle_path" ]]; then
        echo "Expected bundle is unavailable: $bundle_path" >&2
        exit 2
    fi
    arguments+=(--bundle "$bundle_path")
fi
python3 scripts/package_tool.py "${arguments[@]}"
