#!/bin/sh

set -eu
umask 077

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 PACKAGE SHA256_FILE OUTPUT_JSON" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -B "$script_dir/markvii_package_smoke.py" \
    --archive "$1" \
    --sha256-file "$2" \
    --output "$3" \
    --iterations 100
