#!/bin/bash

set -euo pipefail

PACKAGE_PATH=${1:-}
if [[ -z "$PACKAGE_PATH" || ! -f "$PACKAGE_PATH" ]]; then
    echo "Usage: $0 PineAI-X.Y.Z.tar.gz" >&2
    exit 2
fi

SOURCE_VERSION=$(
    python3 -c \
        'import json; print(json.load(open("projects/PineAI/src/module.json", encoding="utf-8"))["version"])'
)
EXPECTED_NAME="PineAI-${SOURCE_VERSION}.tar.gz"
if [[ $(basename "$PACKAGE_PATH") != "$EXPECTED_NAME" ]]; then
    echo "Package name does not match module.json version $SOURCE_VERSION" >&2
    exit 1
fi

FIRST_ENTRY=$(tar -tzf "$PACKAGE_PATH" | sed -n '1p')
if [[ "$FIRST_ENTRY" != "PineAI/" ]]; then
    echo "Package must start with the PineAI/ directory" >&2
    exit 1
fi

while IFS= read -r entry; do
    case "$entry" in
        /*|..|../*|*/../*)
            echo "Unsafe archive path: $entry" >&2
            exit 1
            ;;
        PineAI|PineAI/*)
            ;;
        *)
            echo "Archive entry is outside PineAI/: $entry" >&2
            exit 1
            ;;
    esac
done < <(tar -tzf "$PACKAGE_PATH")

if tar --numeric-owner -tvzf "$PACKAGE_PATH" |
    awk 'substr($1,1,1) == "l" || substr($1,1,1) == "h" { found=1 } END { exit !found }'
then
    echo "Package contains a symbolic or hard link" >&2
    exit 1
fi

if tar --numeric-owner -tvzf "$PACKAGE_PATH" |
    awk '$2 != "0/0" { found=1 } END { exit !found }'
then
    echo "Package contains a non-root owner or group" >&2
    exit 1
fi

if tar --numeric-owner -tvzf "$PACKAGE_PATH" |
    awk '
        substr($1,1,1) == "d" && $1 != "drwxr-xr-x" { found=1 }
        substr($1,1,1) == "-" &&
            ($6 == "PineAI/module.py" ||
             $6 == "PineAI/assets/pineai_cli.py") &&
            $1 != "-rwxr-xr-x" { found=1 }
        substr($1,1,1) == "-" &&
            $6 != "PineAI/module.py" &&
            $6 != "PineAI/assets/pineai_cli.py" &&
            $1 != "-rw-r--r--" { found=1 }
        END { exit !found }
    '
then
    echo "Package contains an unexpected file mode" >&2
    exit 1
fi

REQUIRED_FILES=(
    PineAI/PineAI.umd.js
    PineAI/module.py
    PineAI/module.json
    PineAI/module.svg
    PineAI/assets/pineai_cli.py
    PineAI/assets/pineai_backend/assurance.py
    PineAI/assets/pineai_backend/assurance_service.py
    PineAI/assets/pineai_backend/assessment_store.py
    PineAI/assets/pineai_backend/assurance_profiles.py
    PineAI/assets/pineai_backend/backup.py
    PineAI/assets/pineai_backend/consensus.py
    PineAI/assets/pineai_backend/customer_analysis.py
    PineAI/assets/pineai_backend/customer_store.py
    PineAI/assets/pineai_backend/platform.py
    PineAI/assets/pineai_backend/storage_transaction.py
    PineAI/assets/pineai_backend/openai_client.py
    PineAI/assets/pineai_backend/reports.py
)
for required in "${REQUIRED_FILES[@]}"; do
    tar -tzf "$PACKAGE_PATH" "$required" > /dev/null
done

if tar -tzf "$PACKAGE_PATH" |
    awk '
        /(^|\/)(__pycache__|engagement_store\.py|advisor\.py|adaptive_recon\.py|profiler\.py)(\/|$)/ { found=1 }
        /\.pyc$/ || /\.map$/ { found=1 }
        END { exit !found }
    '
then
    echo "Package contains a forbidden legacy, cache, bytecode, or source-map entry" >&2
    exit 1
fi

EXTRACT_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/pineai-verify.XXXXXX")
cleanup() {
    rm -rf -- "$EXTRACT_DIRECTORY"
}
trap cleanup EXIT

tar -xzf "$PACKAGE_PATH" -C "$EXTRACT_DIRECTORY"
PACKAGE_VERSION=$(
    python3 -c \
        'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' \
        "$EXTRACT_DIRECTORY/PineAI/module.json"
)
if [[ "$PACKAGE_VERSION" != "$SOURCE_VERSION" ]]; then
    echo "Embedded module.json version does not match source" >&2
    exit 1
fi

python3 -m compileall -q \
    "$EXTRACT_DIRECTORY/PineAI/module.py" \
    "$EXTRACT_DIRECTORY/PineAI/assets"

echo "Verified $EXPECTED_NAME"
