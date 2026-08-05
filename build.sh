#!/usr/bin/env bash

set -euo pipefail

readonly MODULENAME="PineAI"
readonly PROJECT_ROOT="projects/$MODULENAME"
readonly PACKAGE_TOOL="scripts/package_tool.py"
readonly WORKSPACE_ROOT="$(pwd -P)"

resolved_path() {
    python3 - "$1" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).resolve(strict=False))
PY
}

remove_build_stage() {
    local target=$1
    local temp_parent
    local resolved_target

    temp_parent=$(resolved_path "${TMPDIR:-/tmp}")
    resolved_target=$(resolved_path "$target")
    if [[ "$(dirname "$resolved_target")" != "$temp_parent" ]] ||
       [[ "$(basename "$resolved_target")" != pineai-build.* ]]; then
        echo "[!] Refusing to remove an unexpected build stage." >&2
        exit 1
    fi
    rm -rf -- "$resolved_target"
}

remove_runtime_dist() {
    local expected
    local resolved_target

    expected="$WORKSPACE_ROOT/dist/$MODULENAME"
    resolved_target=$(resolved_path "dist/$MODULENAME")
    if [[ "$resolved_target" != "$expected" ]]; then
        echo "[!] Refusing to remove an unexpected runtime target." >&2
        exit 1
    fi
    rm -rf -- "$resolved_target"
}

prepare_workspace() {
    if [[ -x "./node_modules/.bin/ng" ]]; then
        return
    fi
    if ! command -v npm > /dev/null 2>&1; then
        echo "[!] npm is required to prepare the Angular workspace." >&2
        exit 1
    fi
    echo "[*] Preparing the Angular workspace with npm ci."
    npm ci
}

build_module() {
    local bundle_input
    local stage_root

    stage_root=$(mktemp -d "${TMPDIR:-/tmp}/pineai-build.XXXXXX")
    cleanup_build_stage() {
        remove_build_stage "$stage_root"
    }
    trap cleanup_build_stage RETURN

    if [[ ${PINEAI_SKIP_ANGULAR_BUILD:-0} == "1" ]]; then
        bundle_input="dist/$MODULENAME/PineAI.umd.js"
        if [[ ! -f "$bundle_input" ]]; then
            echo "[!] A prebuilt PineAI.umd.js was not found." >&2
            exit 1
        fi
        cp -- "$bundle_input" "$stage_root/PineAI.umd.js"
        bundle_input="$stage_root/PineAI.umd.js"
        echo "[*] Using the existing production bundle."
    else
        prepare_workspace
        local legacy_opt=""
        if node --openssl-legacy-provider -v > /dev/null 2>&1; then
            legacy_opt="--openssl-legacy-provider"
        fi
        NODE_OPTIONS="$legacy_opt ${NODE_OPTIONS:-}" \
            ./node_modules/.bin/ng build --prod
        bundle_input="dist/$MODULENAME/bundles/PineAI.umd.js"
        if [[ ! -f "$bundle_input" ]]; then
            echo "[!] Angular build did not produce PineAI.umd.js." >&2
            exit 1
        fi
        cp -- "$bundle_input" "$stage_root/PineAI.umd.js"
        bundle_input="$stage_root/PineAI.umd.js"
        echo "[*] Angular production build succeeded."
    fi

    python3 "$PACKAGE_TOOL" stage \
        --bundle "$bundle_input" \
        --output "$stage_root/runtime"

    remove_runtime_dist
    mkdir -p dist
    mv -- "$stage_root/runtime" "dist/$MODULENAME"
    echo "[*] Runtime staging matched scripts/package-manifest.json."

    cleanup_build_stage
    trap - RETURN
}

module_version() {
    python3 - <<'PY'
import json
import re
from pathlib import Path

value = json.loads(
    Path("projects/PineAI/src/module.json").read_text(encoding="utf-8")
).get("version")
if not isinstance(value, str) or not re.fullmatch(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
    value,
):
    raise SystemExit("module.json version is not strict SemVer")
print(value)
PY
}

package_module() {
    local version
    local package_path
    version=$(module_version)
    package_path="$PWD/$MODULENAME-$version.tar.gz"
    rm -f -- "$package_path"
    echo "[*] Packaging $MODULENAME version $version."
    python3 "$PACKAGE_TOOL" create \
        --dist "dist/$MODULENAME" \
        --output "$package_path"
}

copy_to_device() {
    echo "[*] Copying the staged module to WiFi Pineapple via SCP."
    scp -r "dist/$MODULENAME" root@172.16.42.1:/pineapple/modules
}

main() {
    build_module
    case "${1:-}" in
        "")
            ;;
        package)
            package_module
            ;;
        copy)
            copy_to_device
            ;;
        *)
            echo "Usage: ./build.sh [package|copy]" >&2
            exit 2
            ;;
    esac
    echo "[*] Success."
}

main "$@"
