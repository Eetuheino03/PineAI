#!/bin/bash

set -e

MODULENAME=$(basename "$PWD")

check_workspace() {
    if [[ ! -d "node_modules" ]]; then
        while true; do
            read -r -p "[!!] The Angular workspace has not been prepared. Would you like to do it now? [Y/n] " yn
            case $yn in
                [Yy]* ) prepare_workspace; break;;
                [Nn]* ) exit 1;;
                * ) prepare_workspace; break;;
            esac
        done
    fi
}

prepare_workspace() {
    echo "[*] Preparing the Angular workspace."

    if ! command -v npm &> /dev/null; then
        echo "[!] NPM does not appear to be installed on this system. Failed to create workspace."
        exit 1
    fi

    if ! npm install &> /dev/null; then
        echo "[!] Failed to prepare workspace. Run npm install to see why."
        exit 1
    fi

    echo "[*] Prepared the Angular workspace successfully."
}

build_module() {
    if [[ ${PINEAI_SKIP_ANGULAR_BUILD:-0} == "1" ]]; then
        if [[ ! -d "dist/$MODULENAME/bundles" ]]; then
            echo "[!] Prebuilt Angular bundles were not found in dist/$MODULENAME/bundles."
            exit 1
        fi
        echo "[*] Using prebuilt Angular bundles"
    else
        if ! "$PWD/node_modules/.bin/ng" build --prod > /dev/null 2>&1; then
            echo "[!] Angular Build Failed: Run './node_modules/.bin/ng build --prod' to inspect the error."
            exit 1
        fi
        echo "[*] Angular Build Succeeded"
    fi

    # Step 2: Copy the required files to the build output
    cp -r "projects/$MODULENAME/src/module.svg" "dist/$MODULENAME/bundles/"
    cp -r "projects/$MODULENAME/src/module.json" "dist/$MODULENAME/bundles/"
    cp -r "projects/$MODULENAME/src/module.py" "dist/$MODULENAME/bundles/"
    if [[ -f "projects/$MODULENAME/src/module.php" ]]; then
        cp -r "projects/$MODULENAME/src/module.php" "dist/$MODULENAME/bundles/"
    fi
    cp -r "projects/$MODULENAME/src/assets/" "dist/$MODULENAME/bundles/"

    # Step 3: Clean up
    rm -f "dist/$MODULENAME/bundles/"*.map
    rm -f "dist/$MODULENAME/bundles/"*.min*
    find "dist/$MODULENAME/bundles" -type d -name "__pycache__" -prune -exec rm -rf {} +
    find "dist/$MODULENAME/bundles" -type f -name "*.pyc" -delete
    rm -rf "bundletmp"
    mv "dist/$MODULENAME/bundles/" "bundletmp"
    rm -rf "dist/$MODULENAME"
    mkdir -p "dist/$MODULENAME"
    mv "bundletmp/"* "dist/$MODULENAME/"
    rm -rf "bundletmp"
}

package() {
    VERS=$(grep '"version"' "dist/$MODULENAME/module.json" | awk '{split($0, a, ": "); gsub("\"", "", a[2]); gsub(",", "", a[2]); print a[2]}')
    PACKAGE_PATH="$PWD/$MODULENAME-$VERS.tar.gz"
    PACKAGE_STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pineai-package.XXXXXX")

    cleanup_package_stage() {
        rm -rf -- "$PACKAGE_STAGE"
    }
    trap cleanup_package_stage RETURN

    rm -f "$PACKAGE_PATH"
    echo "[*] Packaging $MODULENAME (Version $VERS)"
    mkdir -p "$PACKAGE_STAGE/$MODULENAME"
    cp -R "dist/$MODULENAME/." "$PACKAGE_STAGE/$MODULENAME/"

    find "$PACKAGE_STAGE/$MODULENAME" -type d -exec chmod 755 {} +
    find "$PACKAGE_STAGE/$MODULENAME" -type f -exec chmod 644 {} +
    chmod 755 "$PACKAGE_STAGE/$MODULENAME/module.py"
    if [[ -f "$PACKAGE_STAGE/$MODULENAME/assets/pineai_cli.py" ]]; then
        chmod 755 "$PACKAGE_STAGE/$MODULENAME/assets/pineai_cli.py"
    fi

    tar --owner=0 --group=0 --numeric-owner \
        -czf "$PACKAGE_PATH" -C "$PACKAGE_STAGE" "$MODULENAME"

    cleanup_package_stage
    trap - RETURN
}

copy_to_device() {
    echo "[*] Copying module to WiFi Pineapple via SCP"
    scp -r "dist/$MODULENAME" root@172.16.42.1:/pineapple/modules
}

main() {
    check_workspace
    build_module

    if [[ $1 == "package" ]]; then
        package
    elif [[ $1 == "copy" ]]; then
        copy_to_device
    fi

    echo "[*] Success!"
}

main "$@"
