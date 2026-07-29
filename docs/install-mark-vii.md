# Install PineAI 0.6.3 on a WiFi Pineapple Mark VII

## Before installation

PineAI `0.6.3` reads saved Recon scans and does not start, stop, or reconfigure
the radios. Back up any existing PineAI data before replacing an earlier
module version:

```sh
if [ -d /pineapple/modules/PineAI ]; then
    cp -a /pineapple/modules/PineAI /root/PineAI.module.backup-before-0.6.1
fi
if [ -d /root/.PineAI ]; then
    cp -a /root/.PineAI /root/.PineAI.backup-before-0.6.1
fi
```

The old `/root/.PineAI/engagements/` directory is left untouched but is not
read by Baseline & Drift.

## Verify the download

Download both release assets into the same directory:

```text
PineAI-0.6.3.tar.gz
PineAI-0.6.3.tar.gz.sha256
```

Verify them before upload:

```sh
sha256sum -c PineAI-0.6.3.tar.gz.sha256
```

The expected result is:

```text
PineAI-0.6.3.tar.gz: OK
```

## Install

Upload `PineAI-0.6.3.tar.gz` with the WiFi Pineapple module installation
interface. For development installation, extract or copy the packaged
`PineAI/` directory to:

```text
/pineapple/modules/PineAI/
```

The package already records root ownership and these runtime modes:

- directories `0755` inside the module installation;
- `module.py` and `assets/pineai_cli.py` executable;
- other packaged files `0644`;
- runtime assessment directories `0700`;
- runtime JSON, JSONL, key, and configuration files `0600`.

## First run

1. Open PineAI and confirm the toolbar reports backend `0.6.3`.
2. Leave OpenAI unconfigured; the complete assurance workflow must initialize
   as **Offline ready**.
3. Open **Recon**, refresh saved scans, and load one existing scan.
4. Open **Assessments** and create one record for the location.
5. Resolve the scan, create an immutable baseline version, and activate it
   with the separate confirmation.
6. Load a later saved scan, preview comparability, and save the analysis.
7. Review findings and export both JSON and standalone HTML reports.

Only configure an OpenAI API key if optional explanatory prose is wanted.
SSID sharing remains disabled by default, and **Privacy preview** shows the
exact provider payload before a request.

## Device verification

On the Pineapple, confirm:

```sh
python3 --version
find /root/.PineAI/assessments -maxdepth 2 -printf '%m %p\n'
```

Assessment directories should be `700` and persisted files `600`. A generated
report is returned to the browser for download and is not stored by PineAI.

If the module does not start, inspect the Pineapple module/backend log and run:

```sh
/pineapple/modules/PineAI/assets/pineai_cli.py status
```

The command returns only safe configuration state and never the API key.

The `v0.6.3` GitHub release remains marked as a pre-release until these
physical checks are completed and recorded. Automated verification does not
replace this device smoke test.
