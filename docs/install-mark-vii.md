# Install PineAssure 0.7.0 on a WiFi Pineapple Mark VII

PineAssure is the product name. The Hak5 module ID, package root, CLI, and
on-device state paths remain `PineAI`, `PineAI/`, `pineai`, and
`/root/.PineAI` for compatibility.

## Safety boundary

PineAssure `0.7.0` reads existing saved Recon observations. It does not start,
stop, or reconfigure radios. The release-candidate package is workstation- and
CI-verified, but physical Mark VII validation of the exact artifact remains a
release gate. Do not describe it as hardware-validated until the procedure in
[mark-vii-validation-v0.7.md](mark-vii-validation-v0.7.md) passes.

## Back up the installed module and state

Create new timestamped backups before replacing an earlier version. Never
overwrite or remove an older backup:

```sh
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -d /pineapple/modules/PineAI ]; then
    cp -a /pineapple/modules/PineAI \
      "/root/PineAI.module.backup-before-0.7.0-${stamp}"
fi
if [ -d /root/.PineAI ]; then
    cp -a /root/.PineAI "/root/.PineAI.backup-before-0.7.0-${stamp}"
fi
```

The legacy `/root/.PineAI/engagements/` directory is left untouched and is not
used by PineAssure. Repeatable Field Audit state stays under each assessment.
The supported `pineai backup create` continuity archive includes the split
`assessments/<assessment_id>/audit_runs/<audit_run_id>/manifest.json` and
`measurements/<measurement_id>.json` paths; verify the archive before relying
on it for a staged restore.

## Verify the release assets

Download both exact release-candidate assets into the same directory:

```text
PineAI-0.7.0.tar.gz
PineAI-0.7.0.tar.gz.sha256
```

Verify the archive before upload:

```sh
sha256sum -c PineAI-0.7.0.tar.gz.sha256
```

The expected result is:

```text
PineAI-0.7.0.tar.gz: OK
```

## Install

Upload `PineAI-0.7.0.tar.gz` through the WiFi Pineapple module installation
interface. For a development installation, extract or copy the packaged
`PineAI/` directory to:

```text
/pineapple/modules/PineAI/
```

The release package records root ownership and the runtime modes required by
the Hak5 module:

- directories inside the module installation: `0755`;
- `module.py` and `assets/pineai_cli.py`: executable;
- other packaged files: `0644`;
- private runtime directories: `0700`;
- runtime JSON, JSONL, key, and configuration files: `0600`.

Installation must not replace `/root/.PineAI` or its identity key.

## First-run checks

1. Open PineAssure and confirm backend version `0.7.0`; the technical module ID
   remains `PineAI`.
2. Leave OpenAI unconfigured and confirm the deterministic workflow reports
   **Offline ready**.
3. Open **Recon**, list saved scans, and load one existing observation. Do not
   start a scan as part of this check.
4. Create or select an assessment and verify its existing baseline,
   MeasurementProfile, and AssuranceProfile data remains readable.
5. Create a location-only MeasurementPoint using `location_label` and optional
   operator guidance.
6. Create a draft AuditRun with pinned point, profile, baseline, and policy
   revisions. Verify starting the run requires explicit operator action.
7. Reopen the module and confirm the same durable run and measurement state is
   available. Do not resolve a live customer scan during an installation-only
   check.
8. Cancel the disposable run or complete a controlled offline fixture run, then
   export `local_full` and `share_safe` reports only from terminal state.

OpenAI is optional explanatory prose. It is not required for comparison,
finding lifecycle, evidence, AuditRun state, or deterministic reports. SSID
sharing stays disabled by default.

## Safe device inspection

The physical validation procedure uses a disposable state directory first. A
minimal read-only inspection is:

```sh
python3 --version
df -h /root /tmp
free -m
find /root/.PineAI/assessments -maxdepth 3 -printf '%m %p\n'
```

Private directories should be `700` and persisted private files `600`. Do not
print secrets, raw Recon JSON, SSIDs, or BSSIDs into validation logs.

If the module does not start, inspect the module/backend log and run:

```sh
/pineapple/modules/PineAI/assets/pineai_cli.py status
```

The command returns safe configuration state only and never the API key.

## Release status

Automated Windows, WSL, Python, Angular, schema, package, and security checks do
not establish Mark VII performance or compatibility. Keep `v0.7.0` as a
pre-release until the exact published archive and checksum pass the documented
physical smoke and bounded soak tests. Never rebuild or replace the asset
during that validation; publish a new version if a defect requires a change.
