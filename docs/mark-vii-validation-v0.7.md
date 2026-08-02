# PineAssure v0.7 Mark VII validation procedure

## Status and safety boundary

This procedure is the release-candidate hardware gate. A development package
was exercised on a physical Mark VII on 2026-08-02, but the exact artifact
produced from the eventual green CI commit must repeat the procedure before the
release is considered hardware-validated.

The procedure is passive with respect to Wi-Fi. It must not start or stop
Recon, configure a radio, capture traffic, probe clients, deauthenticate,
modify firmware, or reboot the device. A real power-loss test is a separately
approved physical action and uses only disposable validation state.

Never place a password, API key, SSID, BSSID, raw Recon payload, or production
state content in a command line, evidence file, GitHub comment, or release note.

## Development-candidate evidence (2026-08-02)

This evidence closes the early device-compatibility gate; it is not a release
asset attestation because the package was built from an uncommitted development
worktree.

- Device: WiFi Pineapple Mark VII, OpenWrt 21.02.1, kernel 5.4.154,
  Python 3.9.7.
- Initial resources: 253,408 KiB RAM, no swap, and approximately 118 MiB free
  in `/tmp` during validation.
- Package: `PineAI-0.7.0.tar.gz`, SHA-256
  `03771364154a29df3ba11422f6e35121f1ac081c51658bbb9a9f80914e871132`.
- Disposable package smoke: 56 actions present, offline mode confirmed,
  Recon control disabled, peak process RSS 24,668 KiB.
- Storage integrity: native AuditRun lifecycle, JSON/HTML reports,
  action-specific missing/corrupt manifest errors, private permissions, backup
  verification, and staging restore passed in disposable `/tmp` state.
- Transaction recovery: a prepared journal recovered both targets atomically
  with no transaction residue.
- Adapter workload: every one of seven read-only actions completed 100/100;
  observed peak RSS was 21.50 MiB.
- Realistic RepeatableAuditStore workload: eight measurement points, 16
  snapshots, eight comparisons, and 37 events completed with zero harness
  violations; observed peak RSS was 21.71 MiB and persisted state was 268,291
  logical bytes across 59 files. These are device observations, not calibrated
  product performance claims.
- Staged module check: the installed frontend bundle matched the package SHA,
  all 56 actions and health loaded from the staged module, CLI status and
  capabilities worked in disposable state, and the original module was
  restored atomically. The pre-test module and state backup checksums still
  verified after rollback.
- Safety: production `/root/.PineAI` content was not read or changed, and no
  radio, Recon, capture, deauthentication, firmware, or reboot action occurred.

The exact frozen CI package, authenticated saved-scan read, final staged
installation, and final rollback remain release gates.

## Frozen CI artifact evidence (2026-08-02)

The PR head `e64cdf5039f3df1ae1b72e83a1fe00cd9550f408` passed both
the pull-request run `30749608964` and push run `30749606966`. The package was
downloaded with GitHub CLI from the pull-request run rather than rebuilt for
device validation.

- Archive SHA-256:
  `02af848235cb25138e48d0d1eccaaeed5b148a5126bb3e9abced99ce15206c15`.
- CycloneDX SHA-256:
  `492870ca77286cc4bfa453536f889f32a529fa2ed1c117d8d723a2f1e800403b`.
- Windows Python 3.8.20, WSL Python 3.13, the archive sidecar, and the Mark VII
  independently accepted the same 28-file, three-directory archive.
- Package smoke passed with 56 actions, Python 3.9.7, offline mode,
  Recon control disabled, and 24,708 KiB peak RSS.
- Prepared-journal recovery published both targets atomically and left no
  transaction residue.
- The storage-integrity probe passed AuditRun lifecycle, JSON/HTML report,
  missing/corrupt manifest, private-permission, backup verification, and
  restore-staging checks with zero violations.
- The 20- and 100-iteration adapter runs completed 140 and 700 read-only action
  calls with zero failures. Peak RSS was 21.37 and 21.28 MiB respectively.
- The realistic store workload completed in 204,441.456 ms, reopened in
  7,666.158 ms, reached 22.09 MiB peak RSS, and persisted 268,291 logical
  bytes across 59 files. It produced 16 snapshots, eight comparisons, and 37
  events with zero harness violations.
- The staged module served the exact 562,703-byte CI frontend bundle with
  SHA-256
  `9b199cd0427cc46f429e053522e43b846597e2d919b3b17b91c8d258555ef1e8`.
  Installed-path import/health found 56 actions and peaked at 24,072 KiB; CLI
  status and capabilities also passed in disposable state.
- A new pre-final module/state backup was written to
  `/root/pineai-backups/20260802T133200Z-final-v070/`. Both backup members
  verified before and after rollback. The original module bundle and backend
  hashes were restored and port 1471 again served the original bundle.
- No active radio, Recon, capture, deauthentication, firmware, or reboot action
  occurred, and production assessment content was not read or mutated.

Before the final staged test, the original module directory was unexpectedly
absent even though its route had been verified after the earlier development
rollback. It was reconstructed from the verified initial backup, its original
file hashes and HTTP route were revalidated, and the final install/rollback then
passed. The cause of that one disappearance was not established and must remain
visible in review evidence.

The authenticated saved-scan read is still open. The endpoint returned HTTP
401 without a Hak5 session, as expected; no password or session secret was put
on a command line to bypass that boundary. Stable release approval therefore
remains blocked even though the exact CI artifact passed the other passive
hardware gates.

## Release inputs

Copy only these files to a private validation directory on the device:

- `PineAI-0.7.0.tar.gz`;
- `PineAI-0.7.0.tar.gz.sha256`;
- the files under `scripts/markvii/`.

The archive and checksum must be byte-identical to the release candidate
assets produced by the green GitHub Actions run. Do not rebuild on the device.

All first-stage work uses `/tmp/pineassure-v070-validation/`. The production
module and `/root/.PineAI` remain untouched.

## 1. Read-only device baseline

Record only non-secret facts:

```sh
uname -a
cat /etc/openwrt_release
python3 --version
grep -E '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
df -Pk / /tmp /pineapple 2>/dev/null
```

Do not collect environment variables, process command lines, configuration
files, browser sessions, OpenAI keys, Recon data, or `/root/.PineAI` content.

## 2. Disposable package smoke

From the copied harness directory:

```sh
umask 077
sh markvii-smoke-test.sh \
  /tmp/pineassure-v070-validation/PineAI-0.7.0.tar.gz \
  /tmp/pineassure-v070-validation/PineAI-0.7.0.tar.gz.sha256 \
  /tmp/pineassure-v070-validation/smoke.json
```

The harness verifies the SHA-256, archive bounds, root, paths, member types,
modes, imports, health action, offline flag, Recon-control flag, and required
v0.7 actions. It extracts only into a temporary directory and sets
`PINEAI_CONFIG_DIR` to disposable temporary state.

The emitted `hardware_validated` value deliberately remains `false`. A reviewer
must combine the evidence with the rest of this procedure before changing the
release status.

## 3. Bounded import and health soak

```sh
sh markvii-soak-test.sh \
  /tmp/pineassure-v070-validation/PineAI-0.7.0.tar.gz \
  /tmp/pineassure-v070-validation/PineAI-0.7.0.tar.gz.sha256 \
  /tmp/pineassure-v070-validation/soak.json
```

This performs 100 health calls in one process and records before/after and peak
RSS. It does not validate the full resolve/compare workload. That workload must
be run separately with sanitized saved-scan fixtures and the public action
integration harness before declaring the memory budget proven.

For a passive watch of an already identified PineAssure process:

```sh
python3 -B markvii_resource_watch.py \
  --pid PID \
  --duration-seconds 300 \
  --interval-seconds 5 \
  --output /tmp/pineassure-v070-validation/resource.json
```

The watcher reads `/proc`; it never signals or controls the target process.

## 4. Disposable transaction recovery

Extract the verified package into the validation directory using the same
safe, staged method used by the smoke harness. Choose a new absolute directory
whose path does not contain `.PineAI`.

Prepare a durable journal and stop at the prepared boundary:

```sh
python3 -B markvii_recovery_probe.py prepare \
  --package-root /tmp/pineassure-v070-validation/extracted/PineAI \
  --state-dir /root/PineAssure-v070-disposable-recovery
```

Without an approved physical interruption, immediately verify recovery:

```sh
python3 -B markvii_recovery_probe.py verify \
  --package-root /tmp/pineassure-v070-validation/extracted/PineAI \
  --state-dir /root/PineAssure-v070-disposable-recovery
```

For an approved power-loss test, stop after `prepare`, physically interrupt and
restore power, then run `verify`. The harness refuses any state path containing
`.PineAI`, uses a disposable marker, and never touches production assessment
data. It does not power-cycle or reboot the device itself.

Keep the disposable recovery directory until the result is reviewed. Remove it
only with a separate, explicit operator decision after resolving and verifying
its absolute path.

## 5. Staged installation and rollback

Only after the disposable checks and green CI:

1. Create new timestamped backups of the installed module and `/root/.PineAI`.
2. Verify backup size and SHA-256 without printing its contents.
3. Stage the new module in a sibling directory.
4. Verify imports, files, modes, ownership, and module version in staging.
5. Replace only the module directory atomically; do not replace production state.
6. Verify health, existing v0.6 data reads, the v0.7 UI, and saved-scan listing.
7. On failure, restore only the module backup. Preserve production state and
   every backup for investigation.

Do not delete old backups during the release validation.

## 6. Acceptance record

The final hardware record must identify:

- device model and firmware;
- archive name and SHA-256;
- source commit and CI run;
- Python version and initial free RAM/disk;
- smoke, soak, resource, recovery, install, and rollback results;
- peak RSS, lowest MemAvailable, latency summary, and state growth;
- every limitation or skipped gate;
- confirmation that no active radio operation occurred.

Any missing correctness, recovery, package, resource, or rollback evidence keeps
stable `v0.7.0` at **NO-GO**. A successful automated-only result is sufficient
only for a prerelease labelled `hardware validation pending`.
