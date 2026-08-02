# PineAI implementation continuation

This file is the hand-off checkpoint for Customer Audit Foundation. Update it
whenever a phase is completed or work stops.

## Starting point

- Public baseline commit: `705b960` (`v0.5.0`)
- Released Baseline & Drift commit: `28f0c4f` (`v0.6.0`)
- v0.6.1 review baseline: `fa8dc40`
- Release-hardening branch: `fix/v0.6.1-release`
- Target release: `v0.6.1` pre-release pending physical validation
- Last verified Python result before the rewrite: 74 tests passed in WSL

## Pre-existing uncommitted work

The working tree already contained an interrupted v0.5.1 repair:

- lazy backend imports to reduce Mark VII module cold-start time;
- safer package ownership and file modes;
- related adapter, workflow, version, and documentation edits;
- an untested initial `assurance.py` draft;
- line-ending noise in several tracked text files.

These changes must not be discarded wholesale. Retain the cold-start and
packaging fixes, review the assurance draft against the v0.6 contracts, and
remove accidental CRLF-only changes before implementation commits.

## Locked product decisions

- One assessment represents one wireless environment or location.
- Baseline versions are immutable and activated only by explicit confirmation.
- A comparable clean scan resolves open or acknowledged findings.
- A recurring condition reopens the same stable finding ID.
- Real SSIDs and BSSIDs may be stored locally; cloud payloads are
  pseudonymized and SSID sharing remains opt-in.
- The old profiler, engagement, attack-path, and adaptive-Recon public
  interfaces are removed rather than migrated.
- Old on-device engagement files remain untouched and ignored.
- v0.6 does not start or stop Recon scans.
- Optional AI explanations and report prose are included, but are never
  authoritative.

## Implementation phases

1. Product-direction checkpoint.
2. Deterministic assurance core and assessment storage.
3. Module actions, optional AI analysis, reports, and CLI.
4. Angular Baseline & Drift workflow.
5. Schemas, documentation, tests, package validation, device smoke test.
6. GitHub Actions, merge, tag, and release assets.

## Current state

- Phase: v0.6.1 pre-release published; physical smoke test pending
- Direction checkpoint commit: `201b291`
- Baseline & Drift pull request: `#16`, merged into `main` as `255a8db`
- v0.6.1 release-hardening pull request: `#24`, merged into `main` as
  `192a97b`
- Release tag: `v0.6.1`, pointing to `192a97b`
- Backend: deterministic resolver, assessment storage, comparability, eight
  finding rules, lifecycle, optional AI explanation boundary, and reports
  implemented
- Frontend: all nine Baseline & Drift views implemented; no radio controls or
  old attack-oriented branding remain
- Contract: assurance schema `1.1` covers measurement context and
  comparability; legacy stored assurance schema `1.0` remains readable
- v0.6.1 hardening restores the pushed Python test class, derives the CI
  package version from `module.json`, unifies runtime version reporting,
  validates the full comparison contract, and scopes channel metadata to the
  selected Recon scan
- Comparability policy: explicit location, point, scan-profile, or interface
  mismatch is not comparable; an explicit radio-profile mismatch is partially
  comparable and cannot create absence findings; unknown scan, radio, or
  interface profiles are also limited to partial comparison

## Latest completed verification

- Windows Python: 71 tests passed; two POSIX-only permission checks skipped
- WSL Python: 71 tests passed with no skips, including JSON Schema and
  `0700`/`0600` permission validation
- Angular/ChromeHeadlessCI: 15 tests passed
- Angular production build: passed
- Windows and WSL source compilation: passed
- WSL `PineAI-0.6.1.tar.gz` package build: passed
- Package ownership, modes, paths, symlinks, required contents, embedded
  version, extracted Python compilation, and checksum round trip: passed
- Secret-pattern scan: no committed OpenAI-style API key found
- GitHub Actions on the final pull-request head: passed for both the push and
  pull-request events:
  - `30351733005`
  - `30351736174`
- GitHub Actions on merged `main`: passed (`30351894717`)
- GitHub Actions on tag `v0.6.1`: passed (`30352064847`)
- Published pre-release:
  `https://github.com/Eetuheino03/PineAI/releases/tag/v0.6.1`
- Published package SHA-256:
  `940a0811e68314fd374039603473af4962132a86b8384734ab08327887bd3341`
- The package and checksum were downloaded back from the release and passed
  both checksum verification and `scripts/verify-package.sh`

Physical Mark VII smoke testing is intentionally pending. No device files,
settings, radios, or stored assessment data were changed during v0.6.1
release hardening.

## v0.6.2 implementation checkpoint

- Starting commit: `b3ef98e7629dc077ab5842d4cc10d5375ffc6f6f`
- Development branch: `feature/customer-audit-foundation-v0.6.2`
- Target: `v0.6.2` pre-release
- Product position: Portable offline wireless change auditing for WiFi
  Pineapple
- Writer contracts: assessment `1.1`; snapshot/comparison `1.2`; consensus,
  measurement profile, AssuranceProfile, occurrence, and report contracts are
  independently versioned
- Physical Mark VII access is explicitly out of scope for implementation and
  release automation. Stable promotion waits for a later smoke test of the
  exact published asset.

Implementation checkpoints:

1. Direction, schemas, identity continuity, transaction recovery, and
   canonical resolver hardening.
2. Two-to-five scan strict-80 consensus baseline.
3. Immutable AssuranceProfile plus the three-level result model.
4. Point-in-time occurrences, evidence bundles, and scoped customer reports.
5. Versioned measurement profiles, capability banner, and Guided/Expert UI.
6. Root/SSH backup, lazy read adapters, documentation, packaging, CI, and
   pre-release.

The v0.6.1 single-scan baselines and comparisons stay readable. Legacy
findings are shown as read-only history and are not retrospectively
reclassified without the inventory and policy that existed at the time.

## v0.6.3 release closure checkpoint

- Target release: `v0.6.3` pre-release / release candidate
- Primary objective: Complete release closure sprint for Customer Audit Foundation (harness hardening, local adapter correctness gate, attach-only UDS socket mode, synthetic harness tests, documentation synchronization, and physical Mark VII smoke test specification).
- Product position: Portable offline wireless change auditing for WiFi Pineapple Mark VII.
- Writer contracts: assessment `1.1`; snapshot/comparison `1.2`; customer analysis `1.2`; assurance capabilities `1.2`; report fact `1.1`; consensus, measurement profile, AssuranceProfile, occurrence, and finding contracts are independently versioned.
- Physical Mark VII validation remains explicitly pending for the exact `PineAI-0.6.3.tar.gz` artifact.

## Release handoff

The verified `PineAI-0.6.3.tar.gz` artifact and its matching SHA-256 sidecar will be published as a GitHub pre-release upon completion of release verification. Keep that exact release marked as a pre-release until the exact asset passes the physical Mark VII hardware smoke test. Do not rebuild or replace the assets during hardware validation.

## Formal hardware validation gate & v0.7.0 contract checkpoint

- **Status**: Automated verification and packaging for `v0.6.3` (`1e77e18670c49c0fca3ecb809fbc08b0f6235222`) are complete.
- **Hardware Validation**: Physical Mark VII validation remains explicitly **pending**.
- **Authorization**: The user has formally authorized contract design for `v0.7.0` (Repeatable Field Audits) to proceed prior to physical device testing.
- **Isolation**: This authorization does not mark `v0.6.3` as hardware-validated. No claim of production readiness or hardware validation is added. Any `v0.6.3` hardware defect discovered later will be handled separately without silently altering the existing release candidate artifact.
- **v0.7.0 Contract Branch**: `docs/repeatable-field-audits-contract-v0.7.0`
- **Contracts Frozen**: API specification (`docs/repeatable-audits-api-v1.md`), JSON Schemas (`repeatable-audits-v1.schema.json`, `audit-run-report-v1.schema.json`), and schema test suites (`test_repeatable_audits_schema.py`, `test_audit_run_report_schema.py`).

## PR #47 workstation audit checkpoint

PR `#47` remains a draft on branch
`feature/repeatable-field-audits-store-v0.7.0`. The audit corrected the
internal persistence and recovery implementation without changing module
version `0.6.3` or exposing the frozen v0.7 module actions.

Correctness and security corrections include:

- strict AuditRun manifest validation and read-only reconstruction;
- closure reserve derived from the validated run map;
- atomic AuditRun lifecycle mutations and native artifact persistence;
- exact immutable CustomerAuditStore snapshot, comparison, occurrence, and
  digest validation;
- strict RFC 3339 timestamps and action-specific errors;
- Windows-safe file descriptors and bounded retry of an atomic replacement
  temporarily denied by a scanner or sync provider;
- safe configuration, backup, CLI, and parser error messages;
- a terminal-event byte reserve that covers the maximum accepted UTF-8
  cancellation reason;
- transient assessment lock files no longer binding an uninitialized identity;
- canonical package staging that rejects output symlinks.
- optional AI context for persisted comparisons is reconstructed from the
  immutable occurrence set; the explicitly labelled legacy fallback cannot
  select findings from another comparison.

Committed-head workstation validation:

- WSL Python 3.13: Ruff, compileall, and 218 Python tests passed;
- Windows Python 3.8.20: Ruff, compileall, and 218 Python tests passed, with
  13 intentional POSIX/socket-only skips;
- Windows Node 16.20.2 / Angular 9: lint passed, 26 ChromeHeadless tests
  passed, and the production build passed;
- Angular coverage: statements 42.35%, branches 27.57%, functions 48.18%,
  and lines 42.21%;
- no Angular e2e target exists in `angular.json`, so an e2e run is not a
  defined repository gate;
- `git diff --check`, shell syntax, secret patterns, unsafe subprocess,
  archive traversal, raw Recon, permissions, and package-path checks passed.

The non-mutating dependency audit reports 177 findings in the full legacy
Angular 9 development tree (12 low, 73 moderate, 74 high, and 18 critical).
The production tree reports three high findings in direct Angular 9
dependencies. npm only offers an incompatible major Angular upgrade, so no
automatic dependency mutation was made in this PR.

Workstation benchmark results are functional measurements, not product
performance claims:

- local adapter: 6,100 action calls completed without a failed sample;
- three 100-iteration aggregate action-median measurements had 8.05% CV;
- realistic store workload: 2,535.953 ms, 6.533 ms reopen, 38 files, and
  217,008 persisted bytes;
- frozen-limit workload: 44,880.169 ms, 363.087 ms reopen, and the exact
  64 active / 90 total measurement-point / 128 AuditRun boundaries;
- every result explicitly has `hardware_validated=false`,
  `protocol_validated=false`, and `performance_thresholds_applied=false`.

The canonical local package contains 24 runtime files and passed source,
bundle, owner, mode, path, special-file, source-map, bytecode, secret, compile,
and isolated-import checks. Its SHA-256 is
`7050a647ec6593b1e9c20b51e0315fe3af078495b7db726569f762b20463d1c3`.

No physical Mark VII, SSH, module socket, Recon radio, capture, or firmware
test was performed in this audit. Hardware validation remains a separate,
explicitly pending gate and is not required to complete the workstation-only
PR correction cycle.

## Proposed Component Architecture Checkpoint (v0.9.0 Companion)

The optional single-container **PineAI / PineAssure Companion** architecture specification is documented in [docs/companion-architecture.md](companion-architecture.md). It defines direct Mark VII HTTPS bundle pushing via outbound-only ingress tunnels without public IP, router port forwarding, or stored root SSH credentials. The design remains proposed, non-authoritative toward Mark VII local engine, and does not claim physical hardware validation.

## v0.7.0 updated product-direction checkpoint

- Working branch: `feature/repeatable-field-audits-store-v0.7.0`.
- Updated-direction reference commit: `4dc574c708956506c3324a8443c543aa9e580202`.
- Display brand: PineAssure. Technical module, package, state-directory and CLI
  compatibility identity: PineAI.
- Release target: `v0.7.0-rc.1` with `hardware validation pending`; no stable
  tag until the exact assets pass the physical Mark VII procedure.
- Frozen limits: 16 active and 32 total MeasurementPoints, 16 assignments per
  AuditRun, 32 AuditRuns per assessment, one `in_progress` run and one scan
  operation at a time.
- Public outer action schema remains `1.0`; split AuditRun manifest and
  AuditRunMeasurement records use schema `1.1`.
- MeasurementPoint is location-only. AuditRun creation atomically pins point,
  MeasurementProfile, baseline and AssuranceProfile provenance.
- The assigned baseline measurement context must identify the same physical
  MeasurementPoint. Resolution always rebuilds current measurement context
  from the immutable assignment instead of trusting the scan payload.
- Resolved v1.1 measurements pin `snapshot_record_digest` over the complete
  canonical normalized snapshot. Reopen, comparison, and report paths reject
  later content changes with `pinned_reference_mismatch`.
- New standalone baseline and analysis snapshots also carry
  `snapshot_record_digest`. Older snapshots without it remain readable and
  can be reused only when their canonical content is identical; they are
  never rewritten in place and reports label them with
  `legacy_snapshot_integrity_unbound`.
- Root/SSH continuity backups include split AuditRun manifests and measurement
  documents; backup verification and staging restore preserve them and apply
  the same path/content contract as backup creation.
- Saved-Recon `date`, `started_at`, and `completed_at` metadata is validated as
  nullable strict RFC 3339 before an immutable snapshot is built;
  `started_at <= completed_at` is enforced when both are present.
- Split manifest and measurement timestamps are revalidated for monotonic
  ordering on every reopen, and draft-run readiness rechecks every frozen
  point, profile, baseline, and assurance pin against its immutable record.
- Reports are available for terminal `completed` and `cancelled` runs and use
  only `local_full` or `share_safe`.
- Report privacy redacts structured SSID fields and SSID literals in defined
  prose without mutating schema, ID, status, time, or digest values.
- Optional provider responses are capped at 1 MiB; Customer Audit and AuditRun
  reports reject over-budget aggregates before retaining the remaining
  history or immutable artifacts.
- Backup verification validates each tar header's path, type, mode, duplicate
  identity, declared size, and cumulative payload before advancing through the
  compressed member body.

Documentation and release-tool work completed in the current worktree:

- updated product direction, architecture, API, release notes and readiness
  audit;
- v1.1 request/response and canonical report schemas with replacement contract
  tests;
- UTF-8/LF, whitespace, JSON and relative-link validation in CI;
- deterministic CycloneDX generation from the verified archive;
- passive package, resource and transaction-recovery harnesses plus a physical
  validation procedure;
- conditional dependency-risk acceptance and product-direction assessment.

Latest focused verification before the physical development-package pass:

- 25 v0.7 contract/report schema tests pass on Windows;
- 45 store/router strictness tests pass on Windows and 13 focused regression
  tests pass in WSL;
- documentation encoding, links, whitespace and JSON pass;
- Ruff passes for the changed schema tests and release scripts;
- the disposable transaction recovery prepare/verify round trip passes;
- Mark VII shell wrappers pass `bash -n`;
- no physical Mark VII validation had been performed at that checkpoint.

Physical development-package checkpoint (2026-08-02):

- a Mark VII running OpenWrt 21.02.1 and Python 3.9.7 exercised development
  package SHA-256
  `03771364154a29df3ba11422f6e35121f1ac081c51658bbb9a9f80914e871132`;
- passive package smoke, 56-action import/health, storage integrity,
  JSON/HTML report generation, backup/restore-staging, exact transaction
  recovery, 100-iteration adapter workload, and the realistic store workload
  passed in disposable `/tmp` state;
- the staged frontend bundle was served byte-identically from port 1471, CLI
  status/capabilities worked offline, and the original installed module was
  restored with its backup checksums verified;
- the package exposed a stripped-firmware incompatibility in the desktop-only
  `statistics` dependency; it was replaced with a deterministic local median
  implementation and an isolated package-import regression now blocks
  `decimal`, `statistics`, and `sqlite3`;
- malformed non-empty AuditRun manifest JSON now preserves the public
  `invalid_audit_run` error code and has a regression test;
- no production assessment data or radio functionality was used.

This was a development worktree package, not the frozen green-CI artifact.
The authenticated saved-Recon UI read, exact post-CI package retest, final
staged installation, and final rollback therefore remain open release gates.

Post-device workstation closure checkpoint (2026-08-02):

- Windows CPython 3.8.20 and WSL each passed all 261 Python tests; Windows had
  17 intentional platform skips and WSL had three;
- Ruff, Windows and WSL compileall, documentation/JSON validation, shell
  syntax, `git diff --check`, and the tracked secret scan passed;
- Node 16.20.2 passed Angular lint, all 52 ChromeHeadless tests, coverage, and
  the production build. Coverage was 50.60% statements, 36.53% branches,
  58.68% functions, and 50.39% lines;
- no Angular e2e target exists in `angular.json`; `ng e2e` therefore exits with
  `No projects support the 'e2e' target` and is documented as an unavailable
  repository gate rather than a passing test;
- the non-mutating npm audit still reports 177 findings in the legacy full
  development tree and three high findings in production dependencies. No
  automatic or incompatible dependency update was made;
- local-adapter workloads completed 20, three independent 100, and 1,000
  iterations without a failed action. The three 100-iteration aggregate p50
  observations ranged from 0.148 to 0.158 ms;
- minimal, realistic, and frozen-limit store workloads passed. The realistic
  run took 7,818.640 ms, reopened in 92.017 ms, reached 26.43 MiB peak RSS,
  and wrote 268,291 logical bytes across 59 files. The frozen-limit run took
  18,196.438 ms, reopened in 214.319 ms, reached 26.48 MiB peak RSS, and
  exercised the 32-point and 32-run total limits;
- the canonical package contains 28 files and three directories with 1,568,799
  payload bytes. Windows Python 3.8 and WSL independently verified SHA-256
  `03771364154a29df3ba11422f6e35121f1ac081c51658bbb9a9f80914e871132`;
- passive packaged-runtime smoke passed and the deterministic CycloneDX SBOM
  contains 1,275 components with SHA-256
  `2e4c71eeb334682813e8c19115f7715f71e66a71027be67ab88ea91dae1cb5d2`.

Remaining closure work is to create the logical commits, push the draft PR,
obtain green GitHub Actions on the same commit, download or rebuild the frozen
CI-equivalent package, repeat the final physical package/staged-install/
rollback gates, and perform the authenticated saved-Recon read without placing
credentials in commands or evidence.
