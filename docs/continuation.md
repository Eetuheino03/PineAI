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
