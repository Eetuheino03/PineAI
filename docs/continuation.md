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

## Release handoff

The verified `PineAI-0.6.1.tar.gz` artifact and its matching SHA-256 sidecar
are published as a GitHub pre-release. Keep that exact release marked as a
pre-release until the exact asset passes the physical Mark VII smoke test.
Do not rebuild or replace the assets during hardware validation.

## Next task

When the Mark VII is connected again, install that exact v0.6.1 release package
after backing up the existing module and `/root/.PineAI`, then verify module
initialization, offline health, saved Recon listing, baseline creation and
activation, comparison, findings, and offline JSON/HTML report export. Record
the result here. If successful, promote the same GitHub release from
pre-release to stable without rebuilding its assets.
