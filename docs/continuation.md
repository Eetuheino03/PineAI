# PineAI implementation continuation

This file is the hand-off checkpoint for the Baseline & Drift rewrite. Update
it whenever a phase is completed or work stops.

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

- Phase: v0.6.1 release hardening
- Direction checkpoint commit: `201b291`
- Baseline & Drift pull request: `#16`, merged into `main` as `255a8db`
- v0.6.1 release-hardening pull request: `#24`
- Latest implementation and main-integration commit verified by CI: `c34a8cf`
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
- GitHub Actions on pull request `#24`: passed for both the push and pull
  request events:
  - `30351527983`
  - `30351530748`
- Published release-asset checksum: pending tag and pre-release creation

Physical Mark VII smoke testing is intentionally pending. No device files,
settings, radios, or stored assessment data were changed during v0.6.1
release hardening.

## Release handoff

Publish the verified `PineAI-0.6.1.tar.gz` artifact and its matching
SHA-256 sidecar as a GitHub pre-release. Keep it marked as a pre-release until
the exact asset passes the physical Mark VII smoke test. The release notes
must distinguish automated package verification from hardware validation.

## Next task

When the Mark VII is connected again, install that exact v0.6.1 release package
after backing up the existing module and `/root/.PineAI`, then verify module
initialization, offline health, saved Recon listing, baseline creation and
activation, comparison, findings, and offline JSON/HTML report export. Record
the result here. If successful, promote the same GitHub release from
pre-release to stable without rebuilding its assets.
