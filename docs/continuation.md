# PineAI implementation continuation

This file is the hand-off checkpoint for the Baseline & Drift rewrite. Update
it whenever a phase is completed or work stops.

## Starting point

- Public baseline commit: `705b960` (`v0.5.0`)
- Development branch: `feature/baseline-drift-v0.6`
- Target release: `v0.6.0`
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

- Phase: 6 - implementation merged and release handoff ready
- Direction checkpoint commit: `201b291`
- Pull request: `#16`, merged into `main`
- Merge commit: `255a8db`
- Backend: deterministic resolver, assessment storage, comparability, eight
  finding rules, lifecycle, optional AI explanation boundary, and reports
  implemented
- Frontend: all nine Baseline & Drift views implemented; no radio controls or
  old attack-oriented branding remain
- Contract: `baseline-drift-v1.schema.json` and complete frontend/backend
  examples implemented
- Package: `PineAI-0.6.0.tar.gz` built in WSL with root ownership, expected
  modes, and SHA-256 sidecar
- CI artifact SHA-256:
  `caa6f636cb625e5417b7bb55b6f5db61aa4533585bba3ad8de708e71cd77df63`

## Latest completed verification

- Windows Python: 60 tests passed; two POSIX-only permission checks skipped
- WSL Python: 60 tests passed, including `0700`/`0600` permission checks
- Angular/ChromeHeadless: 14 tests passed
- Angular production build: passed
- WSL package build: passed
- Extracted package Python compilation: passed
- Package content check: passed; no legacy advisor, adaptive-Recon,
  engagement-store, profiler, source-map, minified duplicate, bytecode, or
  cache files
- Secret-pattern scan: no committed OpenAI-style API key found
- GitHub Actions: both branch and pull-request runs passed on Python 3.8 and
  Node 16
- Physical Mark VII smoke test: pending because the device hostname and
  default management address were not reachable from the development machine;
  no device files or settings were changed

## Release handoff

Publish the verified CI artifact and checksum as `v0.6.0` from this `main`
state. Do not rebuild the release archive locally.

## Next task

When the Mark VII is connected again, install that exact release package
after backing up the existing module and `/root/.PineAI`, then verify module
initialization, offline health, saved Recon listing, baseline creation and
activation, comparison, findings, and offline JSON/HTML report export. Record
the result here. The device smoke test is the only hardware-dependent
verification still outstanding.
