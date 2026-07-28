# Architecture

PineAI separates platform integration, deterministic analysis, persistence,
optional AI prose, and operator decisions into explicit trust boundaries.

```text
Authenticated Hak5 Angular session
        |
        | GET saved Recon scan
        v
In-memory validation and normalization
        |
        +--> stable local asset, network, snapshot, and evidence IDs
        |
        v
Immutable active baseline + current snapshot
        |
        +--> deterministic comparability decision
        +--> deterministic AP and SSID diff
        +--> eight deterministic finding rules
        +--> revisioned finding lifecycle
        |
        +--------------------------+
        |                          |
        v                          v
JSON / standalone HTML       Privacy-filtered structured facts
authoritative report                |
                                    v
                              Optional AI provider
                                    |
                                    v
                              labelled explanation only
```

## Authority boundaries

The deterministic engine is authoritative for:

- normalized observations and stable IDs;
- scan comparability and its reason codes;
- AP and SSID differences;
- rule matching and evidence references;
- severity, confidence, and confidence factors;
- finding lifecycle;
- machine-readable and factual report content.

AI output is non-authoritative. It may explain an existing finding, provide
alternative explanations, suggest safe manual validation, summarize
deterministic changes, or draft technical prose. It may not create or remove a
finding, change a rule result, assign severity or confidence, update lifecycle
state, operate the radio, or return executable commands.

Every AI response uses a strict versioned schema. Returned assessment,
comparison, finding, and evidence references are checked against the local
request before the prose is accepted.

## Data flow and persistence

Raw Hak5 Recon JSON exists only for the duration of the request. The resolver
validates it, normalizes documented aliases, and derives:

- a normalized snapshot;
- access-point assets and SSID networks;
- per-observation evidence IDs;
- a canonical snapshot digest;
- a comparability profile.

An assessment represents one wireless environment or location. Its baseline
versions are immutable; a separate revision-checked operation activates one
version. Saved analysis contains normalized snapshots, comparison facts,
evidence, findings, and lifecycle events, never the raw Recon response.

State is stored below `/root/.PineAI/assessments/`:

- directories: `0700`;
- persisted JSON and JSONL files: `0600`;
- writes: atomic replace;
- concurrency: `expected_revision`;
- history: append-only audit events.

Generated JSON and HTML reports are returned in memory for an explicit
operator download; PineAI does not persist report artifacts on the device.

Legacy `/root/.PineAI/engagements/` data is ignored and left untouched.

## Identity and privacy

The device has a private 256-bit HMAC key in
`/root/.PineAI/pseudonymization.key`. Stable asset, network, finding, and
evidence IDs are derived with HMAC-SHA256.

Real BSSIDs and SSIDs may be stored locally because they are required for
repeatable assurance. They are separated from the optional AI payload:

- MAC addresses and BSSIDs are always removed;
- SSIDs are pseudonymized unless `share_ssids=true`;
- raw scans, scan IDs, secrets, local notes, and audit free text are removed;
- wireless strings remain untrusted data and never become instructions.

AI and network failure leave the complete deterministic workflow operational.

## Comparability

The resolver returns one of:

- `comparable`: absence-based drift and lifecycle resolution are allowed.
  Requires matching `location_id` and `measurement_point_id`, no explicit
  scan/radio/interface profile mismatch, complete declared-channel coverage,
  and passing duration, detection, and quality thresholds.
- `partially_comparable`: observed changes are reported with a confidence
  penalty, but absence-based findings are suppressed. Triggered when required
  location/point context or declared channels are unknown, an explicit radio
  profile differs, or a quality threshold is not met.
- `not_comparable`: a diagnostic diff is returned, but finding lifecycle is
  not changed. Triggered by explicit location, measurement-point,
  `scan_profile_id`, or `interface` mismatch; a band mismatch; or an empty
  current scan.

`radio_profile_id` mismatch is deliberately less strict than a scan-profile
or interface mismatch: the observation remains useful, but the result cannot
assert that a baseline AP is absent. Unknown scan, radio, or interface
profiles also limit the result to `partially_comparable`, because the
measurement method has not been proven equivalent.

The decision considers absolute measurement context (`location_id` and
`measurement_point_id`), scan/radio/interface profile compatibility, declared
and observed channel coverage, scan duration, baseline AP detection ratio,
and overall comparison quality score. Reason codes remain machine-readable.

## Finding rules and confidence

The first registry contains exactly:

1. `new_access_point`
2. `known_ssid_new_bssid`
3. `access_point_missing`
4. `ssid_changed`
5. `encryption_changed`
6. `wps_enabled`
7. `channel_changed`
8. `security_profile_divergence`

When a new BSSID advertises a baseline SSID, only
`known_ssid_new_bssid` is emitted; the generic `new_access_point` duplicate is
suppressed.

Each rule declares an authoritative severity and base confidence. Final
confidence is the bounded sum of:

```text
base confidence
- comparability penalty
+ evidence bonus (capped)
```

Hak5 encryption values remain opaque numeric codes in this release.

## Finding lifecycle

Finding identity is stable across scans and is based on assessment, rule, and
subject. Supported states are:

```text
open -> acknowledged -> resolved
  |            |
  +-----> false_positive
```

A comparable clean scan automatically resolves matching `open` or
`acknowledged` findings. If the condition returns, the same finding ID is
reopened. A `false_positive` state is an operator decision; new occurrences
are recorded but do not silently override it.

## Platform boundary

The Angular frontend reads saved scans through the authenticated Hak5 REST
session:

```text
GET /api/recon/scans
GET /api/recon/scans/:scan_id
```

PineAI `0.6.1` does not call `POST /api/recon/start`, stop scans, or operate a
radio. The backend receives Recon JSON from Angular and does not store the
Pineapple root password.

The public module contract is documented in
[backend-api.md](backend-api.md) and
[baseline-drift-v1.schema.json](schemas/baseline-drift-v1.schema.json).

## Roadmap

- **0.6.x Baseline & Drift:** introduced in `0.6.0`, with the current
  comparability-hardening patch in `0.6.1`; one environment per assessment,
  versioned
  baselines, deterministic changes and findings, lifecycle, reports, optional
  AI explanations, complete Angular workflow.
- **0.7.0 Wireless Assurance:** continuous observation, multiple locations,
  timelines, deterministic rogue/clone scoring, suppressions, and
  notifications.
- **0.8.0 AI Analyst:** structured Q&A, evidence-gap suggestions, and local or
  OpenAI-backed provider abstraction.
