# PineAI v0.6.3 Customer Audit Foundation architecture

PineAI is a portable, offline-first wireless change-audit layer for the WiFi
Pineapple Mark VII. It analyzes saved Hak5 Recon observations. It is not an
attack assistant, and it never starts, stops, or reconfigures a radio.

## Authority boundary

The deterministic backend is authoritative for:

- Recon validation and normalization;
- stable AP, network, snapshot, evidence, occurrence, and issue identities;
- measurement-profile provenance and comparison quality;
- consensus-baseline membership and attributes;
- before/after changes;
- inventory and fixed-policy evaluation;
- result type, severity, categorical certainty, and lifecycle;
- report scope, facts, limitations, and integrity digests.

The optional AI layer may explain or summarize facts already selected by the
deterministic backend. It cannot create an issue, change a result type,
severity, certainty, status, evidence reference, comparison-quality decision,
or report fact.

The entire customer-audit workflow remains available without an API key or
network connection.

## Data flow

```text
Saved Hak5 Recon scans (read-only REST)
        |
        v
Versioned MeasurementProfile
        |
        v
Asset & Change Resolver
  - validates Recon aliases and limits
  - normalizes APs, networks and metadata
  - creates stable HMAC identities and evidence IDs
        |
        +-----------------------------+
        |                             |
        v                             v
2-5 scan consensus preview     Current resolved snapshot
        |                             |
        v                             |
Operator creates and activates        |
an immutable baseline version         |
        |                             |
        +-------------+---------------+
                      |
                      v
Deterministic comparison
  - comparable / partially_comparable / not_comparable
  - observed changes
  - optional AssuranceProfile evaluation
                      |
                      v
Operator saves analysis
  - immutable occurrence and evidence bundle
  - lifecycle updates for policy deviations/security findings
                      |
                      v
Prepared report scope -> scope digest -> JSON/HTML export
```

Raw Hak5 Recon JSON is held only in memory. PineAI persists normalized
snapshots and the evidence required to reproduce its conclusions.

## Measurement profiles and provenance

A MeasurementProfile describes how and where observations are collected:

- location and measurement-point identifiers;
- scan- and radio-profile identifiers;
- interface;
- declared bands and channels;
- expected scan duration;
- explicit confirmation when 5 GHz coverage is claimed.

Profiles are versioned. A resolved snapshot pins the profile version and
digest used at collection time. Consensus inputs must use matching measurement
provenance. A later comparison exposes mismatches as deterministic
comparability reasons instead of silently treating unlike observations as
equivalent.

## Consensus baseline

The primary v0.6.2 baseline is constructed from two to five non-empty resolved
scans. Input order and AP order do not affect the model digest.

The fixed `strict_80_v1` policy classifies each AP as:

- `core` when present in at least `ceil(0.8 * scan_count)` observations;
- `recurring` when present at least twice but below the core threshold;
- `singleton` when present once.

Only a core AP supports an absence inference. Recurring and singleton assets
remain known baseline members, so their later return is not classified as a
new AP.

The default source-age window is 24 hours. The operator may select a value
between 1 and 168 hours, or deliberately use an unbounded source window. An
unbounded window is preserved as a report limitation.

The consensus preview is read-only. Creating a version persists an immutable
baseline model, but does not activate it. Activation is a separate,
revision-checked operator action.

The older single-scan baseline contract remains available for compatibility
with v0.6.0/v0.6.1 records. Guided Customer Audit uses consensus baselines.

## Comparability and categorical certainty

Comparison status is one of:

- `comparable` — matching provenance and sufficient coverage permit positive
  changes and absence inferences;
- `partially_comparable` — observed changes may be reported, but missing-asset
  conclusions are disabled;
- `not_comparable` — a diagnostic diff may be shown, but no issue lifecycle is
  changed.

Examples of hard mismatches include a known location, measurement point,
scan-profile, interface, or MeasurementProfile-provenance mismatch. Missing
provenance and incomplete coverage reduce comparison quality instead of being
hidden.

Customer-facing certainty is categorical:

- `confirmed` — directly observed in comparable data;
- `probable` — an allowed absence inference or a positive observation from
  partially comparable data;
- `limited` — diagnostic evidence from non-comparable or legacy data.

There is no customer-facing percentage score. Older stored records may contain
deprecated numeric fields; they are retained only as read-only legacy
metadata.

## AssuranceProfile

An AssuranceProfile is an immutable, assessment-local version of approved
inventory plus the fixed policy registry. It may be created from a validated
CSV preview or a normalized profile object. Creating a profile does not
activate it.

Inventory coverage is:

- `partial` — unlisted observed assets are not automatically unauthorized;
- `authoritative` — the inventory is treated as the approved estate.

Activating an authoritative profile requires an additional explicit
confirmation. The active profile version and digest are pinned into each new
analysis occurrence.

Without an active AssuranceProfile, PineAI still reports measured drift as
observed changes. It does not promote ordinary drift to a customer security
finding.

## Result taxonomy

The active product has three separate result types:

| Result type | Meaning | Severity | Lifecycle |
| --- | --- | --- | --- |
| `observed_change` | A measured before/after fact | No | No |
| `policy_deviation` | A violation of the explicitly active fixed policy | Yes | Yes |
| `security_finding` | A policy- and inventory-backed security condition | Yes | Yes |

Policy deviations include authoritative-inventory, required-presence, SSID,
opaque encryption-code, WPS, channel, and vendor rules. The first release does
not infer that one Hak5 numeric encryption code is stronger than another.

Security findings are restricted to the fixed registry:

- an unauthorized BSSID advertising a protected SSID;
- a protected SSID using a disallowed encryption code;
- WPS enabled where the active policy forbids it.

Issue lifecycle states are `open`, `acknowledged`, `false_positive`, and
`resolved`. A comparable clean observation may resolve an active issue. A
later recurrence reopens the same stable issue identity. Operator
false-positive decisions are preserved and later occurrences are recorded
without silently reversing that decision.

## Immutable evidence and legacy history

Saving an analysis creates an immutable occurrence set containing:

- observed changes;
- inventory reconciliation;
- policy deviations and security findings;
- before/after evidence references;
- comparison-quality factors;
- pinned baseline, MeasurementProfile, and AssuranceProfile versions;
- limitations.

`get_evidence_bundle` resolves one selected item to its exact point-in-time
evidence. Reports do not reconstruct facts that were never stored.

v0.6.0/v0.6.1 assessments, baselines, comparisons, and findings remain
readable. Legacy findings are labelled `legacy_read_only`; Customer Audit does
not reclassify or mutate them retrospectively.

## Report boundary

Every report uses one explicit scope:

- `comparison` — one immutable comparison and its point-in-time occurrence;
- `assessment_current` — the assessment's current active customer-audit
  state;
- `assessment_history` — stored comparisons, occurrences, and lifecycle
  history.

The operator first calls `prepare_report`. The backend returns an authoritative
manifest, warnings, and a `scope_digest`. `generate_report` recomputes the
selected facts and rejects a stale digest.

JSON and standalone script-free HTML are rendered from the same canonical fact
model. The public module action stores a private short-lived export under the
assessment's `exports/` directory and returns an exact `POST /api/download`
descriptor. The frontend sends that descriptor unchanged. It never injects
report HTML into the module page.

`local_full` retains local audit identifiers. `share_safe` removes or
pseudonymizes local identifiers; SSIDs remain hidden unless sharing was
explicitly enabled. Optional AI prose is clearly labelled non-authoritative.

## Persistence and transactions

Runtime state is rooted at `/root/.PineAI/`:

```text
/root/.PineAI/
├── config.json
├── pseudonymization.key
├── openai.key                         # optional; never in continuity backup
├── measurement_profiles/
│   └── mprofile_<uuid>/
│       ├── profile.json
│       └── versions/
└── assessments/
    └── assessment_<uuid>/
        ├── assessment.json
        ├── events.jsonl
        ├── snapshots/
        ├── baselines/
        ├── baseline_models/
        ├── assurance_profiles/
        ├── comparisons/
        ├── findings/
        ├── occurrences/
        └── exports/
```

Private directories are `0700`; JSON, JSONL, key, configuration, occurrence,
and export files are `0600`. Mutations use `expected_revision` optimistic
concurrency and append-only audit events. Multi-file writes use recoverable
private transaction journals; transient locks and journals are not report or
backup evidence.

The old `/root/.PineAI/engagements/` tree is left untouched and is not read by
Customer Audit.

## Identity continuity and backup

Stable IDs depend on `/root/.PineAI/pseudonymization.key`. Once assessment data
exists, a missing or invalid identity key is a hard failure; PineAI never
silently generates a replacement identity.

The continuity-backup CLI includes assessments, measurement profiles,
`config.json`, and the pseudonymization key. It excludes `openai.key`,
transient locks, and transaction journals. Restore always targets a new or
empty staging directory and never overwrites live state.

See [install-mark-vii.md](install-mark-vii.md) for the exact SSH commands.

## Radio and network boundaries

PineAI v0.6.3 reads only:

```text
GET /api/recon/status
GET /api/recon/scans
GET /api/recon/scans/:scan_id
```

`GET /api/recon/status` is informational. PineAI does not call Recon start or
stop endpoints and does not alter PineAP or radio settings.

Only optional AI explanation requires an outbound provider connection. All
authoritative analysis, lifecycle, evidence, and reporting remain local.

## v0.7.0 Repeatable Field Audits Architecture (Contract Frozen)

PineAI v0.7.0 introduces multi-point offline wireless change auditing (`MeasurementPoint` and `AuditRun`).
* **Contract Specification**: `docs/repeatable-audits-api-v1.md`
* **JSON Schemas**: `docs/schemas/repeatable-audits-v1.schema.json` and `docs/schemas/audit-run-report-v1.schema.json`
* **Hardware Validation Gate**: Physical Mark VII validation for `v0.6.3` remains pending. Contract design for `v0.7.0` is frozen as a pre-implementation specification by user authorization.
