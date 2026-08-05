# PineAssure v0.7.0 architecture

PineAssure is a portable, offline-first wireless assurance and repeatable
field-audit layer for the WiFi Pineapple Mark VII. The technical Hak5 module
ID, package root, CLI, and state directory remain `PineAI`, `PineAI/`,
`pineai`, and `/root/.PineAI`. It analyzes saved Hak5 Recon observations. It is
not an attack assistant, and it never starts, stops, or reconfigures a radio.

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
                      |
                      v
Location-only MeasurementPoints -> pinned AuditRun
                      |
                      v
Per-point resolve/compare -> terminal deterministic run report
```

Raw Hak5 Recon JSON is held only in memory. PineAI persists normalized
snapshots and the evidence required to reproduce its conclusions.

## Measurement profiles and provenance

A MeasurementProfile describes the operator-declared technical collection
contract, not the physical measurement location:

- scan- and radio-profile identifiers;
- interface;
- declared bands and channels;
- expected scan duration;
- explicit confirmation when 5 GHz coverage is claimed.

Physical location and placement instructions belong only to the versioned
MeasurementPoint. AuditRun assignments bind that location-only point to an
immutable MeasurementProfile version, baseline, and AssuranceProfile.

Profiles are versioned. A resolved snapshot pins the profile version and
digest used at collection time. Consensus inputs must use matching measurement
provenance. A later comparison exposes mismatches as deterministic
comparability reasons instead of silently treating unlike observations as
equivalent.

An AuditRun assignment additionally binds a baseline to one physical
MeasurementPoint: the baseline's
`measurement_context.measurement_point_id` must equal the assigned point. The
current scan context is reconstructed from the immutable assignment and pinned
MeasurementProfile, so untrusted scan metadata cannot override the point
identity.

This pin is an operator-declared collection contract. Hak5 saved Recon does
not independently bind the scan to the declared interface, bands, channels,
duration, or radio profile. The resolve UI and every AuditRun report disclose
that limitation; PineAssure does not present those settings as device-verified
measurement facts.

## Consensus baseline

The consensus baseline is constructed from two to five non-empty resolved
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

Snapshots written by the current writer include a canonical
`snapshot_record_digest`. A legacy snapshot without that field remains
readable, but its record content is explicitly integrity-unbound. Identical
legacy content may be referenced without rewriting the immutable file, and
the limitation code `legacy_snapshot_integrity_unbound` is carried into new
occurrence/report facts.

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
Structured `ssid`, `*_ssid`, and `*_ssids` fields are always redacted when
sharing is disabled. Known SSID literals are also removed from defined finding
and AI prose fields without rewriting schema versions, IDs, timestamps,
digests, statuses, or other structural values.

Customer history loading uses a 512 KiB aggregate occurrence budget and the
canonical customer fact model is capped at 1 MiB. AuditRun reporting loads one
immutable artifact at a time into a 512 KiB canonical-fact budget and reads
audit events in bounded pages. These are admission limits, not Mark VII
performance claims.

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
        ├── exports/
        └── audit_runs/
            └── ar_<id>/
                ├── manifest.json
                └── measurements/
                    └── arm_<id>.json
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
`config.json`, and the pseudonymization key. Assessment content includes split
AuditRun manifests and their per-measurement documents. It excludes
`openai.key`, transient locks, and transaction journals. Restore always targets
a new or empty staging directory and never overwrites live state.

Creation, verification, and staging restore enforce the same file-path and
content allowlist. Verification rejects unsupported state files, invalid
configuration or identity content, raw Hak5 Recon structures, links, special
files, size mismatches, and digest mismatches before staging writes begin.
Tar member paths, modes, types, duplicates, declared sizes, and cumulative
payload size are rejected from each header before advancing through that
member's compressed body.

See [install-mark-vii.md](install-mark-vii.md) for the exact SSH commands.

## Radio and network boundaries

PineAssure v0.7.0 reads only:

```text
GET /api/recon/status
GET /api/recon/scans
GET /api/recon/scans/:scan_id
```

`GET /api/recon/status` is informational. PineAI does not call Recon start or
stop endpoints and does not alter PineAP or radio settings.

Only optional AI explanation requires an outbound provider connection. All
authoritative analysis, lifecycle, evidence, and reporting remain local.

## v0.7.0 Repeatable Field Audit architecture

PineAssure v0.7 adds operator-driven multi-point auditing to the technical
`PineAI` module. MeasurementPoints hold only location context. Technical
settings remain versioned MeasurementProfiles and are pinned with the baseline
and AssuranceProfile when a run is created.

Limits are 16 active and 32 total points, 16 assignments per run, 32 runs per
assessment, one `in_progress` run per assessment, and one Recon resolution at a
time. Runs use one manifest and one file per measurement. Mutations retain the
existing journal, commit-marker, atomic-replace, and recovery guarantees.

See [Repeatable Field Audit architecture](repeatable-audits.md), the
[public action guide](repeatable-audits-api-v1.md), and the
[versioned schema](schemas/repeatable-audits-v1.schema.json).

Workstation and CI validation do not establish Mark VII performance. The
stable release remains gated by the exact-asset
[physical validation procedure](mark-vii-validation-v0.7.md).

## PineAI / PineAssure Companion System Architecture (Proposed v0.9.0)

The optional **PineAI Companion** allows a WiFi Pineapple Mark VII to push sealed, privacy-filtered audit bundles directly to an operator-controlled Companion instance over an outbound-only ingress tunnel without public IP addresses, router port forwarding, or stored root SSH credentials.

* **Detailed Specification**: See [docs/companion-architecture.md](companion-architecture.md).
* **Companion Core**: Shared Python backend (`pineai_companion_core`) serving single-container Docker, native Windows desktop, and native Linux desktop distributions.
* **Mark VII Outbox**: Bounded local delivery outbox under `/root/.PineAI/outbox/` (max 5 bundles / 64 MiB RAM/disk ceiling) with exponential backoff retry.
* **Ingress Isolation**: Admin UI binds to `127.0.0.1:8741`. Ingress adapter exposes strictly an allowlisted ingest service (`127.0.0.1:8742`).
* **Offline Authority**: Mark VII retains 100% deterministic authority. The Companion is strictly an optional storage, analytics, and reporting enhancement.
