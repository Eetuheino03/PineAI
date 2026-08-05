# PineAssure v0.7 Repeatable Field Audit architecture

## Purpose

Repeatable Field Audit turns an existing PineAI assessment into a durable,
multi-point field workflow. The operator selects saved Hak5 Recon observations;
PineAssure resolves, compares, and reports them locally.

The backend is the only state authority. Closing the browser does not pause,
cancel, or advance a run. Reopening an `in_progress` run resumes the same
operator workflow.

## Safety boundary

The v0.7 workflow does not expose or execute:

- Recon start or stop;
- radio, channel, capture, or interface configuration;
- campaigns, deauthentication, evil twins, or credential collection;
- background scheduling, polling that mutates state, or autonomous actions;
- persistence of raw Hak5 Recon JSON.

All mutations are explicit Hak5 module actions with optimistic concurrency.

## Domain model

```text
Assessment
|-- MeasurementPoint (location and operator context)
|-- MeasurementProfile versions (technical measurement contract)
|-- baseline versions
|-- AssuranceProfile versions
`-- AuditRun
    |-- immutable run-level AssuranceProfile pin
    `-- 1..16 AuditRunMeasurements
        |-- MeasurementPoint revision, digest, and snapshot
        |-- MeasurementProfile version and digest
        |-- baseline version and digest
        `-- resolution, comparison, occurrence, and evidence references
```

### MeasurementPoint

A point describes where an operator stands and what they need to know at that
location. It contains a required `location_label`, optional `physical_notes`
and optional `operator_instructions`, plus status, revision and RFC 3339
timestamps.

It never contains interface, band, channel, radio profile, scan profile, or
duration. Those fields belong to MeasurementProfile.

The assessment may hold 16 active and 32 total point records. Archiving is a
terminal point transition in v0.7; existing AuditRun pins remain valid because
the run retains the point snapshot and digest.

### AuditRun and assignment pinning

A draft run accepts 1-16 assignments. Each assignment identifies a point, one
exact MeasurementProfile version, and one baseline version. The run identifies
one exact AssuranceProfile version.

Creation resolves and stores all referenced revisions and digests. Missing,
archived, incompatible, or ambiguous references fail creation. Later edits to
source records do not silently change the run; the UI shows provenance status
before start and resolution.

MeasurementProfile provenance is an operator-declared contract. The saved
Hak5 Recon record does not independently prove which interface, bands,
channels, duration, or radio profile produced it. PineAssure shows this before
resolution and includes it as an authoritative report limitation.

The selected baseline is valid for an assignment only when its
`measurement_context.measurement_point_id` exactly matches the assigned
physical MeasurementPoint. Resolution does not trust a point identifier from
the browser or saved-scan metadata: the current normalized snapshot always
inherits the immutable point identifier from the AuditRun assignment. This
prevents a baseline or caller-supplied context from silently moving evidence
between physical points.

At most 32 runs may exist in an assessment. Multiple drafts are allowed, but
only one may be `in_progress`.

## State machines

### AuditRun

```text
draft ------> in_progress ------> completed
  |                 |
  `-----------------+-----------> cancelled
```

- Start requires every pin to remain valid.
- Complete requires every measurement to be `completed`.
- Cancel is allowed from `draft` or `in_progress` and records an optional
  bounded reason.
- Completed and cancelled runs are immutable.
- v0.7 has no `paused` state. Durable `in_progress` state is implicitly
  resumable.

### AuditRunMeasurement

```text
pending --resolve--> resolved --compare--> completed
   ^                     ^
   |                     |
   +-- retry resolution -+-- retry comparison
```

A resolution failure retains only bounded diagnostic information and retries to
`pending`. A comparison failure preserves the valid normalized snapshot and
retries to `resolved`. Retrying never changes pinned provenance.

## Persistence and transaction model

```text
/root/.PineAI/assessments/<assessment_id>/
|-- assessment.json
|-- events.jsonl
|-- measurement_points.json
`-- audit_runs/
    `-- <audit_run_id>/
        |-- manifest.json
        `-- measurements/
            `-- <measurement_id>.json
```

The run manifest contains run metadata, status, revision, terminal timestamps,
the run-level AssuranceProfile pin, and ordered measurement identifiers. Each
measurement document contains its own revision, pins, state, and artifact
references.

A point transition rewrites only that measurement, the small run manifest when
its summary/revision changes, and required assessment/event/artifact documents.
Sibling measurement files are not rewritten.

Directories use mode `0700`; state files use `0600`. Reads reject symlinks,
special files, path escapes, unknown fields, unsupported schemas, oversized
documents, invalid IDs, invalid RFC 3339 values, and digest mismatches.

Root/SSH continuity backups include this split AuditRun tree, including each
run `manifest.json`, optional migration marker, and per-measurement documents.
Backup verification and staging restore preserve these paths and validate their
content hashes; `openai.key`, locks, and transaction journals remain excluded.

Cross-file writes use a prepared transaction journal, staged documents, atomic
replacement, a commit marker, fsync where supported, and deterministic startup
roll-forward. A transaction validates all staged entries before publishing the
first target.

## Legacy compatibility

Released v0.6 assessment, baseline, profile, comparison, occurrence, and
finding documents remain authoritative and are not rewritten merely by reading
them.

The unreleased flat AuditRun draft format is read through an adapter. Its first
v0.7 mutation performs a transactionally journalled copy-validate-commit
migration to split documents. The source remains recoverable until the
migration marker and target documents validate. Migration failures return a
stable error and do not guess at partial state.

## Resolution and comparison flow

1. The frontend fetches a saved scan using the authenticated Hak5 REST session.
2. It submits the selected raw response and scan metadata to
   `resolve_audit_measurement`.
3. A module-wide non-blocking operation lock allows one resolution at a time.
4. The resource guard checks memory, disk, input size, and artifact capacity.
5. Recon validation canonicalizes AP order, rejects invalid BSSIDs, bounds APs,
   clients, and text, and creates one normalized snapshot.
6. Only the normalized snapshot and bounded provenance are persisted. The
   measurement pins both the snapshot identity digest and
   `snapshot_record_digest`, a SHA-256 digest over the complete canonical
   normalized snapshot record.
7. `save_audit_measurement_comparison` loads the pinned baseline and computes
   comparability, changes, deviations, findings, occurrence facts, and evidence
   locally.

Reopening a run, saving its comparison, and generating its report all verify
`snapshot_record_digest`. Any later change to locally stored snapshot content,
including a field that is not part of the stable snapshot identity, fails with
`pinned_reference_mismatch`; PineAssure does not continue from altered
evidence.

The client cannot submit a comparison result or substitute profile/baseline
parameters during either step.

## Resource safety

- Raw Recon input remains bounded to 8 MiB, 1000 APs, and 10000 clients.
- Snapshot, comparison, occurrence, evidence, event, document, and report pools
  retain explicit independent limits.
- A module-wide lock returns `scan_processing_busy` rather than waiting
  indefinitely.
- Resource admission fails with `resource_guard_blocked` before a heavy
  operation when projected memory or disk reserve is unsafe.
- OUI data is loaded lazily and cached by file identity and mtime.
- Telemetry reports RSS, peak RSS, MemAvailable, load, disk space, assessment
  size/artifact counts, lock state, and recovery state without secrets.

The initial guard floors are conservative and not hardware performance claims.
They must be calibrated with exact-asset Mark VII evidence.

## Deterministic reports

Completed and cancelled runs can export `local_full` or `share_safe` JSON and
script-free HTML. Cancelled reports include pending and failed points.

The report service:

- loads and validates immutable point-in-time references;
- builds one canonical fact model;
- uses the terminal run timestamp as `generated_at`;
- derives both formats from the same facts;
- returns separate canonical fact and content SHA-256 digests;
- escapes all untrusted HTML;
- performs no event, export-file, or domain-state write.

`share_safe` removes local notes, run and baseline labels, source Recon IDs,
physical-location identifiers, interface/profile labels, and raw MAC/BSSID
values. It redacts SSIDs while retaining stable opaque PineAssure identifiers
and non-identifying technical facts such as channels and band coverage. Inline
AI prose is excluded because its caller-supplied text cannot be proven free of
local secrets. The frontend creates a browser Blob for download.

## Public integration

The normative request/response schema is
[`repeatable-audits-v1.schema.json`](schemas/repeatable-audits-v1.schema.json).
Frontend call order, examples, revisions, and error handling are documented in
[the public API guide](repeatable-audits-api-v1.md).

The hardware release procedure is
[Mark VII validation for v0.7](mark-vii-validation-v0.7.md).
