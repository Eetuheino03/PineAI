# PineAssure v0.7.0 repeatable-audit API

This document freezes the public Hak5 module-action contract for the v0.7.0
Repeatable Field Audit workflow. The technical module identifier remains
`PineAI`; PineAssure is the product name.

The machine-readable contract is
[`schemas/repeatable-audits-v1.schema.json`](schemas/repeatable-audits-v1.schema.json).
If an example and that schema differ, the schema is authoritative. Runtime
responses may add only fields explicitly allowed by the schema.

## Authority and exclusions

The backend owns workflow state, revisions, immutable pins, comparisons,
findings, evidence, capacity and report facts. The browser never infers or
persists an alternate state truth.

v0.7.0 does not start Recon, control radios, schedule background work, run an
agent loop or perform an attack. An operator selects an already saved Recon
result and supplies it to `resolve_audit_measurement`.

Only one scan payload is processed at a time. Raw Recon JSON is validated and
normalized in memory and is never persisted.

## Identifiers and common rules

| Entity | Pattern |
| --- | --- |
| Assessment | `assessment_<UUID-v4>` |
| MeasurementPoint | `mp_<16 lowercase hex>` |
| AuditRun | `ar_<16 lowercase hex>` |
| AuditRunMeasurement | `arm_<16 lowercase hex>` |
| MeasurementProfile | `mprofile_<UUID-v4>` |
| MeasurementProfile version | `mprofile_r<4 digits>` |
| Baseline version | `baseline_v<4 digits>` |
| AssuranceProfile version | `assurance_v<4 digits>` |
| Snapshot | `snapshot_<16 lowercase hex>` |
| Comparison | `comparison_<16 lowercase hex>` |
| Occurrence set | `occurrence_<16 lowercase hex>` |
| Evidence | `evidence_<12 lowercase hex>` |

Digests are SHA-256 values encoded as exactly 64 lowercase hexadecimal
characters. Timestamps are strict RFC 3339 values with an explicit timezone;
the backend emits UTC timestamps ending in `Z`.

Unknown request fields are rejected. Every mutation uses optimistic
concurrency. A stale revision returns `revision_conflict` and does not mutate
state.

The fixed v0.7.0 limits per assessment are:

- 16 active MeasurementPoints;
- 32 MeasurementPoint records including archived records;
- 16 assignments per AuditRun;
- 32 AuditRuns;
- one `in_progress` AuditRun;
- one scan-processing operation globally.

The pre-existing assessment pools remain bounded independently. Call
`repeatable_audit_capabilities` for contractual limits and
`resource_telemetry` for current observational resource state.

## Domain separation

### MeasurementPoint

A MeasurementPoint describes a physical place and operator guidance only:

```json
{
  "measurement_point_id": "mp_0123456789abcdef",
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "location_label": "Reception desk",
  "physical_notes": "Stand beside the visitor counter.",
  "operator_instructions": "Keep the device at desk height.",
  "status": "active",
  "created_at": "2026-07-31T08:00:00Z",
  "archived_at": null,
  "revision": 1
}
```

Technical interface, band, channel and duration configuration belongs to an
existing immutable MeasurementProfile version, not to the point.

### AuditRun and immutable assignment pins

An AuditRun pins one AssuranceProfile version. Each assignment pins the exact
MeasurementPoint revision and digest, MeasurementProfile version and digest,
and baseline version and digest when the run is created. Updating or archiving
a source object later cannot alter an existing run.

The assigned baseline must have a
`measurement_context.measurement_point_id` equal to the assignment's
`measurement_point_id`. A cross-point baseline is rejected with
`pinned_reference_mismatch`. During resolution the backend ignores any
caller-supplied measurement context and constructs the current snapshot context
from the immutable AuditRun assignment and MeasurementProfile pin. The current
snapshot's `measurement_point_id` is therefore always the assigned physical
point.

Creation uses this request shape:

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "expected_assessment_revision": 8,
  "audit_run": {
    "name": "July floor audit",
    "description": "Operator-guided repeat measurement",
    "due_at": "2026-08-01T15:00:00Z",
    "assurance_profile_version_id": "assurance_v0003",
    "assignments": [
      {
        "measurement_point_id": "mp_0123456789abcdef",
        "measurement_profile_id": "mprofile_123e4567-e89b-42d3-a456-426614174000",
        "measurement_profile_version_id": "mprofile_r0002",
        "baseline_version_id": "baseline_v0004"
      }
    ]
  }
}
```

The response includes `audit_run`, separately stored `measurements`,
`workflow`, `ready_to_start`, `assessment_revision` and
`assessment_capacity`.

## State machines

AuditRun transitions:

```text
draft -> in_progress -> completed
  |          |
  +----------+-> cancelled
```

Several drafts may exist, but at most one run may be `in_progress`. There is no
`paused` state or pause/resume action. An `in_progress` run is durable and is
resumed implicitly by loading it again.

AuditRunMeasurement transitions:

```text
pending -> resolved -> completed
   |          |
   +----------+-> failed

failed(resolution) --retry--> pending
failed(comparison) --retry--> resolved
```

`complete_audit_run` is accepted only when every measurement is completed.
Completed and cancelled runs are sealed.

## Public actions

### Capabilities and resources

#### `repeatable_audit_capabilities`

Request: `{}`.

Returns schema versions, public action names, statuses, privacy profiles,
capacity limits, storage layout and strict exclusions. This is the frontend's
feature-discovery source.

#### `resource_telemetry`

Request:

```json
{"assessment_id":"assessment_123e4567-e89b-42d3-a456-426614174000"}
```

`assessment_id` is optional. The response reports process RSS and peak RSS when
available, system memory, load average, storage, bounded artifact statistics,
scan-processing status, recovery state and guard thresholds. It is
observational and never a claim of Mark VII calibration.

### MeasurementPoint actions

#### `create_measurement_point`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "expected_assessment_revision": 3,
  "measurement_point": {
    "location_label": "Meeting room A",
    "physical_notes": "North wall",
    "operator_instructions": "Use the marked table position"
  }
}
```

`location_label` is required and is at most 128 characters. The two optional
texts are each at most 1024 characters. Control characters are rejected.

#### `list_measurement_points`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "include_archived": false,
  "limit": 50,
  "offset": 0
}
```

Returns `measurement_points`, pagination fields and `assessment_capacity`.

#### `get_measurement_point`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "measurement_point_id": "mp_0123456789abcdef"
}
```

#### `update_measurement_point`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "measurement_point_id": "mp_0123456789abcdef",
  "expected_assessment_revision": 4,
  "expected_measurement_point_revision": 1,
  "changes": {
    "location_label": "Meeting room A, marked table",
    "operator_instructions": "Align device with the table marker"
  }
}
```

At least one allowed field must be present in `changes`. Technical measurement
configuration is not accepted.

#### `archive_measurement_point`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "measurement_point_id": "mp_0123456789abcdef",
  "expected_assessment_revision": 5,
  "expected_measurement_point_revision": 2
}
```

Archiving is irreversible in v0.7.0. Existing pinned runs remain readable.

### AuditRun actions

#### `create_audit_run`

Uses the nested request shown under "AuditRun and immutable assignment pins".
Assignments contain identifiers only; the backend resolves and pins the
authoritative revisions and digests atomically.

#### `list_audit_runs`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "limit": 50,
  "offset": 0
}
```

Returns compact run entries, `workflow` summaries, pagination and
`assessment_capacity`.

#### `get_audit_run`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "audit_run_id": "ar_0123456789abcdef"
}
```

Returns `audit_run`, `measurements`, `workflow`, `ready_to_start` and
`assessment_capacity`. The workflow object identifies the current or next
measurement and the next valid operator action.

#### `start_audit_run`, `cancel_audit_run`, `complete_audit_run`

All three use the same concurrency envelope:

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "audit_run_id": "ar_0123456789abcdef",
  "expected_assessment_revision": 9,
  "expected_audit_run_revision": 1
}
```

`cancel_audit_run` additionally accepts an optional `reason` string of at most
512 characters. It is trimmed and included only in the audit event; an empty
or omitted reason is not stored.

Starting revalidates all immutable pins. Cancelling or completing seals the
run. No endpoint deletes a run.

### Measurement actions

All measurement mutations use:

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "audit_run_id": "ar_0123456789abcdef",
  "measurement_id": "arm_0123456789abcdef",
  "expected_assessment_revision": 10,
  "expected_audit_run_revision": 2,
  "expected_measurement_revision": 1
}
```

#### `resolve_audit_measurement`

Adds `scan` and optional `scan_metadata` to the common envelope. The public
action accepts only the saved Hak5 Recon response. It validates and normalizes
that response, discards the raw object, and stores the normalized snapshot.
The measurement records `snapshot_digest` for stable snapshot identity and
`snapshot_record_digest` for the complete canonical normalized snapshot
record. Both values are 64-character lowercase SHA-256 hex digests. Callers
cannot submit an internal snapshot representation or override the assigned
measurement point.

#### `save_audit_measurement_comparison`

Uses only the common envelope. The backend loads the resolved snapshot and all
pinned objects by ID and digest, verifies the complete snapshot against
`snapshot_record_digest`, computes the deterministic comparison and persists
the immutable comparison and occurrence set. Callers cannot submit comparison
facts or occurrence data. Reopening the run and report generation perform the
same complete-record verification; altered snapshot content returns
`pinned_reference_mismatch`.

#### `retry_audit_measurement`

Uses only the common envelope. A resolution failure returns to `pending`; a
comparison failure returns to `resolved`. Valid pinned snapshot state is kept
for a comparison retry.

### `generate_audit_run_report`

```json
{
  "assessment_id": "assessment_123e4567-e89b-42d3-a456-426614174000",
  "audit_run_id": "ar_0123456789abcdef",
  "format": "html",
  "privacy_profile": "share_safe"
}
```

Accepted formats are `json` and `html`. Accepted privacy profiles are
`local_full` and `share_safe`. The action is read-only and available for a
terminal `completed` or `cancelled` run. Cancelled-run reports retain failed
and unfinished measurement facts and describe their limitations.

The response contains `report_id`, `audit_run_id`, `format`, `privacy_profile`,
`generated_at`, `fact_digest`, `content_sha256`, `filename`, `mime_type` and
`content`. JSON and script-free HTML are rendered from the same canonical fact
model. `generated_at` comes from the sealed run so repeated generation from
unchanged facts is deterministic.

Report reconstruction is bounded before rendering: immutable measurement
artifacts are loaded one at a time, selected audit events are paged, and the
canonical fact model has a 512 KiB admission limit. Exceeding the fact or final
output budget returns `audit_report_too_large` before remaining artifacts are
loaded.

## Response and failure envelope

Successful responses use schema version `1.0`. Mutation responses return the
new `assessment_revision`. Run mutations return the latest run detail;
measurement mutations return the updated run manifest, affected measurement,
workflow and capacity so clients can discard stale local state.

Hak5 module failures use:

```json
{
  "error": {
    "code": "revision_conflict",
    "message": "The assessment changed; reload and retry."
  }
}
```

No stack trace, local path, secret or raw Recon value is returned. Important
stable error codes include:

| Code | Meaning |
| --- | --- |
| `invalid_request` | Unknown or malformed public request field |
| `invalid_measurement_point` | Invalid physical point data or identifier |
| `invalid_audit_run` | Invalid run data, identifier or timestamp |
| `invalid_audit_run_measurement` | Invalid measurement identity or state |
| `invalid_recon` | Saved Recon payload cannot be normalized |
| `revision_conflict` | An optimistic-concurrency revision is stale |
| `capacity_exceeded` | A v0.7 entity-count limit was reached |
| `storage_limit_exceeded` | A bounded document or artifact pool is full |
| `event_limit` | Audit-log headroom would violate closure reserve |
| `active_audit_run_exists` | Another run is already `in_progress` |
| `audit_run_not_ready` | A draft cannot start because a pin is invalid |
| `audit_run_sealed` | A completed or cancelled run cannot be mutated |
| `pinned_reference_missing` | A required versioned object is unavailable |
| `pinned_reference_mismatch` | A pinned digest or revision no longer verifies |
| `scan_processing_busy` | Another scan is being processed |
| `resource_guard_blocked` | Local memory or storage guard denied heavy work |
| `transaction_recovery_failed` | Durable recovery could not be completed |
| `audit_run_not_terminal` | Report requested before the run is completed or cancelled |
| `audit_report_too_large` | Report facts or rendered output exceed the safe bounded limit |

## Persistence and recovery

Each run uses split storage:

```text
assessments/<assessment_id>/audit_runs/<audit_run_id>/
  manifest.json
  measurements/
    <measurement_id>.json
```

Changing one measurement never rewrites its siblings. Cross-file mutations use
the existing transaction journal and atomic replacement. A valid legacy flat
v0.7 draft is adapted on read and journal-migrated before its first mutation;
v0.6 assessment, baseline, profile, finding and comparison artifacts remain
unchanged.

All persisted private directories are mode `0700` and private files are mode
`0600`. Symlinks, path traversal and oversized documents are rejected.

The root/SSH continuity-backup allowlist includes the split run paths shown
above: run manifests, optional migration markers, and per-measurement JSON
documents. `pineai backup verify` hashes them and `restore-staging` reproduces
them under an empty staging root. Transient locks and journals and
`openai.key` are not backup members.

The reader applies the same storage-path and bounded content contract as the
backup writer. An internally self-consistent foreign archive is still rejected
when it contains an unsupported assessment file, unknown configuration field,
invalid identity key, or raw Hak5 Recon structure.

## Frontend sequence

1. Load `repeatable_audit_capabilities` and `resource_telemetry`.
2. Create or select physical MeasurementPoints.
3. Create an AuditRun with explicit immutable assignments.
4. Start the run after reviewing the resolved pins.
5. Load `get_audit_run` and follow its backend-owned workflow.
6. Select a saved Recon result and call `resolve_audit_measurement`.
7. Call `save_audit_measurement_comparison` for the resolved measurement.
8. Retry only a backend-reported failed stage.
9. Complete or cancel the run.
10. Generate an offline report from a completed or cancelled run.

The browser must reload after `revision_conflict`, `scan_processing_busy`, a
resource-blocked response or any uncertain network failure. It must never
blindly replay a mutation.
