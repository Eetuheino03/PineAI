# PineAI v0.7.0 — Repeatable Field Audits API Contract Specification

This document defines the formal, frozen API module action contract for **PineAI v0.7.0 — Repeatable Field Audits**.

> [!IMPORTANT]
> **Pre-Implementation Contract Gate**: This specification is a mandatory contract freeze. No backend Python service code or frontend Angular component code may be implemented until this API contract document and its associated JSON Schemas are approved.

---

## 1. Domain Identifier Patterns & Contract Constants

### 1.1 Existing Repository Identifier Formats
All domain entities reuse authentic PineAI identifier formats derived from repository constants:

* `assessment_<UUID-v4>` (e.g. `assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890`)
* `snapshot_<16 lowercase hex>` (e.g. `snapshot_a1b2c3d4e5f67890`)
* `baseline_v<4 digits>` (e.g. `baseline_v0001`)
* `comparison_<16 lowercase hex>` (e.g. `comparison_0123456789abcdef`)
* `finding_<12 lowercase hex>` (e.g. `finding_123456789abc`)
* `evidence_<12 lowercase hex>` (e.g. `evidence_123456789abc`)
* `occurrence_<16 lowercase hex>` (e.g. `occurrence_fedcba9876543210`) — Used as the value for `occurrence_set_id`.
* `mprofile_<UUID-v4>` (e.g. `mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890`)
* `mprofile_r<4 digits>` (e.g. `mprofile_r0001`)
* `assurance_v<4 digits>` (e.g. `assurance_v0001`)
* `bmodel_<16 lowercase hex>` (e.g. `bmodel_1122334455667788`)

### 1.2 Proposed v0.7.0 Identifier Regex Rules
New entity identifiers introduced in v0.7.0:

* `MEASUREMENT_POINT_ID_PATTERN = r"^mp_[0-9a-f]{16}$"` (e.g. `mp_a1b2c3d4e5f67890`)
* `AUDIT_RUN_ID_PATTERN = r"^ar_[0-9a-f]{16}$"` (e.g. `ar_0123456789abcdef`)
* `AUDIT_RUN_MEASUREMENT_ID_PATTERN = r"^arm_[0-9a-f]{16}$"` (e.g. `arm_0123456789abcdef`)
* `AUDIT_RUN_REPORT_ID_PATTERN = r"^report_[0-9a-f]{16}$"` (e.g. `report_0123456789abcdef`)

### 1.3 Digest Encoding
All SHA-256 digests MUST be serialized as exactly 64 lowercase hexadecimal characters without any prefix (e.g. `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). Prefixes such as `sha256_` are strictly prohibited.

---

## 2. Expected Measurement Context Structure

MeasurementPoints define an expected physical or logical measurement context aligned to the existing PineAI contract:

```json
{
  "location_id": "loc_site_alpha",
  "measurement_point_id": "mp_a1b2c3d4e5f67890",
  "scan_profile_id": "prof_full_dual_band",
  "radio_profile_id": "radio_wlan0_wlan1",
  "interface": "wlan0",
  "declared_bands": ["2.4", "5"],
  "declared_channels": [1, 6, 11, 36, 40],
  "scan_time": 300
}
```

* `declared_bands` MUST contain only `"2.4"` and/or `"5"`.
* `scan_time` MUST be an integer number of seconds between 30 and 3600 (duration, not a timestamp).

---

## 3. Concurrency & Explicit Revision Ownership

To prevent ambiguous concurrency checks, every mutation action explicitly declares and validates entity-specific revisions:

| Entity Mutation | Required Revision Parameters | Advanced Revisions |
|---|---|---|
| **MeasurementPoint** | `expected_assessment_revision`, `expected_measurement_point_revision` | Point revision +1, Assessment revision +1 |
| **AuditRun** | `expected_assessment_revision`, `expected_audit_run_revision` | AuditRun revision +1, Assessment revision +1 |
| **AuditRunMeasurement** | `expected_assessment_revision`, `expected_audit_run_revision` | AuditRun revision +1, Assessment revision +1 |

Mutation actions are non-idempotent. Executing a mutation with a stale revision raises `BackendError("revision_conflict")`.

---

## 4. Backend Module Action Specifications (v0.7.0)

### 4.1 `create_measurement_point`
* **Version**: `v0.7.0`
* **Purpose**: Defines a new MeasurementPoint in an Assessment.
* **Classification**: Non-idempotent mutation.
* **Preconditions**: Assessment exists; point count < 64.
* **Request Schema**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "name": "Floor 2 West Wing",
    "description": "Primary office workspace",
    "expected_measurement_context": {
      "location_id": "loc_site_alpha",
      "measurement_point_id": "mp_a1b2c3d4e5f67890",
      "scan_profile_id": "prof_full_dual_band",
      "radio_profile_id": "radio_wlan0_wlan1",
      "interface": "wlan0",
      "declared_bands": ["2.4", "5"],
      "declared_channels": [1, 6, 11, 36, 40],
      "scan_time": 300
    },
    "expected_assessment_revision": 1
  }
  ```
* **Response Schema Version**: `"1.0"`
* **Response Payload**: `MeasurementPoint` object (`status: "active"`).
* **Audit Event**: `measurement_point_created`.
* **Error Codes**: `assessment_not_found`, `revision_conflict`, `storage_limit_exceeded`, `invalid_measurement_context`.

### 4.2 `list_measurement_points`
* **Version**: `v0.7.0`
* **Purpose**: Paginated list of MeasurementPoints for an Assessment.
* **Classification**: Read-only. Idempotent.
* **Request Schema**: `assessment_id` (str), `include_archived` (bool, default false), `limit` (int, default 50, max 100), `offset` (int, default 0).
* **Response Payload**: `{"schema_version": "1.0", "measurement_points": [...], "total": 1, "limit": 50, "offset": 0}`.

### 4.3 `get_measurement_point`
* **Version**: `v0.7.0`
* **Purpose**: Retrieves single MeasurementPoint details.
* **Classification**: Read-only. Idempotent.

### 4.4 `update_measurement_point`
* **Version**: `v0.7.0`
* **Purpose**: Updates MeasurementPoint metadata or context.
* **Classification**: Non-idempotent mutation.
* **Preconditions**: Point status is `active`. Archived points raise `measurement_point_archived`.
* **Request Parameters**: `expected_assessment_revision`, `expected_measurement_point_revision`.

### 4.5 `archive_measurement_point`
* **Version**: `v0.7.0`
* **Purpose**: Archives a MeasurementPoint (`status: "archived"`, `archived_at` set).
* **Classification**: Non-idempotent mutation.

### 4.6 `create_audit_run`
* **Version**: `v0.7.0`
* **Purpose**: Initializes a multi-point AuditRun.
* **Classification**: Non-idempotent mutation.
* **Preconditions**: Assessment exists; run count < 128; points exist and belong to same Assessment.
* **Request Schema**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "title": "Q3 Security Audit",
    "due_at": "2026-08-15T17:00:00Z",
    "pinned_assurance_profile_version_id": "assurance_v0001",
    "measurement_point_ids": ["mp_a1b2c3d4e5f67890"],
    "expected_assessment_revision": 2
  }
  ```
* **Persisted Status**: `draft`.
* **Derived Response Field**: `ready_to_start` (boolean; `true` when `measurement_point_ids` non-empty and AssuranceProfile valid). Not written to disk.

### 4.7 `list_audit_runs`
* **Version**: `v0.7.0`
* **Purpose**: Paginated list of AuditRuns for an Assessment.
* **Classification**: Read-only. Idempotent.

### 4.8 `get_audit_run`
* **Version**: `v0.7.0`
* **Purpose**: Retrieves AuditRun details, progress, and per-point measurements.
* **Classification**: Read-only. Idempotent.

### 4.9 `start_audit_run`
* **Version**: `v0.7.0`
* **Purpose**: Transitions AuditRun status `draft` → `in_progress`.
* **Classification**: Non-idempotent mutation.
* **Preconditions**: Validates all readiness requirements (`ready_to_start == true`) atomically. Raises `audit_run_not_ready` if invalid.

### 4.10 `cancel_audit_run`
* **Version**: `v0.7.0`
* **Purpose**: Cancels an in-progress AuditRun (`status: "cancelled"`).
* **Classification**: Non-idempotent mutation. Seals run against future measurements.

### 4.11 `resolve_audit_measurement`
* **Version**: `v0.7.0`
* **Purpose**: Receives raw Recon JSON in request body, resolves and persists normalized snapshot, pins snapshot ID and digest, and returns comparability preview.
* **Classification**: Non-idempotent mutation (`expected_assessment_revision`, `expected_audit_run_revision`).
* **Rule**: Raw Recon JSON is **never** persisted. Reuses existing `ReconNormalizer` and `AssessmentStore.save_snapshot()`.
* **State Transition**: `AuditRunMeasurement` status `pending` → `resolved`.

### 4.12 `retry_audit_measurement`
* **Version**: `v0.7.0`
* **Purpose**: Resets a `failed` measurement back to `pending` or `resolved` to allow re-trying resolution/comparison without abandoning the entire AuditRun.
* **Classification**: Non-idempotent mutation.

### 4.13 `save_audit_measurement_comparison`
* **Version**: `v0.7.0`
* **Purpose**: Executes baseline comparison for a point, pins exact contract digests, and saves occurrence set.
* **Classification**: Non-idempotent mutation (`expected_assessment_revision`, `expected_audit_run_revision`).
* **Rule**: Reuses existing `assurance_service.py` comparison engine. Suppressions are NOT evaluated in v0.7.0.
* **State Transition**: `AuditRunMeasurement` status `resolved` → `completed`.

### 4.14 `complete_audit_run`
* **Version**: `v0.7.0`
* **Purpose**: Seals an AuditRun (`status: "completed"`).
* **Classification**: Non-idempotent mutation.
* **Rule**: In v0.7.0, requires **all** required measurements to be in `completed` status. (No skip or partial completion in v0.7.0).

### 4.15 `generate_audit_run_report`
* **Version**: `v0.7.0`
* **Purpose**: Exports deterministic JSON or script-free HTML report for a completed AuditRun.
* **Classification**: Strictly read-only. Idempotent.
* **Rule**: MUST NOT write audit events, mutate files, or advance revisions. Repeated generation from the same sealed AuditRun produces byte-identical JSON/HTML output, identical `report_id` (`report_<16 hex>`), and identical `report_digest` (64 hex).

---

## 5. BackendError Code Registry

| Error Code | HTTP Equiv | Description |
|---|---|---|
| `invalid_measurement_point` | 400 | MeasurementPoint payload invalid |
| `measurement_point_not_found` | 404 | MeasurementPoint ID does not exist |
| `measurement_point_archived` | 409 | Attempted mutation on archived point |
| `invalid_audit_run` | 400 | AuditRun payload invalid |
| `audit_run_not_found` | 404 | AuditRun ID does not exist |
| `audit_run_not_ready` | 409 | `start_audit_run` called when `ready_to_start` is false |
| `audit_run_sealed` | 409 | Mutation attempted on sealed (`completed`/`cancelled`) run |
| `audit_run_cancelled` | 409 | Action rejected because run was cancelled |
| `invalid_audit_run_transition` | 409 | Illegal state transition for AuditRun |
| `audit_measurement_not_found` | 404 | Measurement ID does not exist |
| `invalid_audit_measurement_transition` | 409 | Illegal state transition for Measurement |
| `audit_measurement_not_resolved` | 409 | Comparison attempted before resolving snapshot |
| `audit_measurement_failed` | 409 | Attempted execution on failed measurement |
| `revision_conflict` | 409 | Stale `expected_..._revision` provided |
| `assessment_archived` | 409 | Assessment is archived |
| `cross_assessment_reference` | 400 | Reference belongs to different Assessment |
| `profile_version_not_found` | 404 | MeasurementProfile or AssuranceProfile version missing |
| `profile_digest_mismatch` | 409 | Profile digest does not match pinned value |
| `baseline_version_not_found` | 404 | Baseline version ID missing |
| `baseline_digest_mismatch` | 409 | Baseline digest does not match pinned value |
| `snapshot_not_found` | 404 | Snapshot ID missing |
| `snapshot_digest_mismatch` | 409 | Snapshot digest does not match pinned value |
| `comparison_digest_mismatch` | 409 | Comparison digest mismatch |
| `storage_limit_exceeded` | 409 | Assessment limits (64 points, 128 runs, 64 measurements) exceeded |
| `invalid_page_token` | 400 | Pagination token or offset invalid |
| `invalid_report_scope` | 400 | Report scope is invalid |
| `report_not_available` | 404 | Report requested for incomplete AuditRun |
