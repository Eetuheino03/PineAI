# PineAI v0.7.0 — Repeatable Field Audits API Contract Specification

This document defines the formal, frozen API module action contract for **PineAI v0.7.0 — Repeatable Field Audits**.

> [!IMPORTANT]
> **Pre-Implementation Contract Gate**: This specification is a mandatory contract freeze. No backend Python service code or frontend Angular component code may be implemented until this API contract document and its associated JSON Schemas are approved.

---

## 1. Core Architectural & Protocol Rules

### 1.1 Identity Formats & Patterns
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

**Proposed v0.7.0 Identifier Regex Patterns**:
* `MEASUREMENT_POINT_ID_PATTERN = r"^mp_[0-9a-f]{16}$"`
* `AUDIT_RUN_ID_PATTERN = r"^ar_[0-9a-f]{16}$"`
* `AUDIT_RUN_MEASUREMENT_ID_PATTERN = r"^arm_[0-9a-f]{16}$"`
* `AUDIT_RUN_REPORT_ID_PATTERN = r"^report_[0-9a-f]{16}$"`

**Digest Rule**: Digests are strictly 64 lowercase hex characters (SHA-256). Prefixes such as `sha256_` are prohibited.

### 1.2 MeasurementPoint ID Ownership Model
* The server generates `measurement_point_id` (`mp_<16 hex>`).
* In `createMeasurementPointRequest`, the client provides `expected_measurement_context` WITHOUT `measurement_point_id`.
* Upon generation, the server populates `measurement_point_id` inside both `measurement_point.measurement_point_id` and `measurement_point.expected_measurement_context.measurement_point_id`.

### 1.3 Retry Semantics (`retry_audit_measurement`)
* If `failed_stage == "resolution"`:
  * Resets measurement `status` to `pending`.
  * Clears `snapshot_id`, `snapshot_digest`, and error fields (`failed_stage`, `error_code`, `error_message`, `failed_at`, `retry_target`).
* If `failed_stage == "comparison"`:
  * Resets measurement `status` to `resolved`.
  * Retains snapshot ID/digest and profile pins. Clears comparison ID/digest, occurrence set ID, and error fields.
* Emits audit event `audit_measurement_retried`.

### 1.4 Deterministic Canonical AuditRun Reporting & Digest Algorithm
1. `generate_audit_run_report` is available ONLY when AuditRun status is `completed`.
2. Build canonical report facts WITHOUT `report_id` and `report_digest`.
3. Set `generated_at` equal to the sealed AuditRun's `completed_at` timestamp (normalized UTC ending in `Z`).
4. Canonical JSON encoding: UTF-8, keys lexicographically sorted, no extra whitespace (`separators=(',', ':')`).
5. Compute SHA-256 lowercase hex of canonical JSON byte stream as `report_digest`.
6. Derive `report_id = "report_" + report_digest[:16]`.
7. Insert `report_id` and `report_digest` into the response wrapper.
8. Script-free HTML is rendered deterministically from canonical report facts with stable section/row ordering.

### 1.5 Pagination Strategy
All list actions use offset pagination:
* Primary sort key: `created_at` descending; tie-break sort key: entity ID ascending.
* Parameters: `limit` (integer 1..100, default 50), `offset` (integer >= 0, default 0).
* Response fields: `total` (int), `limit` (int), `offset` (int), `has_more` (bool).
* Invalid offset or negative values raise `invalid_page_token`.

### 1.6 Privacy Profile Contract Evolution
* **v0.7.0 AuditRun Reports**: Use privacy profiles `internal_full`, `share_safe`, and `pseudonymized`.
* **Intentional Successor**: `internal_full` is the explicit AuditRun-report successor to legacy v0.6.3 `local_full`.
* **Backward Compatibility**: Existing v0.6.3 comparison and assessment reports remain unchanged and continue accepting `local_full` and `share_safe`.
* **Non-Interchangeable Scopes**: `internal_full` and `local_full` are bound to their respective schema versions and must not be treated as interchangeable outside their report schemas. No automatic rewriting of stored report facts or historical request parameters occurs.

---

## 2. Complete Module Action Contracts (v0.7.0)

### 2.1 `create_measurement_point`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "name": "Floor 2 West Wing",
    "description": "Primary office workspace",
    "expected_measurement_context": {
      "location_id": "loc_site_alpha",
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
* **Request Schema Reference**: `#/$defs/createMeasurementPointRequest`
* **Response JSON Example**:
  ```json
  {
    "schema_version": "1.0",
    "measurement_point": {
      "measurement_point_id": "mp_a1b2c3d4e5f67890",
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
      "status": "active",
      "created_at": "2026-07-30T09:00:00Z",
      "archived_at": null,
      "revision": 1
    }
  }
  ```
* **Response Schema Reference**: `#/$defs/createMeasurementPointResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `name`, `expected_measurement_context`, `expected_assessment_revision`. Optional: `description`.
* **Exact Revision Fields**: `expected_assessment_revision`.
* **Preconditions**: Assessment exists and is not archived; active MeasurementPoint count < 64.
* **Allowed State Transitions**: Creates point in `active` state.
* **Exact Revisions Advanced**: Assessment revision +1; new MeasurementPoint revision set to 1.
* **Ordered Files Written**: 1. `measurement_points.json.staged`, 2. Atomic rename to `measurement_points.json`.
* **Transaction Journal Entries**: `STAGE_MEASUREMENT_POINTS`, `COMMIT_MEASUREMENT_POINTS`.
* **Recovery Behavior**: If interrupted before commit, staged file is removed or rolled forward on next operation.
* **Exact Audit Event**: `measurement_point_created`
* **Audit Event Payload**: `{"event_id": "evt_...", "event_type": "measurement_point_created", "assessment_id": "...", "measurement_point_id": "mp_a1b2c3d4e5f67890", "timestamp": "2026-07-30T09:00:00Z"}`
* **Error Codes**: `assessment_not_found`, `assessment_archived`, `revision_conflict`, `storage_limit_exceeded`, `invalid_measurement_point`.
* **Sealed & Archived Object Behavior**: Cannot create points under archived assessments.
* **Sorting & Pagination**: N/A for create.

---

### 2.2 `list_measurement_points`
* **Version**: `v0.7.0`
* **Classification**: Read-only. Idempotent.
* **Request JSON Example**: `{"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890", "include_archived": false, "limit": 50, "offset": 0}`
* **Request Schema Reference**: `#/$defs/listMeasurementPointsRequest`
* **Response JSON Example**:
  ```json
  {
    "schema_version": "1.0",
    "measurement_points": [],
    "total": 0,
    "limit": 50,
    "offset": 0,
    "has_more": false
  }
  ```
* **Response Schema Reference**: `#/$defs/listMeasurementPointsResponse`
* **Required & Optional Fields**: Required: `assessment_id`. Optional: `include_archived`, `limit`, `offset`.
* **Exact Revision Fields**: None (read-only).
* **Preconditions**: Assessment exists.
* **Allowed State Transitions**: None.
* **Exact Revisions Advanced**: None.
* **Ordered Files Written**: None.
* **Transaction Journal Entries**: None.
* **Recovery Behavior**: N/A.
* **Exact Audit Event**: None.
* **Audit Event Payload**: None.
* **Error Codes**: `assessment_not_found`, `invalid_page_token`.
* **Sealed & Archived Object Behavior**: Archived points included only when `include_archived=true`.
* **Sorting & Pagination**: Primary sort `created_at` DESC, tie-break `measurement_point_id` ASC. Offset pagination.

---

### 2.3 `get_measurement_point`
* **Version**: `v0.7.0`
* **Classification**: Read-only. Idempotent.
* **Request JSON Example**: `{"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890", "measurement_point_id": "mp_a1b2c3d4e5f67890"}`
* **Request Schema Reference**: `#/$defs/getMeasurementPointRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "measurement_point": {...}}`
* **Response Schema Reference**: `#/$defs/getMeasurementPointResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `measurement_point_id`.
* **Exact Revision Fields**: None.
* **Preconditions**: Point exists under assessment.
* **Allowed State Transitions**: None.
* **Exact Revisions Advanced**: None.
* **Ordered Files Written**: None.
* **Transaction Journal Entries**: None.
* **Recovery Behavior**: N/A.
* **Exact Audit Event**: None.
* **Audit Event Payload**: None.
* **Error Codes**: `assessment_not_found`, `measurement_point_not_found`.
* **Sealed & Archived Object Behavior**: Archived points are readable.
* **Sorting & Pagination**: N/A.

---

### 2.4 `update_measurement_point`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "measurement_point_id": "mp_a1b2c3d4e5f67890",
    "name": "Floor 2 West Wing (Renamed)",
    "expected_assessment_revision": 1,
    "expected_measurement_point_revision": 1
  }
  ```
* **Request Schema Reference**: `#/$defs/updateMeasurementPointRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "measurement_point": {...}}`
* **Response Schema Reference**: `#/$defs/updateMeasurementPointResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `measurement_point_id`, `expected_assessment_revision`, `expected_measurement_point_revision`. Optional: `name`, `description`, `expected_measurement_context`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_measurement_point_revision`.
* **Preconditions**: Point exists and `status == "active"`. Revisions match.
* **Allowed State Transitions**: Remains `active`.
* **Exact Revisions Advanced**: Assessment revision +1; MeasurementPoint revision +1.
* **Ordered Files Written**: Atomic write to `measurement_points.json`.
* **Transaction Journal Entries**: `STAGE_MEASUREMENT_POINTS`, `COMMIT_MEASUREMENT_POINTS`.
* **Recovery Behavior**: Atomic file write roll-forward.
* **Exact Audit Event**: `measurement_point_updated`
* **Audit Event Payload**: `{"event_type": "measurement_point_updated", "measurement_point_id": "mp_a1b2c3d4e5f67890"}`
* **Error Codes**: `assessment_not_found`, `measurement_point_not_found`, `measurement_point_archived`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Raises `measurement_point_archived` if point is archived.
* **Sorting & Pagination**: N/A.

---

### 2.5 `archive_measurement_point`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "measurement_point_id": "mp_a1b2c3d4e5f67890",
    "expected_assessment_revision": 2,
    "expected_measurement_point_revision": 2
  }
  ```
* **Request Schema Reference**: `#/$defs/archiveMeasurementPointRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "measurement_point": {... "status": "archived", "archived_at": "2026-07-30T09:10:00Z"}}`
* **Response Schema Reference**: `#/$defs/archiveMeasurementPointResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `measurement_point_id`, `expected_assessment_revision`, `expected_measurement_point_revision`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_measurement_point_revision`.
* **Preconditions**: Point is `active`. Revisions match.
* **Allowed State Transitions**: `active` → `archived`.
* **Exact Revisions Advanced**: Assessment revision +1; MeasurementPoint revision +1.
* **Ordered Files Written**: Atomic write to `measurement_points.json`.
* **Transaction Journal Entries**: `STAGE_MEASUREMENT_POINTS`, `COMMIT_MEASUREMENT_POINTS`.
* **Recovery Behavior**: Atomic file write.
* **Exact Audit Event**: `measurement_point_archived`
* **Audit Event Payload**: `{"event_type": "measurement_point_archived", "measurement_point_id": "mp_a1b2c3d4e5f67890"}`
* **Error Codes**: `assessment_not_found`, `measurement_point_not_found`, `measurement_point_archived`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Re-archiving an archived point raises `measurement_point_archived`.
* **Sorting & Pagination**: N/A.

---

### 2.6 `create_audit_run`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "title": "Q3 Wireless Security Audit",
    "due_at": "2026-08-15T17:00:00Z",
    "pinned_assurance_profile_version_id": "assurance_v0001",
    "measurement_point_ids": ["mp_a1b2c3d4e5f67890"],
    "expected_assessment_revision": 3
  }
  ```
* **Request Schema Reference**: `#/$defs/createAuditRunRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "audit_run": {... "status": "draft"}, "ready_to_start": true}`
* **Response Schema Reference**: `#/$defs/createAuditRunResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `title`, `pinned_assurance_profile_version_id`, `measurement_point_ids`, `expected_assessment_revision`. Optional: `due_at`.
* **Exact Revision Fields**: `expected_assessment_revision`.
* **Preconditions**: Assessment exists; run count < 128; points exist and belong to same Assessment; AssuranceProfile version exists.
* **Allowed State Transitions**: Creates run in `draft` state. Initial measurement status for each point set to `pending`.
* **Exact Revisions Advanced**: Assessment revision +1; AuditRun revision set to 1.
* **Ordered Files Written**: `audit_runs/<audit_run_id>.json`.
* **Transaction Journal Entries**: `STAGE_AUDIT_RUN`, `COMMIT_AUDIT_RUN`.
* **Recovery Behavior**: Staged write roll-forward.
* **Exact Audit Event**: `audit_run_created`
* **Audit Event Payload**: `{"event_type": "audit_run_created", "audit_run_id": "ar_0123456789abcdef"}`
* **Error Codes**: `assessment_not_found`, `measurement_point_not_found`, `profile_version_not_found`, `storage_limit_exceeded`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: N/A for create.
* **Sorting & Pagination**: N/A.

---

### 2.7 `list_audit_runs`
* **Version**: `v0.7.0`
* **Classification**: Read-only. Idempotent.
* **Request JSON Example**: `{"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890", "limit": 50, "offset": 0}`
* **Request Schema Reference**: `#/$defs/listAuditRunsRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "audit_runs": [{"audit_run": {...}, "ready_to_start": true}], "total": 1, "limit": 50, "offset": 0, "has_more": false}`
* **Response Schema Reference**: `#/$defs/listAuditRunsResponse`
* **Required & Optional Fields**: Required: `assessment_id`. Optional: `limit`, `offset`.
* **Exact Revision Fields**: None.
* **Preconditions**: Assessment exists.
* **Allowed State Transitions**: None.
* **Exact Revisions Advanced**: None.
* **Ordered Files Written**: None.
* **Transaction Journal Entries**: None.
* **Recovery Behavior**: N/A.
* **Exact Audit Event**: None.
* **Audit Event Payload**: None.
* **Error Codes**: `assessment_not_found`, `invalid_page_token`.
* **Sealed & Archived Object Behavior**: Lists all runs including completed/cancelled.
* **Sorting & Pagination**: Primary sort `created_at` DESC, tie-break `audit_run_id` ASC. Offset pagination.

---

### 2.8 `get_audit_run`
* **Version**: `v0.7.0`
* **Classification**: Read-only. Idempotent.
* **Request JSON Example**: `{"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890", "audit_run_id": "ar_0123456789abcdef"}`
* **Request Schema Reference**: `#/$defs/getAuditRunRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "audit_run": {...}, "ready_to_start": true, "measurements": [...]}`
* **Response Schema Reference**: `#/$defs/getAuditRunResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`.
* **Exact Revision Fields**: None.
* **Preconditions**: AuditRun exists.
* **Allowed State Transitions**: None.
* **Exact Revisions Advanced**: None.
* **Ordered Files Written**: None.
* **Transaction Journal Entries**: None.
* **Recovery Behavior**: N/A.
* **Exact Audit Event**: None.
* **Audit Event Payload**: None.
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`.
* **Sealed & Archived Object Behavior**: All runs readable.
* **Sorting & Pagination**: N/A.

---

### 2.9 `start_audit_run`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "audit_run_id": "ar_0123456789abcdef",
    "expected_assessment_revision": 4,
    "expected_audit_run_revision": 1
  }
  ```
* **Request Schema Reference**: `#/$defs/startAuditRunRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "audit_run": {... "status": "in_progress", "started_at": "2026-07-30T09:15:00Z"}}`
* **Response Schema Reference**: `#/$defs/startAuditRunResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`, `expected_assessment_revision`, `expected_audit_run_revision`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_audit_run_revision`.
* **Preconditions**: AuditRun status == `draft`; `ready_to_start == true`. Revisions match.
* **Allowed State Transitions**: `draft` → `in_progress`.
* **Exact Revisions Advanced**: Assessment revision +1; AuditRun revision +1.
* **Ordered Files Written**: Atomic update to `audit_runs/<audit_run_id>.json`.
* **Transaction Journal Entries**: `STAGE_AUDIT_RUN`, `COMMIT_AUDIT_RUN`.
* **Recovery Behavior**: Atomic file write.
* **Exact Audit Event**: `audit_run_started`
* **Audit Event Payload**: `{"event_type": "audit_run_started", "audit_run_id": "ar_0123456789abcdef"}`
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`, `audit_run_not_ready`, `invalid_audit_run_transition`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Sealed/cancelled runs raise `audit_run_sealed`.
* **Sorting & Pagination**: N/A.

---

### 2.10 `cancel_audit_run`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "audit_run_id": "ar_0123456789abcdef",
    "reason": "Operator aborted audit",
    "expected_assessment_revision": 5,
    "expected_audit_run_revision": 2
  }
  ```
* **Request Schema Reference**: `#/$defs/cancelAuditRunRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "audit_run": {... "status": "cancelled"}}`
* **Response Schema Reference**: `#/$defs/cancelAuditRunResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`, `expected_assessment_revision`, `expected_audit_run_revision`. Optional: `reason`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_audit_run_revision`.
* **Preconditions**: AuditRun status is `draft` or `in_progress`. Revisions match.
* **Allowed State Transitions**: `draft` / `in_progress` → `cancelled`. Seals run against further measurements.
* **Exact Revisions Advanced**: Assessment revision +1; AuditRun revision +1.
* **Ordered Files Written**: Atomic update to `audit_runs/<audit_run_id>.json`.
* **Transaction Journal Entries**: `STAGE_AUDIT_RUN`, `COMMIT_AUDIT_RUN`.
* **Recovery Behavior**: Atomic file write.
* **Exact Audit Event**: `audit_run_cancelled`
* **Audit Event Payload**: `{"event_type": "audit_run_cancelled", "audit_run_id": "ar_0123456789abcdef", "reason": "Operator aborted audit"}`
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`, `audit_run_sealed`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Re-cancelling raises `audit_run_sealed`.
* **Sorting & Pagination**: N/A.

---

### 2.11 `resolve_audit_measurement`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "audit_run_id": "ar_0123456789abcdef",
    "measurement_point_id": "mp_a1b2c3d4e5f67890",
    "raw_recon_json": { "AccessPointResults": [] },
    "measurement_profile_id": "mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "baseline_version_id": "baseline_v0001",
    "expected_assessment_revision": 6,
    "expected_audit_run_revision": 3
  }
  ```
* **Request Schema Reference**: `#/$defs/resolveAuditMeasurementRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "measurement": {... "status": "resolved", "snapshot_id": "snapshot_a1b2c3d4e5f67890"}}`
* **Response Schema Reference**: `#/$defs/resolveAuditMeasurementResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`, `measurement_point_id`, `raw_recon_json`, `measurement_profile_id`, `baseline_version_id`, `expected_assessment_revision`, `expected_audit_run_revision`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_audit_run_revision`.
* **Preconditions**: AuditRun status == `in_progress`; point measurement status == `pending`; raw Recon valid.
* **Allowed State Transitions**: Point measurement status `pending` → `resolved`.
* **Exact Revisions Advanced**: Assessment revision +1; AuditRun revision +1.
* **Ordered Files Written**: 1. `snapshots/<snapshot_id>.json`, 2. `audit_runs/<audit_run_id>.json`.
* **Transaction Journal Entries**: `SAVE_SNAPSHOT`, `UPDATE_MEASUREMENT`.
* **Recovery Behavior**: Snapshot atomic save + staged audit run write roll-forward.
* **Exact Audit Event**: `audit_measurement_resolved`
* **Audit Event Payload**: `{"event_type": "audit_measurement_resolved", "snapshot_id": "snapshot_a1b2c3d4e5f67890"}`
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`, `audit_run_sealed`, `invalid_recon`, `profile_version_not_found`, `baseline_version_not_found`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Raises `audit_run_sealed` if run is not `in_progress`.
* **Sorting & Pagination**: N/A.

---

### 2.12 `retry_audit_measurement`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "audit_run_id": "ar_0123456789abcdef",
    "measurement_point_id": "mp_a1b2c3d4e5f67890",
    "expected_assessment_revision": 7,
    "expected_audit_run_revision": 4
  }
  ```
* **Request Schema Reference**: `#/$defs/retryAuditMeasurementRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "measurement": {... "status": "pending"}}`
* **Response Schema Reference**: `#/$defs/retryAuditMeasurementResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`, `measurement_point_id`, `expected_assessment_revision`, `expected_audit_run_revision`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_audit_run_revision`.
* **Preconditions**: AuditRun status == `in_progress`; point measurement status == `failed`.
* **Allowed State Transitions**: `failed` → `pending` (if `failed_stage == "resolution"`) OR `failed` → `resolved` (if `failed_stage == "comparison"`).
* **Exact Revisions Advanced**: Assessment revision +1; AuditRun revision +1.
* **Ordered Files Written**: Atomic update to `audit_runs/<audit_run_id>.json`.
* **Transaction Journal Entries**: `STAGE_AUDIT_RUN`, `COMMIT_AUDIT_RUN`.
* **Recovery Behavior**: Atomic file write.
* **Exact Audit Event**: `audit_measurement_retried`
* **Audit Event Payload**: `{"event_type": "audit_measurement_retried", "measurement_point_id": "mp_a1b2c3d4e5f67890"}`
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`, `audit_measurement_not_found`, `invalid_audit_measurement_transition`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Raises `audit_run_sealed` if run is sealed.
* **Sorting & Pagination**: N/A.

---

### 2.13 `save_audit_measurement_comparison`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "audit_run_id": "ar_0123456789abcdef",
    "measurement_point_id": "mp_a1b2c3d4e5f67890",
    "expected_assessment_revision": 8,
    "expected_audit_run_revision": 5
  }
  ```
* **Request Schema Reference**: `#/$defs/saveAuditMeasurementComparisonRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "measurement": {... "status": "completed", "comparison_id": "comparison_0123456789abcdef"}}`
* **Response Schema Reference**: `#/$defs/saveAuditMeasurementComparisonResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`, `measurement_point_id`, `expected_assessment_revision`, `expected_audit_run_revision`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_audit_run_revision`.
* **Preconditions**: AuditRun status == `in_progress`; point measurement status == `resolved`.
* **Allowed State Transitions**: `resolved` → `completed`.
* **Exact Revisions Advanced**: Assessment revision +1; AuditRun revision +1.
* **Ordered Files Written**: 1. `comparisons/<comparison_id>.json`, 2. `occurrences/<occurrence_set_id>.json`, 3. `audit_runs/<audit_run_id>.json`.
* **Transaction Journal Entries**: `SAVE_COMPARISON`, `SAVE_OCCURRENCES`, `UPDATE_MEASUREMENT`.
* **Recovery Behavior**: Multi-document journal roll-forward.
* **Exact Audit Event**: `audit_measurement_completed`
* **Audit Event Payload**: `{"event_type": "audit_measurement_completed", "comparison_id": "comparison_0123456789abcdef"}`
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`, `audit_measurement_not_resolved`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Raises `audit_run_sealed` if run is sealed.
* **Sorting & Pagination**: N/A.

---

### 2.14 `complete_audit_run`
* **Version**: `v0.7.0`
* **Classification**: Non-idempotent mutation.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "audit_run_id": "ar_0123456789abcdef",
    "expected_assessment_revision": 9,
    "expected_audit_run_revision": 6
  }
  ```
* **Request Schema Reference**: `#/$defs/completeAuditRunRequest`
* **Response JSON Example**: `{"schema_version": "1.0", "audit_run": {... "status": "completed", "completed_at": "2026-07-30T09:30:00Z"}}`
* **Response Schema Reference**: `#/$defs/completeAuditRunResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`, `expected_assessment_revision`, `expected_audit_run_revision`.
* **Exact Revision Fields**: `expected_assessment_revision`, `expected_audit_run_revision`.
* **Preconditions**: AuditRun status == `in_progress`; EVERY required measurement point status == `completed`.
* **Allowed State Transitions**: `in_progress` → `completed`. Seals run against further changes.
* **Exact Revisions Advanced**: Assessment revision +1; AuditRun revision +1.
* **Ordered Files Written**: Atomic update to `audit_runs/<audit_run_id>.json`.
* **Transaction Journal Entries**: `STAGE_AUDIT_RUN`, `COMMIT_AUDIT_RUN`.
* **Recovery Behavior**: Atomic file write.
* **Exact Audit Event**: `audit_run_completed`
* **Audit Event Payload**: `{"event_type": "audit_run_completed", "audit_run_id": "ar_0123456789abcdef"}`
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`, `invalid_audit_run_transition`, `revision_conflict`.
* **Sealed & Archived Object Behavior**: Raises `audit_run_sealed` if already completed or cancelled.
* **Sorting & Pagination**: N/A.

---

### 2.15 `generate_audit_run_report`
* **Version**: `v0.7.0`
* **Classification**: Strictly read-only. Idempotent.
* **Request JSON Example**:
  ```json
  {
    "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
    "audit_run_id": "ar_0123456789abcdef",
    "format": "json",
    "privacy_profile": "share_safe"
  }
  ```
* **Request Schema Reference**: `#/$defs/generateAuditRunReportRequest`
* **Response JSON Example**:
  ```json
  {
    "schema_version": "1.0",
    "report_id": "report_0123456789abcdef",
    "format": "json",
    "filename": "audit-run-report-ar_0123456789abcdef.json",
    "mime_type": "application/json",
    "sha256_checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "content": "{\"assessment_id\":...}"
  }
  ```
* **Response Schema Reference**: `#/$defs/generateAuditRunReportResponse`
* **Required & Optional Fields**: Required: `assessment_id`, `audit_run_id`, `format`. Optional: `privacy_profile`.
* **Exact Revision Fields**: None (read-only).
* **Preconditions**: AuditRun status == `completed`.
* **Allowed State Transitions**: None.
* **Exact Revisions Advanced**: None.
* **Ordered Files Written**: Zero (strictly read-only export).
* **Transaction Journal Entries**: None.
* **Recovery Behavior**: N/A.
* **Exact Audit Event**: None (read-only action).
* **Audit Event Payload**: None.
* **Error Codes**: `assessment_not_found`, `audit_run_not_found`, `report_not_available`, `invalid_report_format`.
* **Sealed & Archived Object Behavior**: Only available for completed (sealed) AuditRuns.
* **Sorting & Pagination**: Array elements in report JSON are sorted lexicographically by point ID / evidence ID.
