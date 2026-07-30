# PineAI v0.7.0 — Repeatable Field Audits Architecture Guide

## 1. Overview

PineAI `v0.7.0` introduces **Repeatable Field Audits**, extending the Customer Audit Foundation with multi-point offline wireless change auditing for the Hak5 WiFi Pineapple Mark VII.

### 1.1 Core Objectives
* **Repeatable Location Auditing**: Define physical or logical observation points (`MeasurementPoint`) inside a customer Assessment.
* **Multi-Point Audit Runs**: Group multiple MeasurementPoints into a structured `AuditRun` execution.
* **Per-Measurement Contract Pinning**: Pin exact, immutable version IDs and SHA-256 digests (`MeasurementProfile`, baseline, `AssuranceProfile`) per observation point.
* **Strict Scope Boundaries**: PineAI operates exclusively as an offline read-only analysis layer over operator-selected saved Recon observations.

---

## 2. Scope & Non-Negotiable Boundaries

PineAI MUST NOT contain or expose:
1. WiFi Pineapple Campaign creation, editing, enabling, disabling, or scheduling controls.
2. Scan start/stop controls or radio configuration.
3. Deauthentication, rogue AP, evil twin, or attack script generation capabilities.
4. Duplication of Hak5 Campaign JSON/HTML reporting formats.
5. Persistence of raw Hak5 Recon JSON payloads. Raw Recon payloads are resolved in memory, normalized, and persisted strictly as immutable snapshots (`snapshot_<16 hex>`).

---

## 3. Domain Model Architecture

```text
               ┌─────────────────────────────────────────────────┐
               │           Assessment (Site / Environment)        │
               │        assessment_a1b2c3d4-e5f6-4789-a1b2...   │
               └───────────────┬─────────────────┬───────────────┘
                               │ 1               │ 1
                               │                 │
                               ▼ *               ▼ *
     ┌───────────────────────────────┐ ┌────────────────────────────────┐
     │       MeasurementPoint        │ │            AuditRun            │
     │      mp_a1b2c3d4e5f67890      │ │      ar_0123456789abcdef       │
     │ (location, context, active)   │ │  (status: draft/in_progress/   │
     └───────────────┬───────────────┘ │   completed/cancelled, due_at) │
                     │                 └───────────────┬────────────────┘
                     │ 1                               │ 1
                     │                                 │
                     └─────────────────┬───────────────┘
                                       │ *
                                       ▼
                       ┌───────────────────────────────┐
                       │     AuditRunMeasurement       │
                       │     arm_0123456789abcdef      │
                       │ (pinned baseline & profiles,  │
                       │  snapshot, comparison, occ)   │
                       └───────────────────────────────┘
```

---

## 4. State Machines

### 4.1 MeasurementPoint State Machine
```text
(created) ──► active ──(archive_measurement_point)──► archived
```
* Archived points remain readable but cannot be added to new AuditRuns.

### 4.2 AuditRun State Machine (v0.7.0)
```text
(create_audit_run) ──► draft ──(start_audit_run)──► in_progress ──(complete_audit_run)──► completed
                         │                              │
                         └──────(cancel_audit_run)──────┴──► cancelled
```
* `ready_to_start` is a derived API response field (`true` when `measurement_point_ids` non-empty and AssuranceProfile valid). It is **not** written to disk files.
* `complete_audit_run` in v0.7.0 requires **all** required measurements to be in `completed` status. (Skip and partial completion deferred to v0.7.1).
* Terminal runs (`completed`, `cancelled`) are sealed and immutable.

### 4.3 AuditRunMeasurement State Machine (v0.7.0)
```text
pending ──(resolve_audit_measurement)──► resolved ──(save_comparison)──► completed
   ▲                                        ▲    │
   │   failed_stage=resolution              │    │
   └──────(retry_audit_measurement)─────────┤    └──(failure)──► failed
                                            │                      │
                                            │ failed_stage=comp.   │
                                            └─(retry_measurement)──┘
```
* **Deterministic Retry Paths**:
  * `failed_stage == "resolution"`: `retry_audit_measurement` transitions `failed` → `pending` (resets snapshot resolution & clears error fields).
  * `failed_stage == "comparison"`: `retry_audit_measurement` transitions `failed` → `resolved` (retains snapshot and contract pins, resets comparison & clears error fields).
* **Comparability** (`comparable`, `partially_comparable`, `not_comparable`) is stored as a separate result field. A `not_comparable` result stores diagnostic comparison details without generating findings.

---

## 5. Storage Layout & Backup Integration

All v0.7.0 audit run records are stored strictly under the assessment runtime directory:

```text
/root/.PineAI/assessments/<assessment_id>/
  ├── audit_runs/
  │     └── <audit_run_id>.json
  ├── measurement_points.json
  └── events.jsonl
```

* **Permissions**: Directory `0700` (`drwx------`), files `0600` (`-rw-------`).
* **Zero Backup Production Code Changes**: The existing `backup.py` implementation recursively includes all subdirectories under `/root/.PineAI/assessments/`. Storing `audit_runs/` and `measurement_points.json` under assessment directories requires **zero changes to production backup code**.

---

## 6. Formal Hardware Validation Gate

> [!NOTE]
> **Hardware Validation Status**: Automated unit testing (140 Python, 26 Angular), static analysis, and local-adapter correctness gates are complete for commit `1e77e18670c49c0fca3ecb809fbc08b0f6235222` (`v0.6.3`). Physical WiFi Pineapple Mark VII validation remains explicitly **pending**.
> The user has formally authorized contract design for `v0.7.0` to proceed prior to physical device testing. This authorization does not mark `v0.6.3` as hardware-validated. Any hardware defect discovered later will be addressed separately without altering the `v0.6.3` release candidate artifact.
