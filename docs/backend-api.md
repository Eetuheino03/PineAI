# Baseline & Drift backend API

This document defines the PineAI `0.6.3` module contract. The corresponding
machine-readable definitions are in
[`baseline-drift-v1.schema.json`](schemas/baseline-drift-v1.schema.json).

All module requests include `"module": "PineAI"` in the Hak5 envelope. The
examples below show only action-specific fields. Assessment, settings,
finding, AI, and report records retain schema version `"1.0"`. Resolved
snapshots, deterministic comparisons, capability metadata, and their response
wrappers use assurance schema version `"1.1"`. The schema file accepts stored
assurance `"1.0"` records for backward-compatible reads.

## Common behavior

- Mutations require `expected_revision`.
- A stale revision returns `revision_conflict`; the client must refresh and
  obtain a new explicit confirmation before retrying.
- IDs returned by the backend are opaque. The frontend must not construct
  assessment, baseline, snapshot, evidence, comparison, or finding IDs.
- Times are UTC RFC 3339 strings.
- Wireless strings and local notes are untrusted data.
- Backend errors are safe to display:

```json
{
  "error": {
    "code": "assessment_not_found",
    "message": "Assessment was not found."
  }
}
```

The backend does not persist raw Hak5 Recon JSON and does not call the Hak5
REST API.

## Read-only platform actions

### `health`

Returns runtime state without secrets or stored identifiers:

```json
{
  "status": "ok",
  "module": "PineAI",
  "version": "0.6.3",
  "backend_version": "0.6.3",
  "product_mode": "customer_audit_foundation",
  "offline_complete": true,
  "model": "gpt-5.6-terra",
  "api_key_configured": false,
  "language": "en",
  "share_ssids": false,
  "recon_control": false
}
```

### `assurance_capabilities`

Takes no action-specific fields. It returns the comparability and finding
states, the authoritative eight-rule registry, storage limits, authoritative
field names, public module actions, the non-authoritative AI role, and
`offline_complete:true`. It reports `schema_version:"1.2"` and
`backend_version:"0.6.3"`.

Clients should render registry metadata but must continue to treat returned
finding severity and confidence as authoritative per-analysis values.

## Assessment actions

An assessment represents one wireless environment or location.

### `create_assessment`

Request:

```json
{
  "assessment": {
    "name": "Factory wireless assurance",
    "location": "Plant A",
    "notes": "Local-only operator notes"
  }
}
```

Response:

```json
{
  "schema_version": "1.0",
  "assessment_id": "assessment_...",
  "name": "Factory wireless assurance",
  "location": "Plant A",
  "notes": "Local-only operator notes",
  "status": "active",
  "revision": 1,
  "active_baseline_version": null,
  "created_at": "2026-07-27T16:00:00Z",
  "updated_at": "2026-07-27T16:00:00Z",
  "last_event_sequence": 1,
  "events": [
    {
      "sequence": 1,
      "event_id": "evt_...",
      "event_type": "assessment_created",
      "recorded_at": "2026-07-27T16:00:00Z",
      "revision": 1
    }
  ]
}
```

### `get_assessment`

Request:

```json
{
  "assessment_id": "assessment_...",
  "after_sequence": 0,
  "limit": 100
}
```

Returns assessment metadata plus `events`, `events_has_more`,
`baseline_versions`, comparison summaries, and `finding_summary`. Event
payloads are structured and do not contain raw Recon data.

### `list_assessments`

Request:

```json
{
  "include_archived": false
}
```

Response:

```json
{
  "schema_version": "1.0",
  "assessments": []
}
```

### `update_assessment`

Request:

```json
{
  "assessment_id": "assessment_...",
  "expected_revision": 1,
  "changes": {
    "name": "Factory A wireless assurance",
    "location": "Plant A",
    "notes": "Local-only operator notes"
  }
}
```

Only `name`, `location`, and `notes` are editable. The response is the updated
assessment metadata with the new event in `events`.

### `archive_assessment`

Request:

```json
{
  "assessment_id": "assessment_...",
  "expected_revision": 2
}
```

The response is archived assessment metadata with the new event in `events`.
Archiving is irreversible through the `0.6.3` public API. Archived assessments
remain readable. They cannot create or activate baselines, compare or persist
new Recon analyses, or update finding state. Existing stored comparisons remain
available for deterministic JSON/HTML report export and optional read-only AI
explanation.

## Asset & Change Resolver

### `resolve_recon`

This read-only action validates and normalizes an in-memory Hak5 Recon result.

Request:

```json
{
  "scan": {
    "APResults": [],
    "OutOfRangeClientResults": [],
    "UnassociatedClientResults": []
  },
  "scan_metadata": {
    "scan_id": "frontend-local-reference",
    "date": "2026-07-27T16:00:00Z",
    "started_at": "2026-07-27T15:55:00Z",
    "completed_at": "2026-07-27T16:00:00Z",
    "scan_time": 300,
    "coverage": ["2.4"],
    "source": "hak5_recon",
    "label": "Office sweep",
    "measurement_context": {
      "location_id": "plant-a",
      "measurement_point_id": "north-wall",
      "scan_profile_id": "full-sweep-v1",
      "radio_profile_id": "mk7-radio-a",
      "interface": "wlan1mon",
      "declared_channels": [1, 6, 11]
    }
  }
}
```

The documented `OutOfRangeResult` / `OutOfRangeClientResults` and
`UnassociatedResult` / `UnassociatedClientResults` aliases are accepted by
normalization.

For scan metadata, `id` is accepted as an alias of `scan_id` and `duration` as
an alias of `scan_time`. Duration is 1–86400 seconds. Explicit fields take
precedence over aliases.

Measurement context may use the nested `measurement_context` object shown
above or the legacy direct context fields, but never both in one request.
Unknown context fields and mixed forms return `invalid_scan_metadata`.
`declared_bands` inside measurement context supplies declared coverage only
when top-level `coverage` is absent; top-level `coverage` takes precedence.

The response is a resolved snapshot containing:

- response and snapshot `schema_version:"1.1"`;
- `snapshot_id`, `snapshot_digest`, and nullable `observed_at`;
- normalized `scan_metadata`;
- a `comparability_profile`;
- AP, SSID-network, and client-count summary;
- local access-point and network records;
- stable evidence IDs.

Real BSSIDs and SSIDs are local fields. The response is never a cloud payload.
Hidden networks are represented as distinct BSSID-scoped networks.

## Baseline actions

Baseline versions are immutable. Creating one and activating one are always
separate operations.

### `create_baseline_version`

Request:

```json
{
  "assessment_id": "assessment_...",
  "expected_revision": 1,
  "scan": {},
  "label": "Approved initial baseline",
  "scan_metadata": {
    "scan_time": 300,
    "coverage": ["2.4"],
    "source": "hak5_recon",
    "label": "Source scan label"
  }
}
```

The backend independently validates and resolves `scan`; a client-supplied
resolved snapshot is not accepted as authority.

Response:

```json
{
  "assessment": {},
  "baseline": {
    "schema_version": "1.0",
    "baseline_version_id": "baseline_v0001",
    "assessment_id": "assessment_...",
    "version": 1,
    "label": "Approved initial baseline",
    "created_at": "2026-07-27T16:10:00Z",
    "snapshot_id": "snapshot_...",
    "snapshot_digest": "...",
    "summary": {},
    "scan_metadata": {},
    "comparability_profile": {},
    "is_active": false
  },
  "event": {}
}
```

### `list_baseline_versions`

Request:

```json
{
  "assessment_id": "assessment_..."
}
```

Returns `baselines` in numeric order and identifies the currently active version.
Snapshot contents remain local.

### `activate_baseline_version`

Request:

```json
{
  "assessment_id": "assessment_...",
  "baseline_version": "baseline_v0001",
  "expected_revision": 2
}
```

The response contains updated assessment metadata in `assessment`, the
activated immutable record in `baseline`, and the audit event. Re-activating
the already active version
returns `no_changes`.

## Comparison and analysis actions

### `compare_recon`

This is a read-only preview. It neither increments assessment revision nor
updates audit or finding state.

Request:

```json
{
  "assessment_id": "assessment_...",
  "scan": {},
  "scan_metadata": {
    "scan_time": 300,
    "coverage": ["2.4"],
    "source": "hak5_recon",
    "label": "Weekly verification",
    "measurement_context": {
      "location_id": "plant-a",
      "measurement_point_id": "north-wall",
      "scan_profile_id": "full-sweep-v1",
      "radio_profile_id": "mk7-radio-a",
      "interface": "wlan1mon",
      "declared_channels": [1, 6, 11]
    }
  }
}
```

Response:

```json
{
  "schema_version": "1.1",
  "mode": "preview",
  "assessment_revision": 3,
  "baseline": {},
  "current_snapshot": {},
  "diff": {
    "comparability": {
      "status": "comparable",
      "positive_findings_allowed": true,
      "absence_findings_allowed": true,
      "lifecycle_updates_allowed": true,
      "location_match": true,
      "measurement_point_match": true,
      "scan_profile_match": true,
      "radio_profile_match": true,
      "interface_match": true,
      "reasons": [],
      "baseline": {},
      "current": {}
    },
    "access_points": {
      "added": [],
      "removed": [],
      "changed": []
    },
    "networks": {
      "added": [],
      "removed": [],
      "changed": []
    },
    "summary": {}
  },
  "candidate_findings": []
}
```

`not_comparable` still returns and can persist a diagnostic diff, but produces
no candidate findings and leaves finding lifecycle untouched.
`partially_comparable` permits findings for changes that were actually
observed, applies the documented confidence penalty, and suppresses missing-AP
findings.

Known `location_id` or `measurement_point_id` mismatch is
`not_comparable`. Known `scan_profile_id` or `interface` mismatch is also
`not_comparable`. A known `radio_profile_id` mismatch is
`partially_comparable`: observed changes remain available, while absence
findings are disabled. Unknown scan/radio/interface profile values also limit
the result to `partially_comparable`. The obsolete relative
`position_confirmation` input is rejected; it is not part of the public API.

### `analyze_recon`

Request adds `expected_revision` to the `compare_recon` fields:

```json
{
  "assessment_id": "assessment_...",
  "expected_revision": 3,
  "scan": {},
  "scan_metadata": {}
}
```

The backend reruns validation and comparison. It does not trust a previous
preview supplied by the client.

Response:

```json
{
  "schema_version": "1.1",
  "assessment": {},
  "comparison": {},
  "findings": [],
  "lifecycle": {
    "opened": [],
    "reopened": [],
    "updated": [],
    "resolved": [],
    "preserved_false_positive": [],
    "mutated": false
  },
  "event": {}
}
```

The current normalized snapshot is stored separately and referenced by the
persisted comparison. The comparison contains the deterministic diff,
lifecycle summary, evidence references, and occurrence facts, but not the raw
Recon response. Its lifecycle summary contains `opened`, `reopened`, `updated`,
`resolved`, `preserved_false_positive`, and `mutated`.

## Finding actions

### `list_findings`

Request:

```json
{
  "assessment_id": "assessment_...",
  "status": "open"
}
```

The status filter is optional. The response includes authoritative severity,
confidence and its factors, current state, occurrence count, timestamps,
evidence references, and deterministic details.

### `update_finding`

Request:

```json
{
  "assessment_id": "assessment_...",
  "finding_id": "finding_...",
  "expected_revision": 4,
  "status": "acknowledged",
  "note": "Confirmed with the wireless controller."
}
```

The operator may set `acknowledged` or `false_positive`, and may set `open` to
reverse a previous acknowledgment or false-positive decision. A resolved
finding cannot be manually reopened: only a new deterministic occurrence
reopens it. `resolved` is deterministic-only. A later occurrence updates
evidence and occurrence history but does not silently override
`false_positive`. `note` is optional, local-only, and never sent to an AI
provider.

## Optional AI analysis

AI is never required for any preceding action.

### `prepare_ai_analysis`

Request:

```json
{
  "assessment_id": "assessment_...",
  "comparison_id": "comparison_...",
  "finding_ids": ["finding_..."],
  "options": {
    "language": "en",
    "share_ssids": false
  }
}
```

Returns the exact privacy-filtered provider request without making a network
request:

```json
{
  "schema_version": "1.0",
  "model": "gpt-5.6-terra",
  "language": "en",
  "share_ssids": false,
  "cloud_payload": {}
}
```

`cloud_payload` contains pseudonymized subject IDs, deterministic facts,
existing finding IDs, and valid evidence IDs. Its `assessment` object contains
only `assessment_id`; assessment name, location, and notes stay local. It
contains no MAC,
BSSID, client identifier, raw scan, scan ID, local note, audit text, API key,
or authorization material.

### `generate_ai_analysis`

Accepts the same request. It sends only the prepared payload and validates the
strict structured response against local comparison, finding, and evidence
allowlists.

Response:

```json
{
  "schema_version": "1.0",
  "analysis": {
    "analysis_id": "analysis_...",
    "model": "gpt-5.6-terra",
    "language": "en",
    "summary": "",
    "finding_explanations": [
      {
        "finding_id": "finding_...",
        "explanation": "",
        "alternative_explanations": [],
        "validation_steps": [],
        "evidence_ids": []
      }
    ],
    "report_sections": {
      "executive_summary": "",
      "technical_summary": "",
      "change_summary": "",
      "limitations": []
    }
  },
  "ai_status": {
    "state": "complete",
    "code": null,
    "message": null
  },
  "model": "gpt-5.6-terra",
  "token_usage": {
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0
  }
}
```

On missing key, disabled AI, refusal, timeout, provider error, invalid JSON, or
invalid references, `analysis` is `null`, `ai_status.state` is `unavailable`
or `partial`, and the
deterministic context remains usable.

## Reports

### `generate_report`

Request:

```json
{
  "assessment_id": "assessment_...",
  "comparison_id": "comparison_...",
  "format": "html",
  "ai_analysis": null
}
```

Response:

```json
{
  "schema_version": "1.0",
  "format": "html",
  "filename": "pineai-assessment-comparison.html",
  "mime_type": "text/html",
  "sha256": "...",
  "content": "<!doctype html>..."
}
```

`json` is authoritative machine-readable output. `html` is standalone,
script-free, and escapes every untrusted field. Content is returned as a plain
UTF-8 JSON or HTML string. AI prose is included only when `ai_analysis`
contains a full backend-produced result that passes local reference validation;
it is marked non-authoritative in both report formats.

## Settings actions

`get_settings`, `update_settings`, `set_openai_api_key`, and
`delete_openai_api_key` retain the secure `0.5` key-handling behavior.

For Baseline & Drift, editable settings are:

```json
{
  "settings": {
    "language": "en",
    "share_ssids": false
  }
}
```

The API key is accepted only in the request body, stored in a `0600` file, and
never echoed. Runtime band allowlists are not used by `0.6.3`.

## Error codes

Clients must branch on `code`, not message text.

| Code | Meaning |
| --- | --- |
| `invalid_recon` | Recon structure or documented values are invalid. |
| `invalid_scan_metadata` | Metadata shape, coverage, or duration is invalid. |
| `invalid_assessment` | Assessment create/update fields are invalid. |
| `invalid_assessment_id` | Assessment ID shape is invalid. |
| `assessment_not_found` | No matching assessment exists. |
| `assessment_archived` | A mutation was attempted on archived state. |
| `revision_conflict` | `expected_revision` is stale. |
| `no_changes` | The requested state is already effective. |
| `invalid_request` | A request field or limit is invalid. |
| `invalid_data` | A deterministic value cannot be represented as valid JSON. |
| `invalid_snapshot` | A resolved or stored snapshot failed validation. |
| `snapshot_limit` | Assessment reached the normalized-snapshot limit. |
| `snapshot_conflict` | An immutable snapshot ID already has different content. |
| `invalid_baseline` | Baseline request or record is invalid. |
| `baseline_not_found` | Baseline version does not exist. |
| `baseline_not_active` | No active baseline exists. |
| `baseline_limit` | Assessment reached the baseline-version limit. |
| `baseline_conflict` | An immutable baseline ID already has different content. |
| `invalid_comparison` | Comparison request or stored record is invalid. |
| `comparison_not_found` | Comparison ID does not exist. |
| `comparison_limit` | Assessment reached the persisted-comparison limit. |
| `comparison_conflict` | An immutable comparison ID already has different content. |
| `analysis_already_persisted` | The same deterministic analysis is already stored. |
| `invalid_finding` | Finding request or transition is invalid. |
| `finding_not_found` | Finding ID does not exist. |
| `finding_limit` | Assessment reached the finding limit. |
| `invalid_options` | AI language or privacy options are invalid. |
| `invalid_ai_output` | Provider output failed structural validation. |
| `invalid_ai_reference` | Provider output references unknown local evidence or findings. |
| `unsafe_ai_output` | A suggested validation step crossed the safe advisory boundary. |
| `privacy_violation` | A provider payload still contains a MAC address. |
| `invalid_secret` | The local pseudonymization key is invalid. |
| `invalid_report` | Deterministic report inputs are incomplete. |
| `invalid_report_format` | Report format is not `json` or `html`. |
| `raw_recon_not_allowed` | A persistence request contains raw Recon keys. |
| `event_limit` | Assessment reached the append-only event limit. |
| `storage_busy` | Another mutation holds the assessment lock. |
| `storage_error` | Private persistent storage failed safely. |
| `configuration_error` | Local settings or secret storage is invalid. |

Provider failures are normally represented by `ai_status` partial output,
rather than turning a valid deterministic analysis into a failed action.
