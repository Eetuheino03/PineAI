# PineAssure 0.7.0 frontend

PineAssure is the display brand. The Angular library, Hak5 request envelope,
and module route retain the technical ID `PineAI`. The Angular 9 frontend
implements an offline-first wireless assurance workflow:

```text
Assessment -> saved Recon scan -> resolved assets -> baseline
           -> comparison -> findings -> report
           -> MeasurementPoints -> AuditRun -> sealed run report
```

AI is optional and never controls this sequence.

## Views

- **Overview** — runtime health, active assessment and baseline, latest
  comparison, open finding counts, and the next deterministic workflow step.
- **Recon** — saved Hak5 Recon scans, metadata, load state, and resolver
  preview. There are no start or stop controls in `0.7.0`.
- **Assessments** — create, edit, archive, and select one wireless environment.
- **Baselines** — create immutable versions, inspect them, and explicitly
  activate one with revision checking.
- **Assets & Changes** — access points, SSID networks, comparability, and AP or
  SSID drift.
- **Findings** — severity, confidence factors, evidence, occurrence history,
  acknowledgment, false-positive marking, and resolved state.
- **Reports** — deterministic JSON and standalone HTML export plus optional,
  labelled AI prose.
- **Activity** — append-only assessment events.
- **Settings** — language, optional SSID sharing, and OpenAI key status.
- **Repeatable Audit** — location-only MeasurementPoints, draft/run lifecycle,
  one-at-a-time saved-scan resolution, comparison persistence, retry controls,
  run progress, and terminal deterministic report export.

The layout must remain usable in the narrow Mark VII management view. Status
must be communicated with text in addition to color, all interactive elements
must be keyboard reachable, and loading or error state in one view must not
prevent other offline views from opening.

## Backend calls

Every module request includes `"module": "PineAI"`. The complete field
contract and errors are documented in [backend-api.md](backend-api.md).

The frontend uses:

- `health`
- `get_settings`, `update_settings`
- `set_openai_api_key`, `delete_openai_api_key`
- `assurance_capabilities`
- `create_assessment`, `get_assessment`, `list_assessments`,
  `update_assessment`, `archive_assessment`
- `resolve_recon`
- `create_baseline_version`, `list_baseline_versions`,
  `activate_baseline_version`
- `compare_recon`, `analyze_recon`
- `list_findings`, `update_finding`
- `prepare_ai_analysis`, `generate_ai_analysis`
- `generate_report`
- `repeatable_audit_capabilities`, `resource_telemetry`
- `create_measurement_point`, `list_measurement_points`,
  `get_measurement_point`, `update_measurement_point`,
  `archive_measurement_point`
- `create_audit_run`, `list_audit_runs`, `get_audit_run`,
  `start_audit_run`, `cancel_audit_run`, `complete_audit_run`
- `resolve_audit_measurement`, `save_audit_measurement_comparison`,
  `retry_audit_measurement`, `generate_audit_run_report`

Backend failures have this safe shape:

```json
{
  "error": {
    "code": "revision_conflict",
    "message": "The assessment changed; refresh it before retrying."
  }
}
```

The UI displays `code: message`, keeps the operator's unsaved form data where
safe, refreshes authoritative state on a revision conflict, and requires a
new confirmation before retrying a mutation.

## Saved Recon integration

The Recon view uses only:

```text
GET /api/recon/scans
GET /api/recon/scans/:scan_id
```

The selected response is held in memory and sent to `resolve_recon`,
`create_baseline_version`, `compare_recon`, or `analyze_recon`. Raw Recon JSON
must not be written to `localStorage`, session storage, application logs, or
the PineAI backend.

The frontend supplies explicit scan metadata when known:

```json
{
  "scan_id": "local-ui-reference",
  "date": "2026-07-27T16:00:00Z",
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
```

`scan_id` is local request context. It is never included in an AI payload.
Unknown duration or coverage remains unknown; the frontend must not infer
Hak5 band values.

## Recommended UI sequence

### 1. Create or select an assessment

Create an assessment with name, location, optional local notes, and
`expected_revision` on every later mutation. One assessment represents one
wireless environment.

If an assessment is archived, keep it readable and allow deterministic report
exports from its stored comparisons. Disable baseline changes, new comparisons,
analysis persistence, and finding-status mutations. Optional AI explanation of
already stored comparisons remains a read-only operation.

### 2. Load and resolve a saved scan

Load a scan through the Hak5 REST API and call `resolve_recon`. Show:

- access-point and network counts;
- normalized AP and SSID assets;
- declared, observed, and effective coverage;
- scan duration and evidence IDs;
- validation errors before enabling baseline creation.

The returned snapshot contains local identifiers. Treat every SSID, vendor,
and label as untrusted text and render it through normal Angular interpolation,
never `innerHTML`.

### 3. Create the baseline

Call `create_baseline_version` with the raw scan, scan metadata, assessment ID,
and current revision. Show a confirmation that:

- the version is immutable;
- creating it does not activate it;
- raw Recon JSON is not stored.

After creation, call `activate_baseline_version` separately. Display the
version, digest, source metadata, creation time, creator-supplied label, and
whether it is active.

### 4. Preview comparison

Load a later saved scan and call `compare_recon`. This is read-only and does
not change assessment revision, finding state, or audit history.

Display comparability before findings:

- status;
- reason codes;
- baseline and current coverage, duration, and AP count;
- whether absence-based findings are allowed.

For `not_comparable`, show diagnostic differences and label **Save analysis**
as a diagnostic record: saving produces no findings or lifecycle changes. For
`partially_comparable`, explain that observed changes are available with a
confidence penalty and missing-AP findings are suppressed.

### 5. Save analysis

Call `analyze_recon` only after the operator reviews the preview. Supply the
current `expected_revision`.

Show:

- immutable comparison ID and timestamp;
- AP and SSID diff;
- findings emitted this run;
- lifecycle transitions in the stored comparison, including resolved or
  reopened findings;
- updated assessment revision.

Do not convert AI prose into a finding or lifecycle action.

### 6. Manage findings

`list_findings` supports status and severity filters without changing state.

`update_finding` allows only:

- `open` to reverse an earlier operator decision;
- `acknowledged`
- `false_positive`

The operator sees the finding ID, current state, assessment revision, and
optional local audit note before confirming. A resolved finding cannot be
manually reopened. The backend controls automatic `resolved` and recurrence
reopen transitions.

### 7. Export a report

Call `generate_report` with the assessment and comparison IDs and requested
format:

- `json` for authoritative machine-readable output;
- `html` for a standalone, script-free human report.

The response includes a safe filename, MIME type, SHA-256 checksum, and plain
UTF-8 JSON or HTML content. Verify the checksum in the browser when practical,
create a `Blob`, and download it without injecting HTML into the module page.

AI prose is optional and visibly labelled **AI-generated, non-authoritative
analysis**.

## Optional AI analysis

Before any network request, `prepare_ai_analysis` shows the exact
pseudonymized payload. It contains only selected deterministic comparisons,
findings, and valid evidence references.

The privacy preview must make these states clear:

- BSSIDs and client MAC addresses are absent;
- local notes and audit free text are absent;
- SSIDs are pseudonymized by default;
- enabling `share_ssids` is explicit and reversible.

`generate_ai_analysis` returns deterministic context unchanged plus an
`ai_status`. A missing key, refusal, timeout, invalid JSON, or provider error
leaves comparison, findings, and reporting usable.

## Settings and key handling

`update_settings` changes only `language` (`en` or `fi`) and `share_ssids`.
Legacy runtime band settings are not part of the Baseline & Drift UI.

`set_openai_api_key` accepts the key once and returns only configured state.
Clear the form field immediately after success or failure. Never place the key
in Angular source, browser storage, query parameters, error text, or logs.

On an HTTP management page, require explicit acknowledgement before sending a
key. HTTPS or the interactive device CLI is preferred. AI configuration is
never required for the offline workflow.

## State handling

- Keep only the currently loaded raw scan in Angular memory.
- Refresh assessment and baseline state after every successful mutation.
- On `revision_conflict`, stop and reload before allowing a retry.
- Never silently activate a baseline or save a comparison.
- Never infer a clean environment from a non-comparable scan.
- Keep deterministic results visible when `ai_status` is `unavailable` or
  `partial`.
- Render prompt-injection-like SSIDs, vendor names, labels, and notes only as
  escaped data.

## Repeatable Field Audit UI

The default workflow keeps legacy Customer Audit operations available while
adding an explicit field-run surface:

1. Select an active assessment.
2. Create or select one or more location-only MeasurementPoints. The editable
   fields are `location_label`, optional `physical_notes`, and optional
   `operator_instructions`; technical scan settings never belong to a point.
3. Create a draft AuditRun with 1-16 assignments. Each assignment selects a
   point, an immutable MeasurementProfile version, and a baseline version. The
   run also pins one AssuranceProfile version. The baseline must identify the
   same physical MeasurementPoint; the backend rejects cross-point assignments.
4. Review `ready_to_start`, provenance digests, resource admission, and
   capacity before explicitly starting the run.
5. For the current measurement, select a saved Recon observation and submit
   raw scan data only to `resolve_audit_measurement`. The backend persists the
   normalized candidate, not raw Recon JSON. Any measurement context in the
   saved scan is untrusted input: the backend replaces it with the immutable
   assigned point and MeasurementProfile context. The resulting
   `snapshot_record_digest` protects the complete normalized record. Keep the
   operator-declared provenance warning visible before resolution: Hak5 saved
   Recon does not independently bind the interface, bands, channels, duration,
   or radio profile to the scan, so the UI must not call those settings
   device-verified.
6. Review comparability and deterministic changes, then explicitly save the
   comparison. Independently failed resolution or comparison may be retried.
7. Complete the run only after every measurement is `completed`, or cancel it
   explicitly. There is no paused state; reopening the module resumes by
   reading durable backend state.
8. Generate a report only for a `completed` or `cancelled` run and choose the
   required privacy profile: `local_full` or `share_safe`.

The UI must treat backend workflow and capacity fields as observational. It
must never synthesize revisions, IDs, readiness, or free-form report privacy
values. Mutations use `expected_assessment_revision` and, where required,
`expected_measurement_point_revision`, `expected_audit_run_revision`, and
`expected_measurement_revision`.

See [repeatable-audits-api-v1.md](repeatable-audits-api-v1.md) and the
[versioned JSON schema](schemas/repeatable-audits-v1.schema.json) for exact
request and response fields.

## Physical Mark VII smoke test

After installing the exact `0.7.0` release-candidate archive:

1. Confirm the module loads with AI unconfigured.
2. Confirm display brand PineAssure, technical module ID `PineAI`, backend
   version `0.7.0`, and assurance schema version `1.2`.
3. List and load a saved Recon scan.
4. Confirm the existing Customer Audit workflow remains usable offline.
5. Create a disposable location-only point and a draft run from controlled
   fixture data; confirm no mutation occurs merely by moving between views.
6. Verify revision conflict, start, reopen/resume, retry, terminal transition,
   and both report privacy profiles.
7. Confirm all deterministic operations still work with no network access.
8. Verify private directories are `0700` and files are `0600`.

This physical smoke test is pending for `v0.7.0`. Until the exact published
asset passes it, the release remains a pre-release and must not be described
as hardware-verified.

The detailed device procedure and rollback boundary are in
[mark-vii-validation-v0.7.md](mark-vii-validation-v0.7.md).
