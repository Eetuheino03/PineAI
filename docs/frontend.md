# PineAI Baseline & Drift frontend

The Angular 9 frontend implements an offline-first wireless assurance
workflow:

```text
Assessment -> saved Recon scan -> resolved assets -> baseline
           -> comparison -> findings -> report
```

AI is optional and never controls this sequence.

## Views

- **Overview** — runtime health, active assessment and baseline, latest
  comparison, open finding counts, and the next deterministic workflow step.
- **Recon** — saved Hak5 Recon scans, metadata, load state, and resolver
  preview. There are no start or stop controls in `0.6.1`.
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

## Physical Mark VII smoke test

After installing the `0.6.1` archive:

1. Confirm the module loads with AI unconfigured.
2. Confirm backend version `0.6.1` and assurance schema version `1.1`.
3. List and load a saved Recon scan.
4. Resolve it and create an assessment baseline.
5. Confirm the baseline requires a separate activation.
6. Compare a later scan and verify comparability, diff, and findings.
7. Save the analysis, acknowledge one finding, and refresh the module.
8. Export JSON and HTML and verify both checksums.
9. Confirm all deterministic operations still work with no network access.
10. Verify assessment directories are `0700` and files are `0600`.

This physical smoke test is pending for `v0.6.1`. Until it is completed, the
GitHub release remains a pre-release and must not be described as
hardware-verified.
