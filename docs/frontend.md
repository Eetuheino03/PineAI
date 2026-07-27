# PineAI frontend 0.5

The Angular 9 frontend implements the complete operator workflow without
turning the AI model into an action executor.

```text
Recon -> Target Profiler -> Engagement -> Advisor -> Adaptive Recon
```

## Installation

Build the Hak5 archive from the repository root:

```bash
npm ci
./build.sh package
```

When Angular was built with the Windows Node.js 16 runtime and packaging is
performed from WSL, assemble that verified output without rebuilding:

```bash
PINEAI_SKIP_ANGULAR_BUILD=1 ./build.sh package
```

This mode refuses to run unless `dist/PineAI/bundles/` already exists.

Upload `PineAI-0.5.0.tar.gz` through the WiFi Pineapple module management
interface. For development, copy `dist/PineAI/` to
`/pineapple/modules/PineAI/`.

The archive has one top-level `PineAI/` directory containing the UMD bundle,
module metadata, icon, `module.py`, CLI, and standard-library Python backend.

## First run

1. Open **Settings**.
2. Select the analysis language. Real SSID sharing remains disabled by
   default.
3. Add one or more exact `band` values that have been verified on the physical
   Mark VII. Assign `2.4`, `5`, or both coverages and optionally one default.
4. Store an OpenAI API key, or leave AI offline and use deterministic results.
5. Open **Recon** and load a saved scan or confirm a bounded new scan.

Hak5 documents the `band` request field but not its accepted values. PineAI
therefore ships an empty allowlist and never guesses a value.

## API key handling

`set_openai_api_key` accepts the key in one module request and writes
`/root/.PineAI/openai.key` with mode `0600`. The response contains only:

```json
{
  "api_key_configured": true,
  "api_key_source": "file"
}
```

The field is cleared from the form after every request. It is never stored in
browser storage or returned by the backend. On HTTP pages, the operator must
explicitly acknowledge that network observers may see the request. HTTPS or
the interactive CLI is safer:

```bash
python3 /pineapple/modules/PineAI/assets/pineai_cli.py configure
```

`delete_openai_api_key` deletes only the managed file. If
`OPENAI_API_KEY` is set in the backend environment, the status remains
configured with source `environment`.

## Frontend module actions

Every module request includes `"module": "PineAI"`.

### Settings

`get_settings` returns schema `1.0`, the fixed model, analysis language,
SSID-sharing state, maximum target count, API-key status, and supported bands.

`update_settings` accepts only:

```json
{
  "settings": {
    "language": "en",
    "share_ssids": false,
    "supported_bands": [
      {
        "value": "device-confirmed-value",
        "covers": ["2.4", "5"],
        "is_default": true
      }
    ]
  }
}
```

There may be 0-8 unique printable ASCII values, each 1-32 characters. Coverage
must contain `2.4`, `5`, or both. At most one entry is the default.

### Exact privacy previews

- `prepare_profile_recon` accepts the same fields as `profile_recon` and
  returns the exact profiler payload without a network request.
- `prepare_attack_paths` accepts the same fields as `advise_attack_paths` and
  returns only policy-approved paths in the exact advisor payload.
- `prepare_adaptive_recon` already provides the corresponding exact Adaptive
  Recon payload.

No preview contains API keys, authorization references, local notes, event
free text, or MAC addresses.

## Operator workflow

### Recon and profiling

The frontend calls the authenticated native endpoints:

```text
GET  /api/recon/status
GET  /api/recon/scans
GET  /api/recon/scans/:scan_id
POST /api/recon/start
POST /api/recon/stop
```

Manual and Adaptive starts always use `live:false`. The manual UI accepts only
60, 180, 300, or 600 seconds and an allowlisted band. The operator must confirm
authorization before starting.

The loaded JSON is sent to `profile_recon`. Deterministic profiles remain
visible when `ai_status.state` is `partial` or `disabled`. Operators may select
1-10 target IDs for advice.

### Engagement and advice

An engagement requires a name, 1-5 objective codes, one or more profiled
target IDs, at least one allowed action, authorization reference, and a UTC
time window. The UI supplies `expected_revision` for every mutation.

On `revision_conflict`, the frontend refreshes the engagement and requires the
operator to review and retry. Archived engagements remain readable but cannot
be changed or used for advice.

Advisor cards show authoritative risk, detectability, approval requirements,
preconditions, and stop conditions. Buttons only append
`action_started|completed|failed|aborted` audit events; they never execute the
action.

### Adaptive Recon

Only paths containing `collect_additional_recon` can be selected, one per
target. The sequence is:

1. Refresh `/api/recon/status`.
2. Call `prepare_adaptive_recon` or `recommend_adaptive_recon`.
3. Display only returned candidate IDs and parameters.
4. Require the operator to select and confirm one candidate.
5. Refresh status and call `approve_recon_plan`.
6. Verify the descriptor is exactly `POST /api/recon/start`.
7. Send its `body` unchanged through the Hak5 session.
8. Record the returned `scanRunning` and `scanID`.
9. Poll status without automatically starting another scan.
10. Load and profile the completed scan, then record the aggregate result.

Up to five prior profiler snapshots are held only in Angular memory. Raw Recon
JSON and snapshots are not written to `localStorage` or backend audit files.

## Error behavior

Errors are displayed as `code: safe message`. Partial AI failures do not hide
deterministic output. Stale status, expired approval, changed band capability,
out-of-scope target, revision conflict, or unexpected REST descriptor stops
the workflow.

## Physical Mark VII smoke test

After installing the release archive:

1. Verify the module loads without a browser console error.
2. Confirm backend version `0.5.0` and settings state.
3. Confirm secret and config files use `0600`; engagement directory uses
   `0700`.
4. Enter a known accepted band value and run a 60-second authorized scan.
5. Load and profile its result offline.
6. Configure an API key over HTTPS or CLI and repeat profiling.
7. Create an engagement and generate advice.
8. Approve one Recon-only path and verify the exact REST descriptor.
9. Confirm completion is recorded once and no next scan starts automatically.
10. Reinstall the module and verify persistent settings and engagements.
