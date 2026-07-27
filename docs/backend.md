# Target Profiler backend

PineAI contains a read-only Target Profiler backend. The implementation
uses only the Python standard library so it can run in the Mark VII firmware
without adding packages.

## Processing pipeline

1. Validate the supplied Recon JSON and enforce input/count limits.
2. Accept the documented client-list field variants:
   `OutOfRangeResult` or `OutOfRangeClientResults`, and
   `UnassociatedResult` or `UnassociatedClientResults`.
3. Normalize AP/client observations and group visible APs by exact SSID.
4. Keep each hidden BSSID as a separate target.
5. Calculate deterministic metrics and evidence references.
6. Generate stable HMAC-SHA256 pseudonyms using the local device secret.
7. Build a privacy-filtered payload for at most 50 selected targets.
8. If enabled and configured, request strict structured output from the
   OpenAI Responses API.
9. Validate every returned target, relationship, and evidence reference before
   merging the AI analysis into the local result.

All deterministic targets are returned even when only the 50 highest-ranked
targets are submitted for AI analysis.

## `profile_recon` action

Input:

```json
{
  "scan": {
    "APResults": [],
    "OutOfRangeClientResults": [],
    "UnassociatedClientResults": []
  },
  "scan_metadata": {
    "scan_id": "optional",
    "date": "optional",
    "objective": "optional"
  },
  "options": {
    "language": "en",
    "share_ssids": false,
    "ai_enabled": true
  }
}
```

`language` supports `en` and `fi`. SSID sharing is off by default.

Successful or partial output contains:

- `schema_version` and `backend_version`;
- deterministic `scan_summary` and `targets`;
- optional `ai_profile` per AI-selected target;
- `overall_summary`;
- `ai_status.state`, `ai_status.code`, and a safe message;
- model name and token usage.

Invalid Recon input returns a backend error and never calls OpenAI.

## AI contract

The backend calls `POST https://api.openai.com/v1/responses` with:

- model `gpt-5.6-terra` by default;
- reasoning effort `low`;
- `store: false`;
- no tools;
- strict JSON Schema Structured Outputs.

The model can return only:

- a target role;
- interest level;
- confidence;
- summary and observations;
- missing evidence;
- known target relationships;
- supplied evidence references.

The schema has no command or action field. Wireless strings, including SSIDs,
are explicitly marked as untrusted observations rather than instructions.

## Privacy and secrets

The local deterministic result may contain original SSIDs and BSSIDs. The
OpenAI payload never contains BSSIDs or client MAC addresses. Target and
evidence references are HMAC pseudonyms. SSIDs are also pseudonymized unless
the operator explicitly enables sharing.

Device files:

| Path | Purpose | Mode |
| --- | --- | --- |
| `/root/.PineAI/openai.key` | OpenAI API key | `0600` |
| `/root/.PineAI/pseudonymization.key` | random 256-bit HMAC key | `0600` |
| `/root/.PineAI/config.json` | non-secret defaults | `0600` |

The key is not returned by `health`, `status`, or module actions and is never
accepted as a CLI argument.

## Machine-readable AI states

Common `ai_status.code` values:

- `ok`: AI profiles passed local validation;
- `ai_disabled`: deterministic profiling only by request;
- `not_configured`: API key missing;
- `no_targets`: valid scan contains no targets;
- `authentication_error`: OpenAI rejected the key;
- `rate_limited`: provider limit reached;
- `upstream_error`: provider server failure;
- `network_error`: timeout or connectivity failure;
- `refusal`: model refusal;
- `invalid_response`: invalid provider JSON;
- `invalid_ai_output`: structured result failed local semantic checks.

Provider failures return deterministic profiles as a partial result. A broader
offline heuristic analyzer is intentionally deferred to a future release.

## Physical-device verification

Before upstream publication, verify on a Mark VII:

- bundled Python version and module imports;
- CA certificate validation to `api.openai.com`;
- file and directory modes;
- `health` and `profile_recon` module actions;
- actual firmware Recon response shapes;
- package install, uninstall, and reinstall.

Attack-Path Advisor is documented separately in
[attack-path-advisor.md](attack-path-advisor.md).

## References

- [Hak5 module development](https://hak5.github.io/mk7-docs/docs/modules/modules/)
- [Hak5 Recon REST API](https://hak5.github.io/mk7-docs/docs/rest/recon/recon/)
- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [OpenAI latest-model guidance](https://developers.openai.com/api/docs/guides/latest-model)
