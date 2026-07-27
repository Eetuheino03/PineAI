# Adaptive Recon backend

PineAI `0.4.0` adds a backend-only Adaptive Recon planner. It combines selected
Attack-Path Advisor results for 1–10 targets into one bounded scan plan:

```text
Target Profiler
      |
      v
Attack-Path Advisor
      |
      v
Adaptive Recon recommendation
      |
      v
Operator selects and approves one candidate
      |
      v
Frontend sends POST /api/recon/start through its Hak5 session
```

The backend does not call the Hak5 REST API and does not start, stop, or
configure a radio. It returns an exact REST descriptor only after approval.
The frontend remains unimplemented in this release.

## Why band values are runtime input

Hak5 documents `live`, `scan_time`, and `band` for `POST /api/recon/start`, but
does not publish an enum of accepted `band` values. PineAI therefore treats
each band value as an opaque, device-confirmed string. The frontend must supply
the values verified on the connected Mark VII:

```json
{
  "observed_at": "2026-07-27T12:00:00Z",
  "supported_bands": [
    {
      "value": "DEVICE_CONFIRMED_VALUE",
      "covers": ["2.4"],
      "is_default": true
    }
  ],
  "recon_status": {
    "captureRunning": false,
    "scanRunning": false,
    "continuous": false,
    "scanPercent": 0,
    "scanID": 42
  }
}
```

`value` is used unchanged only in an approved local REST descriptor. It is
never sent to OpenAI. At most one band may be marked as the default. A default
is required when selected targets have no channels or contain an unknown
channel.

## Deterministic planning

The backend always produces a deterministic recommendation, even when AI is
disabled, unconfigured, unavailable, refuses the request, or returns invalid
references.

Channel classification:

- channels 1–14 cover `2.4`;
- documented Wi-Fi channels 15–196 cover `5`;
- every other value is `unknown` and requires the supplied default band.

Candidate scan times are 60, 180, 300, and 600 seconds. The accepted local
range is 30–600 seconds, but version 1 generates only those four values:

| Selected duration | Condition |
| --- | --- |
| 60 seconds | At least three stable snapshots and no missing evidence |
| 180 seconds | First/baseline round with sufficient evidence |
| 300 seconds | Target missing from history, structure changed, or evidence is missing |
| 600 seconds | Same evidence missing in two prior snapshots, or previous Recon failed/aborted |

One plan contains every combination of a policy-valid duration and the
smallest device-confirmed band coverage that contains all selected targets.
Candidates are ranked by duration fit, extra band coverage, scan time, and
stable HMAC candidate ID.

## Common planning request

The actions `prepare_adaptive_recon` and `recommend_adaptive_recon` use the
same input:

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "expected_revision": 1,
  "profile_result": {
    "schema_version": "1.0",
    "targets": []
  },
  "advisor_result": {
    "schema_version": "1.0",
    "engagement_revision": 1,
    "target_results": []
  },
  "selected_path_ids": ["path_aaaaaaaaaaaa"],
  "history": [
    {
      "profile_result": {
        "schema_version": "1.0",
        "targets": []
      },
      "scan_metadata": {
        "scan_id": 41,
        "date": "2026-07-27T11:30:00Z",
        "request": {
          "live": false,
          "scan_time": 180,
          "band": "DEVICE_CONFIRMED_VALUE"
        }
      }
    }
  ],
  "device_context": {
    "observed_at": "2026-07-27T12:00:00Z",
    "supported_bands": [
      {
        "value": "DEVICE_CONFIRMED_VALUE",
        "covers": ["2.4"],
        "is_default": true
      }
    ],
    "recon_status": {
      "captureRunning": false,
      "scanRunning": false,
      "continuous": false,
      "scanPercent": 0,
      "scanID": 42
    }
  },
  "options": {
    "language": "en",
    "share_ssids": false,
    "ai_enabled": true
  }
}
```

Constraints:

- `advisor_result.engagement_revision` must equal `expected_revision`;
- every selected path must contain `collect_additional_recon`;
- one path may be selected per target;
- every target must be present in the current profile and engagement scope;
- the engagement must be active, within its time window, and allow
  `collect_additional_recon`;
- at most 10 paths/targets and 5 history snapshots are accepted;
- a non-expired recommended, approved, or started plan blocks another plan for
  the same target;
- Recon and capture must both be idle.

`prepare_adaptive_recon` returns exactly the privacy-filtered payload that
would be sent to OpenAI and does not persist a plan or make a network request.

`recommend_adaptive_recon` persists a plan, appends an
`adaptive_recon_recommended` audit event, and increments the engagement
revision. Its response includes:

- `plan_id`, selected `path_ids`, and combined `target_ids`;
- history/profile digests and aggregate analysis;
- all allowed candidates;
- selected candidate, source, confidence, rationale, and expected information;
- `adaptive_status`, model, and token usage;
- the new `engagement_revision`;
- `recommendation_expires_at`, five minutes after creation or at engagement
  expiry, whichever occurs first.

The default source is `deterministic`. AI may change only
`selected_candidate_id` and explanatory fields.

## AI boundary and privacy

OpenAI receives only:

- HMAC target and candidate identifiers;
- shared or HMAC-pseudonymized SSIDs;
- channels, encryption codes, aggregate metrics, roles and interest levels;
- numeric history deltas;
- evidence identifiers and missing-evidence counts;
- opaque HMAC `band_id` values and coverage (`2.4`/`5`);
- the allowed duration for each candidate.

It does not receive:

- AP or client MAC addresses;
- raw Recon JSON;
- authorization references, local notes, or event text;
- real Hak5 scan IDs;
- raw device band values;
- credentials or credential material.

The Responses API request uses `gpt-5.6-terra`, reasoning effort `low`,
`store: false`, no tools, and a strict Structured Outputs schema. The model
must select one supplied candidate and may not create targets, bands,
durations, actions, commands, or REST parameters. Every returned target,
candidate, and evidence reference is checked locally.

## Approval

Call `approve_recon_plan` with the latest engagement revision, a plan ID, one
candidate ID from that plan, and a freshly read `device_context`:

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "expected_revision": 2,
  "plan_id": "reconplan_aaaaaaaaaaaa",
  "candidate_id": "reconcandidate_bbbbbbbbbbbb",
  "device_context": {
    "observed_at": "2026-07-27T12:01:00Z",
    "supported_bands": [
      {
        "value": "DEVICE_CONFIRMED_VALUE",
        "covers": ["2.4"],
        "is_default": true
      }
    ],
    "recon_status": {
      "captureRunning": false,
      "scanRunning": false,
      "continuous": false,
      "scanPercent": 0,
      "scanID": 42
    }
  }
}
```

The status observation may be at most 10 seconds old. Approval revalidates
scope, time window, action permission, plan freshness, idle state, and that the
candidate's opaque band value/coverage still exists in the runtime allowlist.
There is no API field for free-form scan parameters.

Successful approval returns the only descriptor the frontend may execute:

```json
{
  "rest_request": {
    "method": "POST",
    "path": "/api/recon/start",
    "body": {
      "live": false,
      "scan_time": 300,
      "band": "DEVICE_CONFIRMED_VALUE"
    }
  }
}
```

Approval expires in five minutes or at engagement expiry. The frontend must
not change this body.

## Recording start and finish

After the frontend sends the approved request, pass Hak5's documented start
response to `record_recon_scan_started`:

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "expected_revision": 3,
  "plan_id": "reconplan_aaaaaaaaaaaa",
  "start_response": {
    "scanRunning": true,
    "scanID": 43
  }
}
```

Finish with one of `completed`, `failed`, or `aborted`:

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "expected_revision": 4,
  "plan_id": "reconplan_aaaaaaaaaaaa",
  "outcome": "completed",
  "scan_id": 43,
  "profile_result": {
    "schema_version": "1.0",
    "targets": []
  },
  "error_code": null
}
```

`completed` requires a new Target Profiler result and forbids `error_code`.
`failed` and `aborted` forbid a profile result and may include a lowercase
machine-readable error code. The scan ID must match the recorded start.

The audit log stores plan metadata, selected parameters, status, digests, and
aggregate target/AP/client/channel/encryption/evidence deltas. It does not
store raw Recon or profiler snapshots.

## State machine

```text
recommended --approve--> approved --record start--> started
     |                       |                         |
     +--expires              +--expires               +--> completed
                                                       +--> failed
                                                       +--> aborted
```

Each mutation requires `expected_revision` and increments the engagement
revision. A stale revision returns `revision_conflict` or
`stale_advisor_result`/`stale_recon_plan`, depending on the object that is
stale.

Advisor maps a non-expired recommended/approved/started plan to an in-progress
`collect_additional_recon` action, preventing duplicate suggestions. Failed
and aborted plans add the existing 15-point retry penalty. Completed plans
release the target for a future analysis cycle.

## Module actions

| Action | Purpose |
| --- | --- |
| `adaptive_recon_capabilities` | Durations, limits, state list, and REST route |
| `prepare_adaptive_recon` | Return exact cloud payload without persistence/network |
| `recommend_adaptive_recon` | Generate and persist one combined plan |
| `get_recon_plan` | Read one reconstructed plan |
| `list_recon_plans` | List compact plan summaries |
| `approve_recon_plan` | Approve one existing candidate |
| `record_recon_scan_started` | Validate and audit Hak5 start response |
| `record_recon_scan_finished` | Close the plan and store aggregate delta |

Backend errors use the Hak5 module convention:

```json
{
  "error": {
    "code": "revision_conflict",
    "message": "engagement revision has changed"
  }
}
```

The complete identifiers, request shapes, lifecycle states, and error-code
enum are in
[`schemas/adaptive-recon-v1.schema.json`](schemas/adaptive-recon-v1.schema.json).
Frontend code should fetch `adaptive_recon_capabilities` rather than
duplicating runtime limits.

## CLI

Use the same JSON request without its optional `options` field:

```bash
python3 assets/pineai_cli.py adaptive-capabilities
python3 assets/pineai_cli.py prepare-recon-plan --input adaptive-request.json
python3 assets/pineai_cli.py recommend-recon-plan --input adaptive-request.json --no-ai
```

Lifecycle commands:

```bash
python3 assets/pineai_cli.py recon-plan list --engagement-id ENGAGEMENT_ID
python3 assets/pineai_cli.py recon-plan get --engagement-id ENGAGEMENT_ID --plan-id PLAN_ID
python3 assets/pineai_cli.py recon-plan approve --engagement-id ENGAGEMENT_ID --revision 2 --plan-id PLAN_ID --candidate-id CANDIDATE_ID --device-context device-context.json
python3 assets/pineai_cli.py recon-plan started --engagement-id ENGAGEMENT_ID --revision 3 --plan-id PLAN_ID --input start-response.json
python3 assets/pineai_cli.py recon-plan finished --engagement-id ENGAGEMENT_ID --revision 4 --plan-id PLAN_ID --outcome completed --scan-id 43 --profile profile-result.json
```

CLI backend/input errors return exit code `2` and machine-readable JSON on
stderr.

## Recommended frontend sequence

1. Read Recon status and device-confirmed band capabilities.
2. Run `profile_recon`.
3. Create/read an engagement and run `advise_attack_paths`.
4. Let the operator select Advisor paths containing
   `collect_additional_recon`.
5. Call `prepare_adaptive_recon` for a privacy preview if requested.
6. Call `recommend_adaptive_recon` with the current revision.
7. Display every candidate and the authoritative selected candidate.
8. Refresh Recon status and call `approve_recon_plan`.
9. Send the returned REST descriptor unchanged through the authenticated Hak5
   frontend session.
10. Record start, wait for Recon completion, fetch the new Recon result, run
    `profile_recon`, and record finish.
11. Run Advisor and Adaptive Recon again only after explicit operator action.

## Physical Mark VII checks still required

- discover and document the real accepted band values;
- confirm Recon status timing and `scanID` semantics;
- validate concurrent capture behavior;
- validate `scan_time` and band rejection behavior;
- verify persisted `0600` engagement/audit files;
- exercise the complete authenticated frontend REST chain.

## References

- [Hak5 Recon REST API](https://hak5.github.io/mk7-docs/docs/rest/recon/recon/)
- [Hak5 module development](https://hak5.github.io/mk7-docs/docs/modules/modules/)
- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [OpenAI model guidance](https://developers.openai.com/api/docs/guides/latest-model)
