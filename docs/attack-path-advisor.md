# Attack-Path Advisor backend

PineAI `0.3.0` adds a persistent, advisory-only Attack-Path Advisor. It reads a
Target Profiler schema `1.0` result and returns policy-approved test paths. It
does not start scans, transmit radio frames, execute commands, create portals,
or collect credentials.

## Frontend integration sequence

```text
profile_recon
    -> create_engagement
    -> advisor_capabilities
    -> advise_attack_paths
    -> append_engagement_event
    -> advise_attack_paths
```

The frontend should keep the current engagement `revision`. Every mutation
requires `expected_revision`; after a successful mutation, replace the local
revision with the value returned by the backend.

## Capabilities

Call `advisor_capabilities` before rendering objective and action choices. It
returns the authoritative IDs, risk metadata and limits. Do not duplicate the
registry in the frontend.

Current limits:

- 1–10 targets per advice request;
- at most three paths per target;
- one to three steps per path;
- at most 200 scoped targets per engagement;
- at most 1,000 audit events per engagement.

The machine-readable contract is
[`schemas/attack-path-advisor-v1.schema.json`](schemas/attack-path-advisor-v1.schema.json).

## Engagement actions

### `create_engagement`

Request:

```json
{
  "engagement": {
    "name": "Example wireless assessment",
    "objectives": [
      "guest_network_security",
      "rogue_ap_resilience"
    ],
    "objective_notes": "Local-only operator context",
    "authorized_target_ids": [
      "target_aaaaaaaaaaaa"
    ],
    "allowed_actions": [
      "collect_additional_recon",
      "test_device_association",
      "captive_portal_inspection"
    ],
    "disruption_allowed": false,
    "authorization_reference": "ROE-2026-001",
    "valid_from": "2026-07-27T08:00:00Z",
    "valid_until": "2026-07-27T18:00:00Z"
  }
}
```

The backend generates `engagement_id`, timestamps, `status=active`,
`revision=1`, and an `engagement_created` event.

### `get_engagement`

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "after_sequence": 0,
  "limit": 100
}
```

Events are paginated by their monotonically increasing `sequence`.
`events_has_more=true` means the frontend should request the next page using
the final returned sequence.

### `list_engagements`

```json
{
  "include_archived": false
}
```

The response contains metadata summaries and does not include event bodies.

### `update_engagement`

Updates are partial. Any engagement field may be changed while active:

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "expected_revision": 1,
  "changes": {
    "disruption_allowed": true,
    "allowed_actions": [
      "collect_additional_recon",
      "authorized_deauthentication"
    ]
  }
}
```

The backend rejects unknown fields, validates the complete resulting time
window, increments the revision and records old/new values in a local
`engagement_updated` audit event.

### `archive_engagement`

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "expected_revision": 2
}
```

Archiving is irreversible through the module API. Archived engagements remain
readable but cannot be updated or used for advice.

### `append_engagement_event`

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "expected_revision": 2,
  "event": {
    "event_type": "action_completed",
    "summary": "Operator-confirmed result; stored only on the device",
    "target_id": "target_aaaaaaaaaaaa",
    "action_id": "collect_additional_recon",
    "evidence_ids": [
      "evidence_bbbbbbbbbbbb"
    ]
  }
}
```

Supported action event types are `action_started`, `action_completed`,
`action_failed`, and `action_aborted`. `operator_note` requires null
`target_id` and `action_id`.

The latest event for a target/action pair controls future advice:

- started and completed actions are excluded;
- failed and aborted actions remain eligible with a 15-point penalty.

## `advise_attack_paths`

Request:

```json
{
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "profile_result": {
    "schema_version": "1.0",
    "targets": []
  },
  "target_ids": [
    "target_aaaaaaaaaaaa"
  ],
  "options": {
    "language": "en",
    "share_ssids": false,
    "ai_enabled": true
  }
}
```

The real `profile_result` is the complete response previously returned by
`profile_recon`. Advisor validates only the fields it consumes. The requested
target IDs must exist in both the profiler result and the engagement scope.

Response outline:

```json
{
  "schema_version": "1.0",
  "backend_version": "0.3.0",
  "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
  "engagement_revision": 2,
  "target_results": [
    {
      "target_id": "target_aaaaaaaaaaaa",
      "paths": [
        {
          "path_id": "path_cccccccccccc",
          "template_id": "guest_portal_assessment",
          "rank": 1,
          "source": "deterministic",
          "confidence": 0.5,
          "risk": "medium",
          "detectability": "medium",
          "requires_explicit_approval": true,
          "credential_collection_advisory_permitted": false,
          "rationale": "Assess guest association and captive-portal behavior with a test device.",
          "steps": [],
          "evidence_ids": [],
          "missing_evidence": [],
          "policy_checks": []
        }
      ]
    }
  ],
  "advisor_status": {
    "state": "partial",
    "code": "not_configured",
    "message": "OpenAI API key is not configured"
  },
  "model": "gpt-5.6-terra",
  "token_usage": {
    "input_tokens": null,
    "output_tokens": null,
    "total_tokens": null
  }
}
```

Risk, detectability, steps, approval requirements, policy checks and stop
conditions always come from the local action registry. AI can only reorder and
explain existing `path_id` values. A provider failure therefore leaves the
deterministic paths intact.

## Disruptive and credential-related advice

`authorized_deauthentication` and `evil_twin_simulation` are eligible only
when:

1. the engagement is active and within its UTC time window;
2. the target is in scope;
3. every path action is explicitly allowed;
4. `authorization_reference` is non-empty;
5. `disruption_allowed` is true.

The selected ROE model allows `evil_twin_simulation` advice to mention
authorized credential-collection objectives. PineAI still has no input,
storage, output or execution field for credentials. It never creates portal
content, payloads or collection commands. The frontend must display
`credential_collection_advisory_permitted` and all stop conditions before an
operator approves any later execution workflow.

## Cloud privacy contract

`prepare-advice` exposes the exact cloud JSON without making a request.

Never sent:

- BSSID or client MAC values;
- authorization reference;
- objective notes;
- event summaries;
- captured credentials or credential values;
- arbitrary commands or execution parameters.

Objective codes, non-identifying metrics, policy-approved candidate IDs and
pseudonymous evidence IDs may be sent. SSIDs remain pseudonymized unless the
existing `share_ssids` option is explicitly enabled.

## Error codes

Validation/storage errors fail the module action:

- `invalid_engagement`, `invalid_engagement_id`, `invalid_event`;
- `engagement_not_found`, `engagement_archived`;
- `engagement_not_started`, `engagement_expired`;
- `revision_conflict`, `no_changes`, `storage_busy`, `storage_error`;
- `target_out_of_scope`, `target_not_found`;
- `invalid_profile_result`, `invalid_advisor_request`, `invalid_options`.

Provider failures preserve deterministic paths in `advisor_status`:

- `not_configured`, `ai_disabled`, `authentication_error`;
- `rate_limited`, `upstream_error`, `network_error`, `refusal`;
- `invalid_response`, `invalid_ai_output`;
- `no_eligible_paths`.

## CLI

```bash
python3 assets/pineai_cli.py engagement create --input engagement.json
python3 assets/pineai_cli.py engagement list
python3 assets/pineai_cli.py engagement get --id ENGAGEMENT_ID
python3 assets/pineai_cli.py engagement update --id ENGAGEMENT_ID --revision 1 --input changes.json
python3 assets/pineai_cli.py engagement event --id ENGAGEMENT_ID --revision 2 --input event.json
python3 assets/pineai_cli.py prepare-advice --engagement-id ENGAGEMENT_ID --input profile.json --target-id TARGET_ID
python3 assets/pineai_cli.py advise --engagement-id ENGAGEMENT_ID --input profile.json --target-id TARGET_ID
python3 assets/pineai_cli.py engagement archive --id ENGAGEMENT_ID --revision 3
```
