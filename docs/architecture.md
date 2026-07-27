# Architecture

PineAI keeps platform integration, deterministic analysis, cloud AI,
and operator approval as separate trust boundaries.

```text
Authenticated Hak5 frontend session
        |
        | Recon JSON
        v
Normalization and redaction
        |
        +--> Deterministic target profiles
        |
        v
OpenAI Responses API
        |
        +--> Strict Target Profiler schema
        +--> Strict Attack-Path selection schema
        +--> Strict Adaptive Recon candidate selection schema
        |
        v
Schema and evidence-reference validation
        |
        +--> Revisioned plan lifecycle and audit events
        |
        +--> Exact approved Hak5 REST descriptor for the future frontend
```

## Trust rules

- Wireless observations are data, never instructions.
- Raw credentials and packet payloads are not sent to the AI service.
- Client identifiers are redacted or pseudonymized before leaving the device.
- SSIDs are pseudonymized by default and shared only by explicit configuration.
- AI responses must match a versioned JSON schema.
- Recommendations reference the evidence fields that support them.
- Target Profiler output is descriptive and cannot request an action.
- The local Advisor policy engine makes scope and permission decisions.
- AI never creates an action or changes authoritative risk metadata.
- The first Adaptive Recon implementation may only vary documented Recon
  parameters: `live`, `scan_time`, and `band`.

## Planned milestones

### 0.1 — Hak5-compatible scaffold

- official Angular project layout;
- Python backend health action;
- module metadata and package build;
- continuous integration.

### 0.2 — Target Profiler backend

- validate Recon JSON supplied by a future authenticated frontend;
- deterministic clustering and metrics;
- HMAC-pseudonymized cloud payload;
- strict evidence-backed AI summaries;
- diagnostic CLI and partial offline results.

### 0.3 — Attack-Path Advisor backend

- revisioned engagement scope and event history;
- deterministic policy-approved paths;
- strict AI selection from pre-approved path IDs;
- module actions, CLI and versioned frontend schema.

### 0.4 — Adaptive Recon backend

- deterministic duration and runtime band-capability planning;
- one combined plan for 1–10 targets;
- strict AI selection from existing candidate IDs;
- operator approval and exact Hak5 REST descriptor;
- revisioned Recon plan lifecycle and aggregate result audit.

### 0.5 — Combined frontend

- select/load Recon scans through the authenticated Hak5 REST session;
- manage engagements and revisions;
- display profiles, paths, candidates, approvals and events;
- execute only the unchanged, approved Adaptive Recon descriptor;
- feed completed results back through Profiler and Advisor.
