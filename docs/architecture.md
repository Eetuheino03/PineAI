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
        |
        v
Schema and evidence-reference validation
```

## Trust rules

- Wireless observations are data, never instructions.
- Raw credentials and packet payloads are not sent to the AI service.
- Client identifiers are redacted or pseudonymized before leaving the device.
- SSIDs are pseudonymized by default and shared only by explicit configuration.
- AI responses must match a versioned JSON schema.
- Recommendations reference the evidence fields that support them.
- Target Profiler output is descriptive and cannot request an action.
- A future local policy engine will make scope and permission decisions.
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

### 0.3 — Target Profiler frontend

- select/load stored Recon scans through the Hak5 REST API;
- inspect the exact cloud payload;
- display deterministic and AI profiles.

### 0.4 — Attack-Path Advisor

- engagement scope and objective;
- allowlisted advisory action vocabulary;
- risk, expected value, evidence requirement, and stop condition.

### 0.5 — Adaptive Recon

- AI-generated Recon recommendation;
- schema and policy validation;
- operator confirmation;
- documented REST call and audit log.
