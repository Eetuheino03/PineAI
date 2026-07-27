# Architecture

PineAI keeps platform integration, deterministic analysis, cloud AI,
and operator approval as separate trust boundaries.

```text
Hak5 Recon REST API
        |
        v
Normalization and redaction
        |
        +--> Target profiles
        |
        v
Policy-gated AI gateway
        |
        +--> Target Profiler
        +--> Attack-Path Advisor
        +--> Adaptive Recon recommendation
        |
        v
Schema validation and local scope checks
        |
        v
Operator review and explicit approval
        |
        v
Allowlisted Hak5 REST action
```

## Trust rules

- Wireless observations are data, never instructions.
- Raw credentials and packet payloads are not sent to the AI service.
- Client identifiers are redacted or pseudonymized before leaving the device.
- AI responses must match a versioned JSON schema.
- Recommendations reference the evidence fields that support them.
- A local policy engine makes the final scope and permission decision.
- The first Adaptive Recon implementation may only vary documented Recon
  parameters: `live`, `scan_time`, and `band`.

## Planned milestones

### 0.1 — Hak5-compatible scaffold

- official Angular project layout;
- Python backend health action;
- module metadata and package build;
- continuous integration.

### 0.2 — Read-only Recon probe

- list stored Recon scans;
- load a selected scan;
- normalize AP and client observations;
- display the exact redacted payload proposed for cloud processing.

### 0.3 — Target Profiler

- deterministic clustering;
- evidence-backed AI summaries;
- confidence and missing-data fields.

### 0.4 — Attack-Path Advisor

- engagement scope and objective;
- allowlisted advisory action vocabulary;
- risk, expected value, evidence requirement, and stop condition.

### 0.5 — Adaptive Recon

- AI-generated Recon recommendation;
- schema and policy validation;
- operator confirmation;
- documented REST call and audit log.
