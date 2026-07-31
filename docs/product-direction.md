# PineAssure product direction

## Full Product Name & Slogan

**Full Product Name**: PineAssure â€” Wireless Assurance for WiFi Pineapple
**Short Slogan**: Baseline. Detect drift. Prove changes.

### Rationale

- **Pine** connects the product immediately to the WiFi Pineapple platform.
- **Assure** describes the exact core value: measurement reliability, versioned baselines, evidence, policy enforcement, and auditability.
- The name does not falsely promise a local LLM running on-device.
- It does not limit the product scope to change detection or reporting only.
- Future capabilities (such as AI Analyst, AuditRun orchestration, and companion sensors) fit naturally under this brand.
- It sounds like a mature software product rather than an experimental AI module.

*Note: Initial preliminary check showed no conflicting GitHub repositories under PineAssure. This does not constitute a formal trademark clearance.*

---

## Customer Problem and Position

PineAssure answers one core audit question:

> What did a site's wireless environment look like when it was approved, what changed, how trustworthy is the comparison, and which evidence proves the change?

The product positioning is:

**PineAssure â€” Wireless Assurance for WiFi Pineapple**
*Baseline. Detect drift. Prove changes.*

---

## Purpose & Authority Boundaries

PineAssure is the analysis and assurance layer missing from the WiFi Pineapple Mark VII. It turns repeatable Recon observations into versioned baselines, deterministic changes, evidence-backed findings, and exportable audit reports.

PineAssure is **not** an attack module, and the language model is **never** a product decision-maker. The complete Baseline, Drift, and AuditRun workflow must work without an internet connection or an AI provider.

### Deterministic Engine Authority Boundary

The deterministic local engine alone is authoritative for:
- What changed between Recon observations;
- Whether two scans or measurements are comparable;
- Which finding rule matched;
- Which evidence belongs to a finding;
- Finding severity, confidence, status, and lifecycle;
- Report facts and all machine-readable outputs.

### AI Capabilities & Strict Boundaries

An optional AI provider may:
- **Evidence Gap Advisor**: Explain why comparison is limited and prioritize allowlisted validation actions.
- **Natural Language Queries**: Translate questions into structured, validated query ASTs executed locally without SQL or vector databases.
- **Investigation Themes**: Group and explain deterministically grouped findings.
- **Policy Draft Assistant**: Suggest draft AssuranceProfiles with source references and explicit "draft, not active" state.
- **Run Briefings & Summaries**: Summarize observed changes and generate debrief prose.

**AI Output Limits & Controls**:
- Payload limit: default max 64 KiB, hard max 128 KiB.
- HTTP response: hard max 512 KiB (bounded chunked read).
- Finding targets: default max 20, hard max 50 (aligned across config and service layer).
- Request timeout: 15 seconds, max 1 retry.
- Output tokens: explanations 800â€“1500, query planning 300â€“600, run debrief 1500â€“2500.
- AI output is stored strictly as separate annotations (`annotations/ai_<digest>.json`) and never mutates finding, occurrence, or lifecycle state directly.
- API Key handling: SSH configuration via `pineai configure --set-openai-key` (or `pineassure`), Web UI key entry disabled by default over HTTP with warning, field cleared immediately, no localStorage/log persistence, `store: false` enabled.

---

## Technical & Version Roadmap

### v0.6.4 â€” Device Validation & Resource Safety (Mandatory prerequisite for v0.7)

Must be completed and verified before v0.7.

| Area | Completion Criteria |
| --- | --- |
| **Mark VII smoke/soak harness** | Exact release artifact verified on physical hardware |
| **Locking** | File-based locking (`flock`), no stale-lockfile removal |
| **Backup/recovery** | All existing tests and PR #47 fault tests passing green |
| **Consensus** | Recon scans processed strictly one at a time |
| **Snapshot digest** | New verifiable digest semantics or measured fix plan |
| **OUI lookup** | Lazy mtime-aware cache; no full JSON re-read on every resolve |
| **Report memory** | Fact model built once; compact HTML; bounded export memory |
| **Resource telemetry** | Measure RSS, peak RSS, MemAvailable, load averages, disk free space |
| **Resource guard** | Reject memory-intensive actions prior to OOM conditions |
| **AI transport** | Bounded request/response streaming and safe key setup |
| **Dependencies** | Runtime and build-time dependency triage and SBOM generation |
| **Firmware** | `firmware_required` accurately matches lowest physically tested hardware version |

#### Target Resource Budget (To be confirmed via physical measurement)

- **PineAssure process RSS**: <= ~48 MiB during normal operation.
- **Peak RSS (heavy test data)**: <= ~64 MiB transient peak.
- **System RAM**: `MemAvailable` must not drop dangerously or trigger OOM killer.
- **Concurrency**: Offline actions must never block module process permanently.
- **Leak Safety**: 100 consecutive resolve/compare operations without continuous RSS growth.
- **Power Loss**: Transaction recovery remains deterministic after unexpected power interruption.

---

### v0.7.0 â€” Repeatable Field Audit MVP

Simplifies the contract to match initial operational field audit needs on resource-constrained hardware.

#### Capacity Limits (MVP)

- 16 active `MeasurementPoints` per assessment (32 total including archived).
- 16 points per `AuditRun`.
- 32 `AuditRuns` per assessment.
- 1 active `AuditRun` at a time per assessment.
- 1 scan processed at a time.

*(Limits will be reassessed only after physical device telemetry is measured).*

#### Domain Model Simplification

Separate responsibilities cleanly to avoid dual-truth duplication:

- **`MeasurementPoint`**: Location context, metadata, and status.
  - `measurement_point_id`, `name`, `description`, `location_id`, `physical_notes`, `status`
- **`MeasurementProfile`**: Technical execution parameters.
  - `scan_profile_id`, `radio_profile_id`, `interface`, `bands`, `channels`, `scan_duration`
- **`AuditRunMeasurement`**: Pinned state and execution record.
  - Point reference, exact pinned profile version, exact pinned baseline, exact pinned assurance profile, snapshot/comparison/occurrence references.

#### Storage Layout per AuditRun

Audit run measurements are split into standalone files to prevent full run re-serialization on single-point updates:

```text
audit_runs/
  ar_x/
    manifest.json
    measurements/
      arm_a.json
      arm_b.json
```

#### Operator Value in v0.7.0

- Operator views the next measurement point in sequence.
- Runs can be paused, browser closed, and resumed seamlessly.
- Each point displays pinned provenance data.
- Failed measurement points can be retried independently.
- Runs can be cancelled or marked complete, generating a compact run report.
- **Strict exclusions**: No background scheduler, no automatic Recon start, no radio control.

---

### v0.7.1 â€” Operational Assurance

High-value, computationally lightweight field capabilities.

1. **Deterministic Evidence Gap Planner**: Converts engine reason codes into explicit, allowlisted action suggestions (e.g. `channel_coverage_unknown` -> `repeat_with_declared_channels`).
2. **Baseline Refresh Candidate**: Deterministically identifies candidate baselines when changes are observed across multiple comparable runs and acknowledged as planned by the operator (no auto-activation).
3. **Planned Maintenance & Suppressions**: Time-bounded suppressions (reason, creator, start/end, scope, expiry) visible in reports without altering underlying evidence or detected drift.
4. **Storage Doctor**: CLI and UI tools for assessment disk usage, artifact counts, export cleanup, backup status, identity key health, transaction recovery, and safe archive/prune policies.

---

### v0.8.0 â€” AI Analyst

*(Prioritized before Sensor Expansion to keep Mark VII CPU load low while leveraging provider-side processing).*

- Task-specific structured AI framework.
- Evidence Gap Advisor with allowlisted recommendations.
- Validated Natural Language Query AST planner (executed locally).
- Investigation themes and group summaries.
- Run briefings and debrief reports.
- Provider abstraction with strict byte and token budgets.
- Annotation storage (`annotations/ai_<digest>.json`).
- Optional companion endpoint transport.

---

### v0.9.0 â€” Companion MVP & Sensor Expansion

Proposed optional component architecture specified in detail in [docs/companion-architecture.md](file:///c:/Users/eetu.heino/OneDrive%20-%20Brand%20ID%20Oy/Documents/PineAI/docs/companion-architecture.md).

#### Deployment & Architecture Principles
- **Single-Container Default**: `pineai-companion` runs as one Docker container using SQLite metadata and filesystem object storage. No mandatory external PostgreSQL, Redis, RabbitMQ, Nginx, or Traefik.
- **Shared Companion Core**: Single unified Python backend (`pineai_companion_core`) serving Docker, Windows (Tauri/desktop shell), and Linux desktop deployments.
- **Outbound-Only Ingress**: Embedded ingress provider adapter (`cloudflared` bundled binary default, `ngrok` SDK supported alt) provides public HTTPS push without port forwarding, public IP, router config, or VPS.
- **Ingest Isolation**: Admin Web UI and API bind strictly to `127.0.0.1:8741`. Ingress tunnel routes only to public ingest allowlist (`127.0.0.1:8742`).
- **Mark VII Outbox**: Bounded queue on Mark VII (max 5 bundles / 64 MiB ceiling) with exponential backoff retries.

#### WiFi Pineapple Mark VII Role
- Recon integration & deterministic normalization.
- Baseline creation, comparison, and evidence lifecycle.
- Compact HTML/JSON report generation.
- Fully self-contained offline operation (100% functional without Companion).

#### Optional Companion Role
- API key storage and remote AI request handling.
- Large-scale historical analytics and fleet-wide audits.
- Isolated PCAP and raw packet parsing in unprivileged worker subprocesses.
- Cryptographic Ed25519 report signing.
- Multi-device management and long-term storage.
- Local LLM execution on operator's heavy host hardware.

----

## Lightweight High-Value Features

Features that add significant operational value with minimal hardware overhead on the Mark VII:

- **Device Doctor**: Real-time telemetry monitoring (RAM, CPU load, storage, identity key, transaction state).
- **Firmware Provenance**: Attaching device firmware and interface details to every snapshot.
- **Baseline Ageing**: Tracking baseline age and date of last comparable run.
- **Candidate Baseline Refresh**: Deterministic refresh suggestions without automatic activation.
- **Planned Maintenance & Expiring Suppressions**: Temporary alert suppression during maintenance windows.
- **Cross-Point Consistency**: Verifying if protected SSIDs or APs appear at expected physical points.
- **Protected SSID Lookalike Detection**: Unicode normalization and edit-distance checks specifically against protected SSID lists.
- **Assessment Template Export/Import**: Sharing points, profiles, and policies without sharing observation data.
- **Storage Retention & Pruning**: Controlled cleanup policies requiring backup verification.
- **Hash-Chained Event Log**: Tamper-evident logging of assessment mutations.
- **Signed Report Manifests**: Digest verification on-device, signature verification via Companion.

---

## Non-Goals (Exclusions from Mark VII Core)

To ensure device safety, performance, and clear product scope, the following MUST NOT be added to the Mark VII core:

- âŒ On-device local LLM execution.
- âŒ Embeddings or vector databases.
- âŒ Autonomous agent execution loops.
- âŒ Automated deauthentication, evil twin, or active radio manipulation.
- âŒ Always-on WIDS (Wireless Intrusion Detection System).
- âŒ Heavy PCAP parsing on-device.
- âŒ Map / GPS dashboard rendering on Mark VII.
- âŒ Multi-device fleet databases on Mark VII.
- âŒ Persistent client MAC tracking.
