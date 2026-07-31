# PineAssure product direction

## Product identity

**Product name:** PineAssure - Wireless Assurance for WiFi Pineapple
**Slogan:** Baseline. Detect drift. Prove changes.

The repository, Hak5 module identifier, package root, CLI command, and on-device
state directory remain `PineAI`, `pineai`, and `/root/.PineAI` for upgrade
compatibility. PineAssure is the customer-facing product name.

PineAssure answers one audit question:

> What did a site's wireless environment look like when it was approved, what
> changed, how trustworthy is the comparison, and which evidence proves the
> change?

The name describes the core value: repeatable measurements, versioned
baselines, deterministic drift, evidence, policy evaluation, and auditability.
It does not imply that a language model runs on the device. This naming decision
is not a trademark clearance.

## Authority boundary

The offline deterministic engine is the sole authority for:

- whether measurements are comparable;
- what changed between observations;
- which deterministic rule matched;
- which evidence supports a result;
- severity, confidence, lifecycle, and status;
- all machine-readable facts and report digests.

An optional AI provider may explain facts, summarize changes, draft
non-authoritative report prose, present alternative explanations, suggest safe
validation actions from an allowlist, and answer questions using validated
structured facts. AI output must not create or mutate findings, evidence,
severity, confidence, comparability, policy, lifecycle, or AuditRun state.

PineAssure must remain fully useful without a network connection, API key, or
AI provider.

## v0.7.0 - Repeatable Field Audit MVP

v0.7.0 adds an operator-driven workflow for auditing multiple physical
measurement points with pinned provenance.

### Capacity limits

- 16 active MeasurementPoints per assessment.
- 32 MeasurementPoint records per assessment including archived records.
- 16 assignments per AuditRun.
- 32 AuditRuns per assessment.
- One `in_progress` AuditRun per assessment; multiple draft runs are allowed.
- One Recon observation is resolved at a time across the module process.

These are product limits, not a claim that every combination of completed runs
fits within the separate snapshot, comparison, occurrence, event, memory, or
disk limits. Hardware telemetry must be used before those pools are expanded.

### Domain separation

`MeasurementPoint` stores only operator and physical-location context:

- stable identifier, name, description, and location label;
- physical notes and operator instructions;
- active or archived status, revision, and timestamps.

`MeasurementProfile` stores technical execution context:

- scan and radio profile identifiers;
- interface, bands, declared channels, and duration;
- immutable version identifier and digest.

`AuditRunMeasurement` pins at run creation:

- MeasurementPoint revision and digest;
- MeasurementProfile identifier, version, and digest;
- baseline version and digest;
- run-level AssuranceProfile version and digest.

These values are immutable for the lifetime of the run. Resolving a saved Recon
observation cannot replace them.

### Operator workflow

1. Create or select an assessment.
2. Define location-only MeasurementPoints.
3. Create a draft AuditRun with pinned assignments.
4. Start the run after reviewing its provenance.
5. Select an existing saved Hak5 Recon observation for the current point.
6. Resolve and compare it locally.
7. Retry an independently failed resolution or comparison if needed.
8. Complete or cancel the run and export a deterministic report.

The browser may be closed while a run is `in_progress`. The durable backend
state is the source of truth, so reopening the module continues the same run.
There is no separate paused state and no background execution.

### Storage layout

Each run uses a manifest and independently mutable measurement documents:

```text
assessments/<assessment_id>/audit_runs/<audit_run_id>/
|-- manifest.json
`-- measurements/
    `-- <measurement_id>.json
```

Updating one point must not rewrite other measurement files. Cross-file
mutations use the existing transaction journal, commit marker, atomic replace,
and recovery model. Raw Hak5 Recon JSON is processed in memory and never stored.

### Strict exclusions

v0.7.0 does not add:

- Recon start or stop actions;
- radio configuration or active radio operations;
- background scheduling or unattended collection;
- deauthentication, evil-twin, campaign, or credential workflows;
- on-device LLMs, embeddings, or vector databases;
- always-on WIDS behavior;
- heavy PCAP parsing or persistent client tracking.

## Release and hardware gate

The exact release candidate must pass Python 3.8, Angular 9/Node 16, schema,
documentation, package, secret, dependency, benchmark-smoke, and SBOM gates.
Workstation tests are not hardware validation.

`v0.7.0-rc.1` may be published as a prerelease with `hardware validation
pending` after all automated gates pass. The final `v0.7.0` tag and stable
release require the exact release assets to pass the documented physical Mark
VII smoke, resource, soak, recovery, and rollback procedure.

Target memory and storage budgets remain unverified until measured on the Mark
VII. Resource guards use documented conservative defaults and must fail closed;
the limits may be recalibrated only with recorded device evidence.

## Roadmap

### v0.7.1 - Operational Assurance

- deterministic evidence-gap suggestions from allowlisted reason codes;
- candidate baseline refresh without automatic activation;
- time-bounded maintenance and suppression records;
- storage doctor, retention previews, and recovery diagnostics.

### v0.8.0 - AI Analyst

- task-specific structured explanations and summaries;
- validated question-to-query planning executed locally;
- investigation themes and run briefings;
- provider abstraction with strict byte, timeout, token, and reference limits;
- AI annotations stored separately from authoritative domain state.

### v0.9.0 - Optional Companion and sensor expansion

The optional Companion may provide long-term analytics, fleet views, signing,
isolated heavy parsing, and provider-hosted AI. It must not be required for the
offline Mark VII workflow. See [Companion architecture](companion-architecture.md).

## Product principles

- Offline first: deterministic audit work never depends on cloud availability.
- Evidence first: every conclusion links to immutable local evidence.
- Operator controlled: mutations are explicit and revision checked.
- Privacy preserving: raw Recon and secrets are not exported by default.
- Resource bounded: inputs, artifacts, reports, locks, and concurrency are
  constrained for the Mark VII.
- Honest validation: workstation, CI, package, and hardware evidence are
  reported separately.
