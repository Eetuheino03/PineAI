# PineAI product direction

## Purpose

PineAI is the analysis and assurance layer that is missing from the WiFi
Pineapple Mark VII. It turns repeatable Recon observations into versioned
baselines, deterministic changes, evidence-backed findings, and exportable
reports.

PineAI is not an attack module and the language model is not a product
decision-maker. The complete Baseline & Drift workflow must work without an
internet connection or an AI provider.

## Decision boundary

The deterministic engine is authoritative for:

- what changed between two Recon observations;
- whether two scans are comparable;
- which finding rule matched;
- which evidence belongs to a finding;
- finding severity, confidence, status, and lifecycle;
- report facts and all machine-readable output.

An optional AI provider may:

- explain existing findings in Finnish or English;
- describe alternative explanations;
- suggest safe validation steps;
- summarize observed changes;
- draft clearly labelled technical report prose.

AI output may never create findings, change deterministic facts, assign
severity or confidence, resolve findings, operate radios, or produce executable
commands.

## Product language

| Previous concept | Current concept |
| --- | --- |
| Target Profiler | Asset & Change Resolver |
| Attack-Path Advisor | Investigation Advisor |
| Adaptive Recon | Evidence Gap Planner |
| Engagement | Assessment |
| Attack path | Validation step |
| Interest score | Finding severity and confidence |

The previous Attack-Path Advisor branding and workflow are removed from the
public product.

## Offline-first and privacy rules

- Recon observations and model output are always untrusted data.
- Raw Hak5 Recon responses are processed in memory and are not persisted.
- Normalized snapshots may retain real SSIDs and BSSIDs locally on the device.
- MAC addresses and BSSIDs are never sent to an AI provider.
- SSIDs are shared with an AI provider only after an explicit opt-in.
- Secrets, local notes, audit text, and authorization material never leave the
  device.
- AI failure must not prevent comparison, finding evaluation, lifecycle
  updates, or deterministic reporting.

## Roadmap

### v0.6.x - Baseline & Drift

Introduced in `v0.6.0`; the current comparability-hardening patch is
`v0.6.1`.

- read saved scans through the authenticated Hak5 Recon REST API;
- resolve assets and scan metadata;
- create, version, and explicitly activate immutable baselines;
- calculate AP and SSID drift;
- evaluate the first eight deterministic finding rules;
- manage finding lifecycle;
- export deterministic JSON and standalone HTML reports;
- optionally add labelled AI explanations and report prose;
- provide a complete responsive Angular UI.

### v0.7.0 - Wireless Assurance

- continuous observation of new saved scans;
- multiple locations and baseline timelines;
- deterministic rogue and clone suspicion scoring;
- persistent suppressions and false-positive memory;
- notifications for material changes.

### v0.8.0 - AI Analyst

- structured questions over findings and evidence;
- evidence-gap suggestions;
- provider abstraction for local and OpenAI-backed models;
- broader daily and cross-assessment summaries.

## Ecosystem role

Recon and PineRecon collect and display observations. DeauthDetect monitors a
specific attack type. TCPDump and hcxdumptool collect packet data. WiGLE and
MACInfo enrich observations. PineAI connects history, baselines, changes,
evidence, findings, and reports into a repeatable wireless assurance workflow.
