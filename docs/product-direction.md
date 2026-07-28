# PineAI product direction

## Customer problem and position

PineAI answers one audit question:

> What did a site's wireless environment look like when it was approved,
> what changed, how trustworthy is the comparison, and which evidence proves
> the change?

The product position is:

**PineAI Baseline & Drift — Portable offline wireless change auditing for
WiFi Pineapple.**

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

Customer-facing v0.6.2 output is deliberately divided into:

- **observed changes**, which state only what the measurements show and have
  neither severity nor lifecycle;
- **policy deviations**, which are violations of an explicitly activated
  fixed policy and have deterministic severity and lifecycle;
- **security findings**, which require both measurement evidence and active
  inventory/policy context and have deterministic severity and lifecycle.

Certainty is categorical (`confirmed`, `probable`, or `limited`). PineAI does
not present uncalibrated confidence percentages as customer assurance.

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

### v0.6.2 - Customer Audit Foundation

- strict 2–5 scan consensus baselines;
- versioned measurement profiles;
- immutable approved inventory and fixed policy profiles;
- observed change, policy deviation, and security finding separation;
- point-in-time occurrences and before/after evidence;
- comparison, current-state, and full-history customer reports;
- Guided and Expert user interfaces;
- root/SSH continuity backups.

### v0.7.0 - Repeatable Field Audits

- recurring operator workflows and audit scheduling;
- multiple repeatable measurement points;
- comparison timelines and deliberate suppressions;
- field-tested quality calibration.

### v0.8.0 - Sensor and Data Source Expansion

- additional passive sensors and evidence types;
- enriched but source-attributed asset metadata;
- broader wireless environment coverage without changing the deterministic
  authority boundary.

### v0.9.0 - AI Analyst

- structured questions over findings and evidence;
- evidence-gap explanations;
- provider abstraction for local and hosted models;
- broader daily and cross-assessment summaries.

## Ecosystem role

Recon and PineRecon collect and display observations. DeauthDetect monitors a
specific attack type. TCPDump and hcxdumptool collect packet data. WiGLE and
MACInfo enrich observations. PineAI connects history, baselines, changes,
evidence, findings, and reports into a repeatable wireless assurance workflow.
