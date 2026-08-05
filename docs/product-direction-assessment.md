# PineAssure product-direction assessment

## Executive assessment

PineAssure has a credible product boundary when it is sold as a portable,
offline wireless audit instrument rather than as an AI or attack product. Its
defensible value is not discovering every wireless threat. It is proving what
was observed at a named point, under a pinned measurement contract, how that
observation differs from an approved baseline, and whether the evidence is
strong enough to support the conclusion.

The v0.7 Repeatable Field Audit is a useful MVP only if provenance, recovery,
resource limits, and reports are more reliable than a spreadsheet-based field
process. A larger feature surface would weaken that value proposition before
the core has device evidence.

## Primary customer and job

The first customer is a security consultant, internal security team, or ICT
operator who periodically revisits offices, factories, warehouses, and other
bounded sites. They need to answer:

- Was each approved physical point measured using the intended profile?
- What changed since the accepted baseline?
- Which changes are direct observations and which are limited inferences?
- Can another reviewer reproduce the report from immutable evidence?
- Can the audit continue after browser closure, network loss, or device restart?

The workflow is not a replacement for an enterprise wireless controller,
continuous WIDS, spectrum analyser, or full packet-analysis platform.

## What v0.7 must prove

1. An operator can define up to 16 active points without duplicating technical
   scan settings into each point.
2. A run freezes the exact point, profile, baseline, and policy provenance
   before any observation is resolved.
3. Each point can succeed, fail, and retry independently without rewriting or
   corrupting unrelated point state.
4. A completed or cancelled run produces a deterministic, privacy-aware report.
5. The workflow remains useful offline and cannot start an active radio action.
6. Bounded operations fail safely on the Mark VII instead of risking an OOM or
   uncontrolled storage growth.

If any of these are missing, v0.7 is an internal prototype rather than a field
audit product.

## Product and engineering risks

### Device capacity is uncalibrated

Workstation benchmarks cannot establish Mark VII memory, storage, latency, or
power-loss behavior. Conservative limits and resource guards reduce risk but do
not replace exact-asset device tests. The product must label those limits as
provisional until telemetry is recorded.

### Saved Recon data has a measurement-quality ceiling

PineAssure can reason only from the data and metadata supplied by the Hak5
saved-scan API. Missing band, channel, duration, interface, or point discipline
reduces comparability. The report must disclose those limitations rather than
turning absence into certainty.

### A report can look more authoritative than its evidence

Professional HTML can overstate weak measurements. Report sections must keep
comparability, limitations, provenance, and direct before/after evidence next
to conclusions. AI prose, when later enabled, must be visibly non-authoritative.

### Legacy framework dependencies remain exposed

The Hak5 module template is tied to Angular 9 and Node 16 build tooling. A forced
upgrade could break upstream compatibility, while ignoring dependency findings
would hide supply-chain risk. v0.7 therefore separates shipped runtime content
from build/test dependencies, records audit evidence, and accepts only the
documented residual risk.

### Branding can create upgrade risk

A full technical rename would break package, state, and installed-module
identity. PineAssure should remain the display brand while compatibility names
stay `PineAI` until a separately designed migration, preferably at 1.0.

## Companion and AI timing

The Companion is premature before the local audit workflow has field evidence.
It would add identity, transport, fleet, storage, update, and privacy surfaces
while obscuring defects in the core. Keep it at v0.9 or later.

AI belongs after the deterministic output and evidence contracts are stable.
v0.8 may add explanations, summaries, and validated queries, but it must consume
existing facts rather than inventing a parallel finding engine. No AI feature is
required to validate v0.7.

## Recommended roadmap

- **v0.7.0:** operator-driven Repeatable Field Audit, deterministic reports,
  resource safety, and exact-asset release candidate validation.
- **v0.7.1:** evidence-gap suggestions, baseline refresh candidates, temporary
  suppressions, and storage/recovery diagnostics.
- **v0.8.0:** optional structured AI Analyst annotations over stable facts.
- **v0.9.0:** optional Companion and additional sensors after local field use
  justifies the operational complexity.

## Go/no-go position

Release `v0.7.0-rc.1` only after all automated gates pass at one commit and the
assets are reproducible. Release final `v0.7.0` only after those exact assets
pass the documented Mark VII smoke, resource, soak, recovery, and rollback
gates. Hardware-pending language is a release constraint, not a documentation
footnote.
