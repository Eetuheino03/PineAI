# Customer Audit Foundation workflow

PineAI `0.6.3` uses saved Hak5 Recon observations to create repeatable,
evidence-backed wireless change audits. It never starts or stops a radio.

## Guided workflow

The default Guided mode has seven explicit steps. Moving between steps never
performs a mutation automatically.

1. Select or create one assessment for one site/environment.
2. Select a versioned measurement profile and review platform capability.
3. Load two to five non-empty saved Recon scans into memory.
4. Preview and create a consensus baseline, or preview a later comparison.
5. Preview/import inventory, create an immutable AssuranceProfile, and
   explicitly activate it.
6. Review comparability, observed changes, policy deviations, security
   findings, and before/after evidence; save only after confirmation.
7. Choose a report scope and privacy profile, prepare its immutable manifest,
   then generate the report using the returned scope digest.

Expert mode exposes the original nine domain views. Both modes use the same
backend contracts and revision checks.

## Consensus baseline

A new consensus baseline requires two to five resolved, non-empty scans from
the same location, measurement point, measurement-profile revision, interface,
declared bands, and declared channels. The source order and each scan's AP
order do not affect the model digest.

The default source window is 24 hours. An operator may deliberately choose no
time limit. The unbounded selection is saved as a report limitation.

- `core`: present in at least `ceil(0.8 * scan_count)` scans;
- `recurring`: present at least twice but below the core threshold;
- `singleton`: present once.

Only a core AP can be the subject of an absence inference. Returning recurring
or singleton assets are already known to the baseline and are not classified
as new.

## Inventory and fixed policy

Inventory CSV accepts UTF-8, with or without BOM, and an explicit comma,
semicolon, or tab delimiter. The required base columns are:

```text
site,ssid,bssid,vendor,role,approved
```

Optional columns describe a label, required presence, allowed opaque Hak5
encryption codes, WPS, allowed channels, allowed vendors, and local notes.
Preview validates size, duplicates, BSSID syntax, and values. Raw CSV is never
persisted. Export neutralizes values that spreadsheet software could interpret
as formulas.

An AssuranceProfile is one immutable atomic version of inventory and fixed
policy. Its inventory coverage is `partial` by default. Activating
`authoritative` coverage requires a separate confirmation.

The fixed deviations are:

- asset absent from authoritative inventory;
- required asset missing from a comparable observation;
- SSID not allowed;
- opaque encryption code not allowed;
- WPS not allowed;
- channel not allowed;
- vendor not allowed.

An `Unknown` vendor never violates policy by itself.

## Result authority

- `observed_change`: a measured or diagnostic before/after fact. It has
  certainty, but no severity or lifecycle.
- `policy_deviation`: a violation of the active fixed policy. It has
  deterministic severity and lifecycle.
- `security_finding`: a policy-and-inventory-confirmed security risk. It has
  deterministic severity and lifecycle.

Certainty is:

- `confirmed` for a direct before/after observation in comparable data;
- `probable` for an absence inference, or a positive change in partially
  comparable data;
- `limited` for diagnostic non-comparable data.

Limited results do not mutate issue lifecycle. Partially comparable positive
evidence may open an issue, but only a comparable clean observation can resolve
one.

## Evidence and reports

Every new comparison saves an immutable occurrence set. `get_evidence_bundle`
resolves a selected item to its baseline and current values, evidence records,
quality factors, policy reference, and limitations.

Report scope is mandatory:

- `comparison`: immutable facts from one comparison;
- `assessment_current`: current active deviations and findings;
- `assessment_history`: complete occurrences and lifecycle history.

`prepare_report` returns a manifest, warnings, and `scope_digest`.
`generate_report` recalculates the facts and rejects a stale digest. JSON and
standalone script-free HTML are rendered from the same canonical fact model.

`local_full` contains local audit identifiers and wireless values.
`share_safe` removes MAC/BSSID values and keeps SSIDs only when sharing has
been explicitly enabled.

## Identity continuity and backup

The HMAC identity key is part of the evidence chain. If assessments exist and
the key is missing or invalid, analysis mutations fail with
`identity_key_missing` or `identity_key_invalid`.

Continuity backup is a root/SSH operation:

```text
pineai backup create --output /root/pineai-backup.tar.gz
pineai backup verify --input /root/pineai-backup.tar.gz
pineai backup restore-staging --input /root/pineai-backup.tar.gz \
  --target /root/pineai-restore-staging
```

The archive includes assessment state, profiles, configuration, and the
identity key. It excludes `openai.key`. The archive is integrity-checked but
not encrypted, so store and transport it as sensitive material. Restore only
extracts into an empty staging directory; it never overwrites live state.

