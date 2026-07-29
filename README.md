# PineAI

PineAI Baseline & Drift is a portable, offline wireless change-auditing
module for the WiFi Pineapple Mark VII. It answers what a site looked like in
an approved state, what changed, how trustworthy the comparison is, and which
evidence proves each result.

![PineAI Banner](docs/asset.png)

PineAI is not an attack module. Version `0.6.3` is the Customer Audit
Foundation:

1. load a saved Recon scan through the authenticated Hak5 session;
2. resolve access points and SSIDs into stable local assets;
3. build and explicitly activate a 2–5 scan consensus baseline;
4. activate a versioned customer inventory and fixed policy;
5. compare a later scan and explain measurement comparability;
6. separate observed changes, policy deviations, and security findings;
7. inspect point-in-time before/after evidence;
8. export comparison, current-state, or full-history JSON/HTML reports.

The complete workflow works without an API key or internet connection. An
optional AI provider may explain existing findings or draft clearly labelled
report prose, but it cannot create findings or change facts, severity,
confidence, comparability, or lifecycle state.

## Compatibility

- WiFi Pineapple Mark VII
- Hak5 module metadata and package layout
- Angular 9 frontend used by the official module template
- Python 3 backend using the bundled `pineapple.modules` library
- Python standard library only; no additional Mark VII package is required

## Development

Use Node.js 16 for compatibility with the upstream Hak5 module build.

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run build -- --prod
npm test -- --watch=false --browsers=ChromeHeadlessCI
python3 -m unittest discover -s tests -v
```

Create an installable archive with:

```bash
./build.sh package
bash scripts/verify-package.sh PineAI-0.6.3.tar.gz
```

The resulting `PineAI-0.6.3.tar.gz` archive can be uploaded through the WiFi
Pineapple management interface. During development, copy the built
`dist/PineAI/` directory to `/pineapple/modules/PineAI/`.

The `v0.6.3` release is published as a pre-release until its smoke test is
completed on a physical Mark VII. Automated tests, package integrity, and
offline behavior are verified independently; no physical-device verification
is claimed yet.

## Operator workflow

PineAI reads only saved scans in this release:

```text
GET /api/recon/scans
GET /api/recon/scans/:scan_id
```

The Angular frontend uses the already-authenticated Hak5 session and passes
the loaded JSON to the PineAI module backend. PineAI does not store the
Pineapple root password and `0.6.1` does not start or stop a Recon scan.

The recommended sequence is:

```text
create assessment
    -> select a versioned measurement profile
    -> resolve 2-5 saved Recon scans
    -> preview, create, and explicitly activate consensus baseline
    -> import/edit and activate inventory plus fixed policy
    -> compare and save a later observation
    -> inspect immutable evidence
    -> prepare and export a scoped JSON or HTML report
```

See [the frontend guide](docs/frontend.md) for the operator workflow and
[the backend API](docs/backend-api.md) for module action contracts. The
machine-readable contract is
[`baseline-drift-v1.schema.json`](docs/schemas/baseline-drift-v1.schema.json).
Installation and first-run checks are in
[the Mark VII installation guide](docs/install-mark-vii.md).

## Deterministic authority

The local engine alone decides:

- what changed;
- whether two scans are comparable;
- which rule matched;
- which evidence supports a finding;
- finding severity and confidence;
- finding lifecycle state;
- all factual and machine-readable report content.

Observed changes never receive a severity or lifecycle. Policy deviations are
created only from the explicitly activated fixed policy, and security findings
require both observed evidence and active inventory/policy context. Result
certainty is categorical (`confirmed`, `probable`, or `limited`) rather than
an uncalibrated percentage.

Hak5 encryption values are treated as opaque numeric codes. PineAI reports a
change but does not call it an upgrade or downgrade without a verified
firmware-specific mapping.

## Privacy

- Raw Hak5 Recon JSON is processed in memory and is not persisted.
- Normalized snapshots may retain real SSIDs and BSSIDs locally.
- Stable public IDs are derived with a private HMAC-SHA256 key.
- MAC addresses and BSSIDs never leave the device.
- SSIDs leave the device only when the operator enables `share_ssids`.
- Local notes, secrets, audit text, and legacy authorization material are
  never included in an AI request.
- An AI error never blocks comparison, finding evaluation, lifecycle updates,
  or deterministic reporting.

The optional OpenAI key is stored in `/root/.PineAI/openai.key` with mode
`0600`. It is never accepted as a command-line argument, returned to Angular,
logged, or committed.

## Storage

Assessments are stored below `/root/.PineAI/assessments/`. Directories use
mode `0700`; assessment, baseline, snapshot, comparison, occurrence, profile,
report, finding, and audit files use mode `0600`. Multi-file mutations use a
recoverable transaction journal. Baseline and AssuranceProfile versions are
immutable and activation always requires an explicit, revision-checked
request.

The pseudonymization key defines stable asset, evidence, and finding identity.
If identity-bound data exists and the key is missing or invalid, PineAI blocks
new analysis instead of silently generating a different identity.

Root/SSH operators can create, verify, and safely unpack continuity backups:

```text
pineai backup create --output /root/pineai-backup.tar.gz
pineai backup verify --input /root/pineai-backup.tar.gz
pineai backup restore-staging --input /root/pineai-backup.tar.gz \
  --target /root/pineai-restore-staging
```

Backups contain assessments, profiles, configuration, and the
pseudonymization key. They never contain `openai.key`, are not encrypted, and
must be handled as sensitive material.

Legacy engagement data is neither migrated nor read by `0.6.1`. It is left
untouched so an operator can recover or remove it separately.

## Upstream contribution

This repository follows the structure generated by Hak5's
`pineapple-modules/create.sh`. Before requesting inclusion in the official
module repository:

- bump `projects/PineAI/src/module.json` for every release;
- build and package from a clean dependency installation;
- test the package on a physical Mark VII;
- document all network destinations and data sent off-device;
- submit the module directory to `hak5/pineapple-modules` as a pull request.

See [CONTRIBUTING.md](CONTRIBUTING.md),
[the architecture](docs/architecture.md), and
[the product direction](docs/product-direction.md).

## Safety and scope

Use PineAI only with wireless environments you own or are authorized to
assess. The module is read-only toward the radio in `0.6.3`: it analyzes saved
Recon results and cannot execute validation steps, shell commands, deauth,
evil-twin, association, capture, or scan-start actions.

The physical Mark VII smoke test for `v0.6.3` is pending. This limitation is
also recorded in the release notes and implementation handoff.

## License

Project-authored code is available under the MIT License. The scaffold is
derived from Hak5's official WiFi Pineapple module template; upstream
dependencies and Hak5 platform components retain their respective terms.
