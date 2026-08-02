# PineAssure v0.7 dependency risk acceptance

## Decision

PineAssure v0.7 retains the Hak5-compatible Angular 9 and Node 16 build stack.
It does not run `npm audit fix --force`, perform an unreviewed lockfile rewrite,
or introduce a major Angular upgrade in the release branch.

This is a conditional acceptance, not a statement that the dependency tree is
free of vulnerabilities. It is valid only for an exact release candidate whose
package, dependency audit JSON, CycloneDX SBOM, tests, and SHA-256 were produced
at the same commit.

## Dependency classes

| Class | Shipped on Mark VII | Treatment |
| --- | --- | --- |
| Python standard library | Host-provided | No third-party Python runtime package is installed by PineAssure. Python compatibility is tested separately. |
| Hak5 firmware and module API | Host-provided | `firmware_required` states the compatibility floor; final support requires physical validation. |
| UMD application bundle | Yes | Treated as one verified runtime artifact and scanned for source maps and secrets. |
| Backend Python sources | Yes | Exact files are allowlisted, compiled, imported in isolation, and hashed. |
| npm dependencies | Build inputs; some code may be bundled | Full and production npm audit reports are retained as release evidence. The SBOM distinguishes them from package files. |
| npm devDependencies | No | Used only for build, lint, tests, and packaging; still relevant to CI supply-chain risk. |
| `jsonschema` and Ruff | No | Development/test-only Python tools pinned in `requirements-dev.txt`. |

The package tarball is the authority for what is shipped. An `npm audit
--omit=dev` result is not by itself proof that a package is present in or absent
from the generated UMD bundle.

## Acceptance rationale

- Hak5 upstream compatibility currently constrains the frontend generation.
- The module operates behind the authenticated Pineapple UI and does not add a
  new listening service or browser origin.
- The deterministic backend uses the Python standard library and does not
  install packages on the target device.
- The release pipeline verifies a strict package allowlist, isolated imports,
  archive paths, file modes, source-map absence, likely secrets, and hashes.
- A rushed framework migration has a higher immediate correctness and platform
  compatibility risk than retaining the known stack for this release.

## Required compensating controls

1. Save `npm audit --json` and `npm audit --omit=dev --json` for every release
   candidate; do not suppress or rewrite their exit status into a success claim.
2. Generate the CycloneDX SBOM from the exact verified archive and lockfiles.
3. Review every critical/high item for reachability in the shipped UMD bundle,
   CI-only exposure, known exploitation, and platform impact.
4. Pin GitHub Actions by reviewed major version and keep workflow permissions
   read-only unless a release job explicitly needs more.
5. Reject source maps, unallowlisted files, secrets, symlinks, path traversal,
   special archive members, and non-canonical packages.
6. Record the final counts and per-advisory disposition in the release notes or
   attached validation evidence.

## Expiry and escalation

This acceptance expires when any of the following occurs:

- an exploitable dependency affects code shipped in the UMD bundle;
- a finding enables authentication bypass, arbitrary script execution, archive
  compromise, secret exposure, or CI credential theft;
- Hak5 publishes a supported newer module template;
- v0.8 or later introduces a new network-facing service;
- the project moves to a stable 1.0 technical identity.

An expired acceptance blocks release until the dependency is upgraded, removed,
isolated, or covered by a new evidence-based acceptance.
