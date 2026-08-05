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

## v0.7.0-rc.1 audit snapshot and advisory disposition

The non-mutating 2026-08-04 audit reports 177 findings in the complete legacy
development tree: 12 low, 73 moderate, 74 high, and 18 critical. The
production dependency view reports three direct high-severity Angular
packages. npm's offered remediation is Angular 22.1.0, an incompatible major
framework and Hak5-host migration; it is not applied in this release branch.

Angular framework modules in the UMD wrapper are supplied by the authenticated
Hak5 application. PineAI does not ship those npm package directories, but it
does execute against the host's Angular runtime. The following table is a
static reachability and residual-risk decision, not a claim that Angular 9 is
generally safe.

| Advisory | Affected surface | PineAI v0.7.0-rc.1 disposition |
| --- | --- | --- |
| `GHSA-58c5-g7wp-6w37` | Angular HTTP XSRF token and protocol-relative URLs | Not reachable from a PineAI request parameter: the service combines the Hak5-provided same-origin base with fixed API paths, and saved-scan IDs are URI-encoded. Retained as host-runtime residual risk. |
| `GHSA-48r7-hpm6-gfxm` | `formatDate` memory exhaustion | PineAI does not import or call `formatDate` or `DatePipe`. Not reached by the current bundle surface. |
| `GHSA-39pv-4j6c-2g6v` | `HttpTransferCache` weak cache keys | PineAI has no SSR or transfer-cache configuration. Not reached by the current client-only module. |
| `GHSA-p3vc-36g9-x9gr` | number-format `digitsInfo` memory exhaustion | The only NumberPipe use has the fixed literal format `1.0-0`; untrusted data cannot control the format string. Retained as host-runtime residual risk. |
| `GHSA-q6f4-qqrg-jv6x` | credentialed `HttpTransferCache` information leak | PineAI has no SSR or transfer cache. Not reached by the current client-only module. |
| `GHSA-jhpw-976m-542j` | `HttpTransferCache` cache-key ambiguity | PineAI has no SSR or transfer cache. Not reached by the current client-only module. |
| `GHSA-jrmj-c5cx-3cw6` | SVG script-attribute XSS | The production UMD has AOT templates and no SVG/MathML templates, dynamic compiler call, `innerHTML`, or sanitizer bypass. Not reached by the current template surface. |
| `GHSA-v4hv-rgfq-gp49` | SVG animation/URL and MathML attribute XSS | PineAI has no SVG/MathML templates or untrusted HTML sink. Not reached by the current template surface. |
| `GHSA-58w9-8g37-x9v5` | two-way property-binding sanitization bypass | PineAI does not compile untrusted templates or use two-way binding on HTML/SVG security-sensitive attributes. Retained as host-compiler residual risk. |
| `GHSA-f3m7-gqxr-g87x` | template/attribute namespace sanitization bypass | PineAI has no dynamic templates or namespaced SVG/MathML bindings. Its two dynamic `aria-label` bindings remain text attributes. Not reached by the current template surface. |
| `GHSA-jj27-h5hq-8x99` | Angular i18n event-handler XSS | PineAI does not use Angular runtime i18n or i18n event attributes. Not reached by the current bundle surface. |
| `GHSA-c75v-2vq8-878f` | Angular core XSS | PineAI has no untrusted HTML sink, sanitizer bypass, or dynamic template compilation. The affected host core remains an accepted residual platform risk. |
| `GHSA-prjf-86w9-mfqv` | Angular i18n XSS | PineAI does not use Angular runtime i18n. Not reached by the current bundle surface. |
| `GHSA-692r-grfm-v8x7` | dynamic component/template namespace XSS | PineAI does not compile operator or Recon strings as components or templates. Not reached by the current bundle surface. |
| `GHSA-rgjc-h3x7-9mwg` | hydration DOM clobbering and cache poisoning | PineAI is a client-only Hak5 module and does not enable SSR, hydration, or transfer cache. Not reached by the current bundle surface. |

The complete audit contains additional critical and high findings in build and
test dependencies that are not installed on Mark VII. They remain CI
supply-chain exposure because `npm ci`, lint, tests, and the Angular build
execute them. The exact machine-readable full audit is retained with each CI
candidate. Compensating controls are the committed lockfile, clean disposable
build, read-only workflow token, strict package allowlist, secret scan,
byte-identical main/tag artifact comparison, and prohibition on automatic
`npm audit fix` or lockfile mutation. This grouped build-tree acceptance
expires under the escalation conditions below.

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
