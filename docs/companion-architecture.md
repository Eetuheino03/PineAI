# PineAI / PineAssure Companion Architecture Guide

> **Status**: Proposed / Design Specification (Target: `v0.9.0` MVP)  
> **Authority**: Non-authoritative optional enhancement. WiFi Pineapple Mark VII retains 100% offline deterministic authority.  
> **Hardware Validation**: Physical WiFi Pineapple Mark VII validation remains pending for release artifacts; this design document does not claim physical device validation.

---

## 1. Status and Scope

This document specifies the technical architecture for the **PineAI Companion** (also referred to as **PineAssure Companion**) and its underlying backend implementation, **Companion Core**.

The Companion is a strictly **optional** companion system for the WiFi Pineapple Mark VII. It allows a Mark VII device to push bounded, privacy-filtered audit bundles directly to an operator-controlled Companion instance whenever outbound internet connectivity is available—**without requiring public IP addresses, router port forwarding, inbound firewall rules, VPN clients on the Mark VII, or root SSH credentials stored in the Companion**.

---

## 2. Goals

1. **Outbound-Only Ingress**: Establish a direct HTTPS push path from the Mark VII to the Companion using an embedded outbound ingress tunnel adapter on the Companion.
2. **Compact Single-Container Default**: The default MVP deployment MUST run as a single Docker container using one persistent data volume, SQLite for metadata, and filesystem object storage.
3. **Shared Companion Core**: A single unified backend implementation written in Python that serves:
   - Single-container Docker deployment;
   - Native Windows desktop application (e.g., via Tauri or a lightweight desktop shell wrapping Companion Core as a local sidecar);
   - Native Linux desktop application;
   - Future self-hosted multi-container server deployment.
4. **Offline First & Mark VII Independence**: The Mark VII remains 100% operational without a Companion, without internet access, and without external AI services.
5. **Privacy by Default**: Bounded audit bundles exclude raw Hak5 Recon JSON payloads by default and support pseudonymized / share-safe privacy profiles.
6. **Streaming & Bounded Resource Footprint**: Mark VII upload generation and transport MUST stream data without loading full bundles into Mark VII RAM.

---

## 3. Non-Goals

- ❌ Replacing or overriding the local deterministic authority of the Mark VII.
- ❌ Requiring mandatory external microservices (PostgreSQL, Redis, RabbitMQ, Nginx, Traefik) for the MVP.
- ❌ Requiring public IP addresses, router port forwarding, or inbound firewall openings on the Companion host.
- ❌ Storing or requiring Mark VII root SSH passwords/keys on the Companion.
- ❌ Automatic radio manipulation, deauthentication, evil-twin, or active attack workflows.
- ❌ Executing local LLM models on the WiFi Pineapple Mark VII hardware.

---

## 4. Local-versus-Companion Responsibility Boundary

| Responsibility Area | WiFi Pineapple Mark VII (Local Engine) | PineAI / PineAssure Companion (Companion Core) |
| --- | --- | --- |
| **Recon Observations** | Ingests, normalizes, and filters saved Recon scans locally in RAM | Receives normalized snapshots contained in uploaded audit bundles |
| **Asset & Drift Resolution** | Authoritative for stable HMAC asset IDs, baseline consensus, comparability, and drift | Stores historical assessment baselines; performs cross-assessment analytics |
| **Finding Evaluation & Lifecycle** | Authoritative for rule matching, finding severity, certainty, lifecycle state, and evidence binding | Stores finding history; correlates findings across multiple physical sites or runs |
| **Audit Execution** | Executes `MeasurementPoint` and `AuditRun` field workflows; manages local outbox | Receives sealed `AuditRun` bundles; provides long-term visualization and reports |
| **Reporting & Export** | Generates offline compact HTML/JSON reports; exports privacy-filtered bundles | Generates enriched multi-run reports; signs report manifests cryptographically |
| **AI Integration** | Optional task-bounded requests (Evidence Gap Advisor) with local AST execution | Hosted provider abstraction or local LLM execution on heavy host hardware |
| **Storage & Retention** | Bounded local assessment storage and strict outbox space reservation | Scalable long-term storage, bundle archiving, retention policy enforcement, and pruning |

---

## 5. Single-Container Deployment

The Companion MVP MUST default to a single-container architecture (`pineai-companion`).

```text
pineai-companion (Docker Container)
├── Companion API (FastAPI / ASGI)
├── Local Administration Web UI (127.0.0.1:8741)
├── Device Ingest Service (127.0.0.1:8742)
├── Embedded Ingress Adapter (cloudflared / ngrok SDK)
├── SQLite Metadata Storage (/var/lib/pineai-companion/companion.db)
├── Filesystem Object Storage (/var/lib/pineai-companion/objects/)
├── Internal Bounded Job Queue (SQLite-backed)
├── Subprocess Worker Manager (Isolated PCAP / Parser Subprocesses)
├── AI Provider Adapter (Hosted API / Local LLM Bridge)
└── Report Generation & Signing Component
```

### Exclusions from MVP Container Stack

The default single-container MVP MUST NOT require:
- `nginx` or `traefik` (ingress handled by embedded adapter or local ASGI server);
- `redis` or `rabbitmq` (job queue handled by SQLite-backed queue table);
- `postgresql` (metadata handled by SQLite with WAL mode enabled);
- Separate tunnel or worker containers.

---

## 6. Shared Companion Core Architecture

To prevent code duplication, all deployment targets wrap the exact same Python package (`pineai_companion_core`):

```text
                               ┌───────────────────────────────────┐
                               │       pineai_companion_core       │
                               │  (API, Ingest, Jobs, Storage, AI)  │
                               └─────────────────┬─────────────────┘
                                                 │
         ┌───────────────────────────────────────┼───────────────────────────────────────┐
         ▼                                       ▼                                       ▼
┌──────────────────┐                   ┌──────────────────┐                   ┌──────────────────┐
│ Single Docker    │                   │ Native Windows   │                   │ Native Linux     │
│ Container Image  │                   │ App (Tauri +     │                   │ App (Tauri +     │
│ (Linux x86_64/   │                   │ Companion Core   │                   │ Companion Core   │
│ arm64)           │                   │ Sidecar)         │                   │ Sidecar)         │
└──────────────────┘                   └──────────────────┘                   └──────────────────┘
```

---

## 7. Docker Deployment Specification

- **Image Name**: `pineai/companion:v0.9.0`
- **Volume Mount**: Single persistent data volume mounted to `/var/lib/pineai-companion`.
- **Environment Variables**:
  - `PINEAI_COMPANION_PORT_ADMIN=8741` (Bound to `127.0.0.1` by default)
  - `PINEAI_COMPANION_PORT_INGEST=8742` (Bound to `127.0.0.1`, reachable via Ingress Adapter)
  - `PINEAI_INGRESS_PROVIDER=cloudflared` (or `ngrok`, `disabled`, `direct`)
  - `PINEAI_INGRESS_TOKEN=<token>`
- **Docker Run Example**:
  ```bash
  docker run -d \
    --name pineai-companion \
    --restart unless-stopped \
    -p 127.0.0.1:8741:8741 \
    -v pineai_companion_data:/var/lib/pineai-companion \
    -e PINEAI_INGRESS_PROVIDER=cloudflared \
    -e PINEAI_INGRESS_TOKEN="ey..." \
    pineai/companion:v0.9.0
  ```

---

## 8. Windows and Linux Desktop Packaging

For operators who prefer not to run Docker, native desktop packages bundle Companion Core:

- **Windows**: Windows Installer (`.msi` / `.exe`) bundling Companion Core Python executable + Tauri WebView shell. Stores data in `%LOCALAPPDATA%\PineAI-Companion\`.
- **Linux**: AppImage / `.deb` bundling Companion Core Python executable + Tauri shell. Stores data in `~/.local/share/pineai-companion/`.
- **Shared Codebase**: Both desktop variants run the exact same `pineai_companion_core` codebase, schemas, SQLite migrations, and ingress adapters as the Docker container.

---

## 9. Network & Ingress Architecture

```text
 WiFi Pineapple Mark VII                          Public Ingress                         PineAI Companion
┌───────────────────────┐                    ┌──────────────────────┐                 ┌──────────────────────┐
│  - Bounded Outbox     │                    │ Public Endpoint      │                 │ Companion Core       │
│  - Streaming Upload   │ ──── HTTPS Push ──►│ https://ingest.x.net │◄─ Tunnel Conn ──┤ - Ingest API (:8742) │
│  - Bearer/HMAC Auth   │                    │ (Hosted Ingress)     │                 │ - Admin UI (:8741)   │
└───────────────────────┘                    └──────────────────────┘                 └──────────────────────┘
```

1. Companion Core initializes the `IngressProvider` adapter on startup.
2. The Ingress Adapter establishes an outbound connection to the ingress provider.
3. The provider assigns a public HTTPS endpoint (e.g., `https://ingest-cmp-a1b2.example.net`).
4. The Mark VII executes standard outbound HTTPS requests (`POST`, `PUT`) to the public ingest endpoint.
5. No incoming ports are opened on the Companion's host network firewall.

---

## 10. Provider Abstraction (`IngressProvider`)

```python
from abc import ABC, abstractmethod
from typing import Dict, Any

class IngressProvider(ABC):
    @abstractmethod
    def start(self, local_ingest_url: str) -> str:
        """Start ingress tunnel and return the public HTTPS endpoint URL."""
        pass

    @abstractmethod
    def status(self) -> Dict[str, Any]:
        """Return operational status, uptime, public URL, and health metrics."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop ingress tunnel cleanly."""
        pass
```

---

## 11. Initial Provider Evaluation

| Ingress Option | Outbound-Only? | Single-Container Fit | Desktop Fit | Custom Domain | Licensing & Trade-offs |
| --- | --- | --- | --- | --- | --- |
| **Bundled `cloudflared` (Recommended Default)** | ✅ Yes | ✅ High (single binary inside image) | ✅ High | ✅ Yes | Free tier available; requires Cloudflare account/tunnel token; reliable production binary. |
| **Embedded `ngrok` Agent SDK (Supported Alt)** | ✅ Yes | ✅ High (Python SDK in-process) | ✅ High | ⚠️ Paid tier | Clean in-process SDK; free tier has endpoint volatility/bandwidth caps; vendor dependence. |
| **Disabled / Direct HTTPS** | ❌ No (requires public IP) | ✅ High | ✅ High | ✅ Yes | Requires manual port forwarding / reverse proxy; useful for local LAN or VPN setups. |

### Decision
- **Recommended Default**: Bundled `cloudflared` subprocess managed by Companion Core process supervisor.
- **Supported Alternative**: Embedded `ngrok` Agent SDK for zero-subprocess in-process tunnel setup.
- **Status**: Proposed design; decision open for review before implementation.

---

## 12. Administration & Ingest Isolation

To protect the Companion against unauthorized internet access, administration interfaces MUST be isolated from device ingest endpoints:

```text
Listening Port 8741 (127.0.0.1 ONLY)
  ├── GET /admin/
  ├── GET /api/v1/admin/assessments
  ├── GET /api/v1/admin/reports
  └── POST /api/v1/admin/enrollment/create

Listening Port 8742 (Ingress Router Target) — PUBLIC ALLOWLIST ONLY
  ├── POST /api/v1/enrollment/exchange
  ├── POST /api/v1/uploads
  ├── PUT  /api/v1/uploads/{upload_id}/content
  ├── POST /api/v1/uploads/{upload_id}/complete
  └── GET  /api/v1/uploads/{upload_id}/receipt
```

Any attempt to access administration endpoints via the public ingest tunnel is rejected with `404 Not Found` or `403 Forbidden` at the ingress routing layer.

---

## 13. Pairing Design

Pairing uses an explicit, out-of-band opt-in workflow:

```text
Operator                  Companion Admin UI (:8741)            WiFi Pineapple Mark VII
   │                               │                                        │
   │─── 1. Generate Enrollment ───►│                                        │
   │    Package                    │                                        │
   │◄── 2. Short-Lived Token ──────┤                                        │
   │    (JSON file / QR)           │                                        │
   │                                                                        │
   │─── 3. Copy Token via SSH/Web ─────────────────────────────────────────►│
   │                                                                        │
   │                               │◄─── 4. POST /enrollment/exchange ──────│
   │                               │    (Exchanges token for Device ID      │
   │                               │     & Device Identity Secret)          │
   │                               │                                        │
   │                               ├─── 5. Issue Device Credential ────────►│
   │                               │    Store in /root/.PineAI/companion.key│
```

### Enrollment Payload (`enrollment_package.json`)
```json
{
  "schema_version": "1.0",
  "companion_id": "cmp_9f8e7d6c5b4a",
  "ingest_endpoint": "https://ingest-cmp-a1b2.example.net",
  "enrollment_token": "enr_tmp_88192a73b4c9102f",
  "expires_at": "2026-07-31T15:00:00Z",
  "expected_companion_fingerprint": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

## 14. Device Authentication

Authentication uses per-device HMAC-SHA256 signatures (or Bearer tokens over HTTPS):

```text
X-PineAI-Device-ID: dev_mk7_a1b2c3d4
X-PineAI-Timestamp: 1785493200
X-PineAI-Nonce: nce_9921ab83c710
X-PineAI-Signature: hmac_sha256(device_secret, "POST\n/api/v1/uploads\n1785493200\nnce_9921ab83c710\n<payload_hash>")
```

- **Replay Resistance**: Nonce store with 5-minute clock-skew tolerance window.
- **Revocation**: Companion admin can revoke individual `device_id` credentials instantly.

---

## 15. Bundle Format Direction

Uploaded audit bundles use standard Gzip-compressed tarballs (`.tar.gz`) with strict structure:

```text
bundle_manifest.json
checksums.json
assessment.json
measurement_points.json
audit_runs/
  ar_01.json
  measurements/
    arm_01.json
snapshots/
  snap_1001.json
comparisons/
  comp_2001.json
evidence/
  ev_3001.json
annotations/
  ai_4001.json
```

- `raw_recon_included`: MUST default to `false`. Raw Hak5 Recon scan payloads are excluded from normal bundles to protect memory and privacy.

---

## 16. Streaming Upload API

1. `POST /api/v1/uploads` -> Initialize upload session (`upload_id`, expected size, SHA-256).
2. `PUT /api/v1/uploads/{upload_id}/content` -> Stream fixed-size chunks (e.g., 512 KiB chunks) with `Content-Range`.
3. `POST /api/v1/uploads/{upload_id}/complete` -> Finalize, calculate full SHA-256 digest, move to validation queue.
4. `GET /api/v1/uploads/{upload_id}/receipt` -> Fetch cryptographic upload receipt confirming import.

---

## 17. WiFi Pineapple Mark VII Outbox

The Mark VII implements a bounded outbox queue under `/root/.PineAI/outbox/`:

```yaml
outbox_config:
  max_bundles: 5
  max_total_bytes: 67108864  # 64 MiB hard ceiling
  retry_schedule: [60, 300, 900, 3600, 21600] # 1m, 5m, 15m, 1h, 6h
```

- **Safety**: Outbox allocation cannot exceed 64 MiB. If full, new auto-export attempts are safely dropped or queued with warning without affecting local assessment storage.
- **Deletion**: Bundle deleted from outbox only after receiving verified receipt from Companion.

---

## 18. Companion Storage Architecture

```text
/var/lib/pineai-companion/
├── companion.db           # SQLite metadata DB (WAL mode enabled)
├── objects/
│   ├── bundles/           # Validated raw bundle archives
│   ├── pcap/              # Optional associated PCAP captures
│   ├── reports/           # Generated HTML/PDF reports
│   └── evidence/          # Extracted evidence attachments
├── staging/               # Temporary chunked upload assembly
├── quarantine/            # Failed / malformed bundles for analysis
└── keys/                  # Companion identity and report signing keys
```

---

## 19. Internal Job Execution Architecture

Companion Core manages jobs via an internal SQLite-backed table (`jobs`), eliminating external queue dependencies:

```sql
CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL, -- 'bundle_import', 'pcap_parse', 'report_generate', 'ai_analyze'
    status TEXT NOT NULL,   -- 'pending', 'processing', 'completed', 'failed'
    payload_json TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 20. PCAP Subprocess Worker Isolation

Binary parsing tasks (such as PCAP inspection via `tshark` or `tcpdump` parser wrappers) are executed in isolated worker subprocesses:

```text
Companion Main API Process
        │
        ├── Spawn worker subprocess (Restricted UID/GID, read-only filesystem)
        │     └── Process PCAP file in /tmp/isolated_pcap_xyz
        │     └── Return JSON results via standard output pipe
        │
        └── Validate JSON output against parser JSON Schema
```

- **Limits**: Subprocess restricted to 15-second CPU limit, 128 MiB RAM limit, no network access.

---

## 21. AI Authority Boundary on Companion

When Companion is connected to a local LLM or hosted AI provider:
- AI results are stored strictly as non-authoritative annotations (`annotations/ai_<digest>.json`).
- AI MAY explain historical drift, suggest policy adjustments, or draft debrief prose.
- AI MUST NOT create findings, alter severity/confidence, change comparability ratings, or auto-activate baselines/policies.

---

## 22. Digital Report Signing Direction

Companion Core supports Ed25519 cryptographic signatures for exported compliance reports:

```text
Fact Model Digest + Artifact Digests + Signer Key ID ────► Ed25519 Signature Header
```

Verification can be performed independently using public keys without requiring an active Companion instance.

---

## 23. Privacy Profiles

1. **Local Full-Fidelity Profile**: Retains normalized SSIDs and location notes for internal trusted deployment.
2. **Share-Safe Profile**: Automatically redacts SSIDs, operator notes, and customer identifiers, replacing them with stable HMAC-SHA256 pseudonyms.

---

## 24. Store-and-Forward Relay (Future Optional v1.x)

For scenarios where Companion is frequently offline, an optional zero-knowledge relay architecture can accept encrypted bundles from Mark VII and hold them until Companion connects and retrieves them. (Deferred past v0.9.0 MVP).

---

## 25. Comprehensive Failure Modes & Operator Guidance

| Failure Mode | Root Cause | System Behavior | Operator-Visible Status |
| --- | --- | --- | --- |
| **1. Companion Offline** | Companion host down or network severed | Mark VII stores bundle in outbox; retries per backoff schedule | `Outbox: 1 bundle pending (Companion unreachable)` |
| **2. Ingress Tunnel Down** | Cloudflare / ngrok tunnel interrupted | Ingress adapter retries connection; Mark VII outbox holds bundle | `Ingress status: Reconnecting` |
| **3. Mark VII Offline** | No Wi-Fi / cellular internet on Mark VII | Outbox retains bundle locally; non-blocking | `Upload paused: Device offline` |
| **4. DNS Failure** | Endpoint hostname resolution fails | Retry backoff initiated | `Upload error: DNS lookup failed` |
| **5. TLS Validation Fail** | Certificate mismatch or MITM attempt | Upload aborted immediately; fail closed | `SECURITY ALERT: Invalid TLS certificate` |
| **6. Token Expired** | Enrollment token used after expiration window | Pairing rejected | `Pairing failed: Token expired` |
| **7. Device Revoked** | Device ID revoked by Companion admin | Requests return `401 Unauthorized`; outbox pauses | `Upload rejected: Device credential revoked` |
| **8. Duplicate Upload** | Same `bundle_id` uploaded twice | Idempotent receipt returned; duplicate skipped | `Upload skipped: Bundle already ingested` |
| **9. Partial Upload** | Connection dropped mid-stream | Staging chunk retained for resume or cleaned after 1h | `Upload incomplete: Retrying chunk` |
| **10. Digest Mismatch** | Upload corrupted during transport | Upload rejected; staging file deleted | `Upload failed: SHA-256 checksum mismatch` |
| **11. Companion Storage Full**| Companion disk space exhausted | Ingest API returns `507 Insufficient Storage` | `Companion error: Storage full` |
| **12. Mark VII Outbox Full** | 5 bundles / 64 MiB ceiling reached | Newest export skipped with warning; local storage safe | `WARNING: Outbox full. Oldest bundle retained.` |
| **13. DB Lock Contention** | SQLite concurrent write lock | SQLite WAL mode handles retry; job queue retries | `Internal notice: Retrying DB transaction` |
| **14. Import Process Crash** | Unexpected exception during bundle import | Job status set to `failed`; moved to quarantine | `Import failed: Quarantine bundle #102` |
| **15. Parser Process Crash** | PCAP parser subprocess OOM or panic | Parser terminated safely; main API unaffected | `Warning: PCAP enrichment failed` |
| **16. Path Traversal Archive**| Malicious `.tar.gz` contains `../../` paths | Archive extractor rejects import; fail closed | `SECURITY ALERT: Invalid path in bundle archive` |
| **17. Unsupported Schema** | Bundle version newer than Companion Core | Import rejected with version error | `Import failed: Unsupported schema version` |
| **18. Unexpected Raw Recon**| Bundle contains raw Recon scan payloads | Import rejected unless explicit flag set | `Import rejected: Raw Recon payloads prohibited` |
| **19. Endpoint URL Changed** | Ingress provider reassigned public URL | Device notified via dynamic re-enrollment | `Endpoint changed: Update companion configuration` |
| **20. Provider Token Expire**| Cloudflare / ngrok authentication expired | Ingress adapter logs warning; admin UI alerts | `Ingress alert: Provider token expired` |
| **21. Companion Restart** | Companion container restarted mid-upload | Upload session resumed via chunk offset check | `Upload resumed after service restart` |
| **22. Receipt Lost** | Mark VII connection dropped before receipt rx | Mark VII re-queries `GET /uploads/{id}/receipt` | `Receipt recovered: Outbox cleared` |

---

## 26. Threat Model & Mitigations

| Threat | Risk Level | Mitigation Strategy |
| --- | --- | --- |
| **Public Endpoint Scanning** | High | Public listener exposes strictly 5 ingest endpoints; all require device HMAC/Bearer auth. |
| **Stolen Device Credential** | Medium | Revocation list in Companion DB; device credential rotation via Admin UI. |
| **Request Replay Attacks** | Medium | Nonces stored with 5-minute timestamp window check. |
| **Decompression Bomb (Zip Bomb)**| High | Strict decompressed size cap (max 256 MiB uncompressed limit enforced during stream extraction). |
| **Parser Subprocess Exploitation**| High | PCAP parser runs in unprivileged subprocess with no network access and strict CPU/RAM limits. |
| **Path Traversal Attacks** | High | Archive extractor validates target canonical paths before writing any member file. |
| **Admin UI Exposure** | High | Admin UI and Admin API bind strictly to `127.0.0.1:8741` by default. |
| **AI Data Leakage** | Medium | Bounded bundles redact MACs/BSSIDs; SSID sharing requires explicit operator opt-in. |

---

## 27. Delivery Phases & Roadmap Integration

```text
v0.7.x (Current) ──────► v0.8.x ──────────────────► v0.9.0 (Companion MVP) ──────► v0.9.1 / v0.9.2+
Repeatable Field         Operational Assurance     - Single Docker container      - Upload Receipts
Audits & Resource        & AI Analyst              - Shared Companion Core        - Desktop Packaging
Safety Core              (On-device AST)           - Bundled Ingress Adapter      - Ed25519 Signatures
                                                   - Direct HTTPS Push
```

---

## 28. Companion MVP Acceptance Criteria

- [ ] Mark VII operates 100% independently when no Companion is configured.
- [ ] Companion MVP deploys as a single Docker container with 1 volume mount.
- [ ] Companion Core uses SQLite for metadata storage (no external DB required).
- [ ] No public IP or router port forwarding required when ingress adapter is enabled.
- [ ] Admin UI binds to `127.0.0.1:8741` by default.
- [ ] Public ingest endpoint exposes strictly the allowlisted API routes.
- [ ] One-time enrollment token exchange establishes per-device credentials.
- [ ] Mark VII streams bundle uploads in fixed chunks without loading full archive into RAM.
- [ ] Mark VII outbox is strictly bounded (max 5 bundles, max 64 MiB).
- [ ] Bundles exclude raw Hak5 Recon JSON payloads by default.
- [ ] PCAP parser executes inside an isolated subprocess worker.
- [ ] AI results are stored strictly as non-authoritative annotations.
- [ ] Windows and Linux desktop builds wrap the exact same `pineai_companion_core` codebase.

---

## 29. Deferred Decisions & Unresolved Questions

1. **Deferred**: Multi-tenant cloud relay architecture (deferred to `v1.x`).
2. **Deferred**: Hardware-backed TPM / Secure Enclave key storage for report signing (deferred to `v0.9.2`).
3. **Unresolved Question**: Should `cloudflared` binary download be automated inside Dockerfile or fetched dynamically during container initialization? *(Decision: Recommend Dockerfile multi-stage build lock for release stability).*
