# Changelog

All notable changes to this project will be documented in this
file. Format follows the spirit of [Keep a Changelog]; this
project does not follow [Semantic Versioning] yet — V1 is still
under development and the tag scheme will land with the V1 cut.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [0.1.0] - 2026-09-22

First tagged release.

### Build & release

- **CI enabled.** The GitHub Actions workflows parked in
  `dist/github-workflows/` since SEZ-28 now live in
  `.github/workflows/`: rust (stable + MSRV), web, paper and a
  Docker image build run on every PR and push to `main`.
- **Reproducible builds.** `Cargo.lock` is committed; CI, release
  and the Dockerfile build with `--locked`.
- **MSRV raised to 1.88** to match what the dependency tree
  actually requires (the declared 1.78 no longer compiled).
- **Container image on GHCR.** Tagged releases push
  `ghcr.io/<owner>/ree0xq-server:<version>` (plus `:X.Y` and
  `:latest` for non-pre-releases).
- **Release guard.** A tag that does not match the workspace
  version or any crate's RPM package version stops the release.
- Code is `cargo fmt`-clean and `clippy -D warnings`-clean; lint
  fixes are behaviour-preserving (CLI subcommand names unchanged).

### Changed

- **Project renamed: Sezar → ree0xQ.** Repository, crate names
  (`ree0xq-core`, `ree0xq-server`, ...), binaries, env vars
  (`REE0XQ_HOST_PORT`, `REE0XQ_ADMIN_TOKEN`, `REE0XQ_DATABASE_URL`),
  systemd units, packaging, docs, web UI branding and the paper all
  carry the new name. GitHub redirects the old repository URL. The
  archived studies keep the former identifiers for reproducibility.


Pre-alpha. V1 (Network module) + V2 (cert inventory) + V3
(chain monitor) + V4 (HSM/KMS) + V5 (recommendations) all
complete per [`ROADMAP.md`](ROADMAP.md); 22/22 SEZ-N issues
closed.

### Added

- **Paper submission package.** `scripts/paper-submission-
  package.sh [magazine|extended|both]` and
  `make paper-submission` rebuild the PDFs, gather every
  artefact a venue submission portal asks for, and zip
  the bundle:
  - Main PDF (rebuilt fresh).
  - Source Markdown (the canonical authoring format).
  - LaTeX source (pandoc-rendered against `ieee.csl`)
    for IEEE-template venues.
  - `references.bib` + `ieee.csl`.
  - Every figure (7 of them) in both PDF and PNG.
  - A venue-customised cover letter with the corresponding
    author's ORCID + co-author's ORCID already filled in.
  - A submission checklist for the operator to tick off
    before upload.
  - `MANIFEST.txt` with SHA-256 of every file in the
    bundle.
  Magazine bundle: 2.0 MB / 24 files. Extended: 1.3 MB /
  24 files. The bundles live under `dist/paper/` (now
  git-ignored — they're regenerable from tracked
  sources).
- **Operator polish — systemd units + multi-host deploy
  runbook** (SEZ-24). `dist/systemd/` ships
  production-default unit files for the four
  always-on or timer-driven daemons:
  - `ree0xq-server.service` (collector + REST + V5
    recommendations endpoint)
  - `ree0xq-net-live.service` (Phase 2.2 libpcap live
    observer; only unit that needs `CAP_NET_RAW`)
  - `ree0xq-cert-host-scan.{service,timer}` (daily
    03:17 ± 30 m)
  - `ree0xq-id-inventory.{service,timer}` (every 6 h)
  Each unit runs as a dedicated `ree0xq` system user, drops
  every capability except the one it actually needs, and
  applies the standard hardening battery
  (`ProtectSystem=strict`, `PrivateTmp`,
  `ProtectKernel*`, `MemoryDenyWriteExecute`,
  `SystemCallFilter=@system-service` minus
  `@privileged @resources`, no writable filesystem outside
  `/var/lib/ree0xq*`).
  `docs/operator-deploy.md` is the multi-host runbook
  covering collector setup, per-agent bootstrap-token mint,
  agent enrolment over the mTLS bootstrap listener,
  systemd drop-in templates, and Day-2 cert rotation.
  Top-level `Makefile` adds `make systemd-install`,
  `systemd-uninstall`, `check-systemd`, `acceptance`,
  `loadtest`, `test`, `release` targets — typed once,
  the install path is idempotent.
- **Dashboard integration of V5 recommendations** (SEZ-23).
  New `GET /v1/recommendations` endpoint on ree0xq-server
  walks the latest-per-asset map and runs the V5
  recommendation engine on each event's primitive list;
  returns `[{identity, kind, host, current_primitives,
  recommendations[]}]`. React UI gets a `/recommendations`
  page polled on the 30 s Inventory cadence, with a
  kind-filter, a max-cost-filter (Trivial / Low / Medium /
  High), and a per-asset card that surfaces every
  recommendation with its cost badge, rationale, and
  caveats. Bundle stays at 59.95 KB gzipped (300 KB
  budget). Closes SEZ-23.
- **`ree0xq-agility` V5 — PQ migration recommendations
  engine** (SEZ-19, SEZ-20, SEZ-21, SEZ-22). Four new
  modules on top of the V1 agility scanner:
  - `recommend` — `recommend_for(&[Primitive]) ->
    Vec<Recommendation>` produces ranked replacement
    options with rationale, `Cost` markers (Trivial → Low
    → Medium → High), and per-replacement caveats. CLI:
    `ree0xq-agility recommend --inventory <url>` walks
    `/v1/inventory` and prints one JSON line per asset
    that has any classical primitive worth replacing.
  - `roadmap` — `project_roadmap(inventory, plan)`
    simulates org_q at each milestone of an operator-
    supplied migration plan. CLI: `ree0xq-agility roadmap
    --inventory <url> --plan <file>`. Milestones sort
    chronologically regardless of input order;
    unknown asset_ids silently skip; migrated assets
    land at the PQ-clean baseline q = 0.10.
  - `compat` — embedded TLS-stack ↔ PQ-algo support
    matrix across 6 stacks (OpenSSL 3.x, BoringSSL,
    rustls-post-quantum, BouncyCastle, NSS, Go crypto/
    tls). CLI: `ree0xq-agility compat --stack <s>
    [--algo <a>]`. Every entry carries `min_version` +
    public source URL. Unknown pairs report
    `SupportStatus::Unknown` rather than misclaim
    support.
  - `deadlines` — embedded per-jurisdiction PQ-mandate
    table; 11 dates across US-NSA CNSA 2.0 / US-NIST IR
    8547 / EU-ANSSI / DE-BSI TR-02102-1 / UK-NCSC. Every
    entry includes the source-URL audit trail. CLI:
    `ree0xq-agility deadlines [--jurisdiction US]
    [--horizon-days 365]`.
  Twenty-three library tests + one in-process integration
  test cover the surface; the smoke test exercises the
  recommend pipeline against a live ree0xq-server with a
  4-asset mixed inventory and asserts the canonical
  replacements (RSA-2048 → ML-DSA-44, ECDSA-P256 →
  ML-DSA-65, the ML-DSA-65 hsm_slot already PQ-safe → no
  recommendation). Closes SEZ-19/20/21/22.
- **`ree0xq-id` V4 — HSM / KMS / smart-card inventory**
  (SEZ-15, SEZ-16, SEZ-17, SEZ-18). Four backends behind
  one shared `algos::primitives_for` table that maps
  `(key_type, key_size_bits?)` onto the
  `Vec<Primitive>` the rollup consumes:
  - `inventory-scan` (default) — operator-exported JSON
    of (vendor, slot, keys[]) → one event per key.
  - `pkcs11-scan` (feature `pkcs11`) — opens a vendor
    `.so` via `cryptoki`, walks every slot's public +
    secret-key objects; classification re-uses the same
    algos table.
  - `aws-kms-scan` (feature `aws-kms`) — `aws-sdk-kms`
    `ListKeys` + `DescribeKey`, every `KeySpec` mapped
    to the shared table. `KmsBackend` trait keeps the
    surface pluggable so GCP KMS / Azure Key Vault drop
    in later.
  - YubiHSM 2 + PIV / OpenPGP smart cards close as
    runbook + reproducer-script (SEZ-3 / SEZ-16 pattern)
    since both are hardware-bound and CI doesn't host
    either. Three operator runbooks
    (`docs/ree0xq-id-pkcs11.md`,
    `docs/ree0xq-id-aws-kms.md`,
    `docs/ree0xq-id-yubihsm.md`) plus the host-side
    `scripts/ree0xq-id-bringup.sh` pre-flight.
  Eleven workspace tests cover the algos table, the
  inventory classifier, the AWS KMS fake-backend
  scanner-loop, the KeySpec mapping, and the
  in-process collector round-trip. Closes SEZ-15,
  SEZ-16, SEZ-17, SEZ-18.

- **`ree0xq-chain` V3 — three offline chain backends** (SEZ-12,
  SEZ-13, SEZ-14). New `ree0xq-chain` binary with three
  subcommands; every backend takes `--addresses <file>` and
  emits one `crypto_inventory_event` per recognised address
  (`asset.kind = blockchain_key`, `asset.identity =
  <chain>:<addr>`, `asset.host = <chain>`).
  - `bitcoin-scan` classifies each address as P2PKH / P2SH /
    P2WPKH / P2WSH / P2TR by prefix + length; emits
    ECDSA-secp256k1 + SHA-256 primitives for the legacy /
    SegWit-v0 forms, Schnorr-secp256k1 + SHA-256 for
    Taproot.
  - `ethereum-scan` validates the `0x` + 40-hex shape and
    emits ECDSA-secp256k1 + Keccak-256. Contract-vs-EOA
    disambiguation needs a live RPC and is deferred.
  - `qrl-scan` validates the `Q` + 78-hex shape and emits
    XMSS + SHA-256, marked `pq_resistant: true` — proves
    the existing `crypto_inventory_event` schema handles
    hash-based stateful PQ signatures without modification.
  Thirteen unit tests cover canonical address shapes for
  each chain, malformed-address rejection, and the
  primitive contracts; one integration test
  (`tests/chain_smoke.rs`) round-trips all three backends
  through a live in-process collector and asserts the
  per-chain shape on `/v1/inventory`. Closes SEZ-12, SEZ-13,
  SEZ-14 — every V3 SEZ-N is now closed.
- **`ree0xq-cert` Vault PKI scanner** (V2.2, SEZ-11). New
  `ree0xq-cert vault-scan --addr <url> --mount <name>
  [--token-env VAULT_TOKEN] [--collector <url>]` subcommand
  lists every active cert under a HashiCorp Vault PKI mount,
  fetches each PEM via `GET /v1/<mount>/cert/<serial>`, and
  emits one event per cert. Reuses the same parser as the
  host-scan and CT-scan paths so the per-cert event shape
  (primitive split, SHA-256 identity, host SAN) is
  identical. The Vault token is read from an env var
  (configurable via `--token-env`) and never written to a
  log line; the `VaultBackend` trait wraps the two-call
  shape so AD CS, ACME, and PKCS#11 backends can drop in
  for V2.3+ without touching the scanner loop. Five
  in-memory unit tests cover the JSON deserialisers, the
  scanner loop, the empty-mount noop, and the URL
  sanitiser. Five-minute reproducer against `vault server
  -dev` lives in [`docs/ree0xq-cert-vault.md`](docs/ree0xq-cert-vault.md).
  Closes SEZ-11 — every V2 SEZ-N is now closed.
- **`ree0xq-cert` CT-log scanner** (V2.1, SEZ-10). New
  `ree0xq-cert ct-scan --domain <fqdn> [--cursor <path>]
  [--collector <url>]` subcommand pulls a domain's full cert
  history from a public Certificate Transparency log
  (crt.sh in V2.1) and emits one event per discovered cert,
  going through the same `event_from_cert` parser as the
  host-scan path. Stateful: a JSON cursor file remembers the
  highest CT entry id seen per domain so re-runs only fetch
  certs newer than the cursor. The `CtBackend` trait wraps
  the two-call list-then-fetch loop so future Google Argon
  or Let's Encrypt Oak backends drop in without touching the
  scanner. Polite poll cap of 1 req / second between PEM
  fetches by default, configurable via
  `--rate-delay-ms`. Four unit tests cover the JSON
  deserialiser, fresh-run + cursor advance, cursor-aware
  delta runs, and empty-domain noop using an in-memory
  fake backend. Closes SEZ-10.
- **`ree0xq-cert` host-filesystem scanner** (V2.0, SEZ-9). New
  crate binary `ree0xq-cert host-scan --root <path>` walks the
  filesystem for PEM-encoded X.509 certs, parses each with
  `x509-parser`, and emits one `crypto_inventory_event` per
  cert. Signature algorithm is decomposed into its `Sig` +
  `Hash` primitives so the posture rollup sees both surfaces;
  asset identity is the cert's SHA-256 fingerprint (stable
  across re-scans, unique per chain). Default roots are the
  common Linux cert paths (`/etc/ssl`, `/etc/pki`,
  `/usr/local/share/ca-certificates`,
  `/etc/letsencrypt/live`); operators add more with repeated
  `--root` flags. `--collector` POSTs each event to a
  ree0xq-server, otherwise NDJSON streams to stdout. Verified
  end-to-end against the docker-compose Postgres-backed
  stack: 3 RSA fixture certs → scan → `/v1/inventory`
  filtered to `x509_cert` shows the three rows with their
  primitives intact. Closes SEZ-9; opens the V2 path toward
  CT-log (SEZ-10) and Vault-PKI (SEZ-11) backends behind the
  same parser.

### V1 (previously listed)

- **`ree0xq-net live-ebpf` CLI + bring-up runbook** (SEZ-3).
  Phase 2.1's kernel-side TC classifier + userspace loader had
  been wired up behind the `live-interface` feature for a
  while; this change puts the entry point on the binary
  (`ree0xq-net live-ebpf --iface <name> --ebpf-object <path>
  [--collector …] [--spool-dir …]`, gated by the feature; the
  no-feature build returns an actionable rebuild-with-feature
  error). A new operator runbook,
  `docs/ree0xq-net-ebpf.md`, covers host requirements,
  one-time toolchain install, build sequence, attach, the
  exact procedure to validate each of SEZ-3's acceptance
  criteria, and a troubleshooting section. The companion
  `scripts/ree0xq-net-ebpf-bringup.sh` is the one-command
  reproducer — pre-flight checks → BPF object build → loader
  build → attach + tail — and the closure path for SEZ-3.
- **Postgres event store** (SEZ-2). `--database-url` /
  `REE0XQ_DATABASE_URL` switches `ree0xq-server` from the
  in-memory DashMap store to a sqlx-backed `PgEventStore`.
  Two-table schema (`events` history + `assets` per-asset
  latest snapshot) bundled as
  `crates/ree0xq-server/migrations/0001_init.sql`, run
  automatically on first boot. The `EventStore` trait
  abstracts both backends so every handler stays unchanged.
  `docker compose up -d` now brings up `postgres:16-alpine`
  alongside `ree0xq-server` and wires them together via the
  internal network; the host binds Postgres to
  `127.0.0.1:5433` (env-overridable via `REE0XQ_PG_HOST_PORT`)
  for `psql` access. Three integration tests
  (`tests/pg_smoke.rs`) exercise the full HTTP loop,
  post-restart durability, and the out-of-order-ingest
  invariant against a disposable `postgres:16-alpine`
  testcontainer. Live-stack ingest at concurrency 16:
  1316 req/s, p50 11 ms, p99 65 ms (SEZ-2 acceptance budget
  was 200 ms p99). Closes SEZ-2.
- **ree0xQ dashboard — V1 ship cut** (SEZ-5). The Vite + React
  + TypeScript + Tailwind scaffolding lights up against the
  live `ree0xq-server` REST surface:
  - Posture page polls `/v1/posture` every 10 s,
    renders `org_q` + asset count + BLOCKED count + deadline
    countdown, and (paired with a 10 s `/v1/inventory` poll)
    shows a breakdown of mean / max q per asset kind with a
    small horizontal bar chart.
  - Inventory page polls `/v1/inventory` every 30 s with a
    manual refresh button; row click opens a modal detail
    panel showing primitives, source module, q, observed-at
    timestamp, and a pointer to `/v1/events?limit=N` for the
    full event JSON.
  - Empty-state CTA — when `/v1/posture` reports zero assets
    the Posture page swaps to a "no agents reporting yet"
    panel with copy-to-clipboard install + bootstrap commands.
  - `lib/usePolling.ts` — a small hook that polls on a fixed
    interval, suspends when the tab goes hidden, and exposes
    a `refresh` thunk so a page can force an out-of-band
    fetch (e.g. after a user action).
  Build artifact stays well under the SEZ-5 budget: 186 KB
  raw / 59.22 KB gzipped (budget: 300 KB).
- **Agent-side spool** (SEZ-6, fourth acceptance criterion).
  `ree0xq-net` now ships an on-disk NDJSON spool
  (`crates/ree0xq-net/src/spool.rs`). When `live` /
  `from-zgrab` are invoked with `--collector <url>
  --spool-dir <path>`, every POST failure appends the event
  to the spool; the spool is drained at the start of every
  subsequent run. Survives mid-process crashes (each append
  fsyncs), tolerant of corrupt lines (logged + dropped from
  the spool), at-least-once delivery (server side
  deduplicates by event identity). Closes SEZ-6.
- **TLS termination + mTLS enforcement** (SEZ-6, third
  acceptance criterion).
  `ree0xq-server --tls` mints a CA-signed server cert at boot
  (additional SANs via `--tls-san`) and runs two listeners:
  - `--tls-bootstrap-listen` (default `0.0.0.0:8443`) — TLS
    with server cert only, no client-cert verifier. Hosts
    `/healthz`, `/v1/enrol`, `/v1/admin/bootstrap-tokens` so
    an un-enrolled agent can still reach enrolment over an
    encrypted channel.
  - `--listen` (default `0.0.0.0:8090`) — mTLS. TLS handshake
    requires a client cert chained to the internal CA. Hosts
    `/v1/events`, `/v1/inventory`, `/v1/posture`, `/v1/blocked`,
    `/v1/qkd/links`. Rejection without a valid client cert
    happens at the TLS layer; handlers never see the request.
  The legacy plain-HTTP single-listener mode (default when
  `--tls` is off) is unchanged, keeping the dev smoke,
  acceptance script, and integration tests friction-free.
- **mTLS bootstrap foundation** (SEZ-6, first half).
  `ree0xq-server` now boots an internal ECDSA-P256 root CA on
  first run (persisted to `--ca-dir`, default
  `/var/lib/ree0xq/ca`, key at mode 0600), reloaded on every
  subsequent start. New endpoints:
  - `POST /v1/admin/bootstrap-tokens` — admin-gated by
    `X-Admin-Token` (configured via `--admin-token` or
    `REE0XQ_ADMIN_TOKEN`), issues a single-use UUID token bound
    to a specific `agent_id` with a 1–720 hour TTL.
  - `POST /v1/enrol` — agent redeems its token, server returns
    a freshly-signed client cert plus its private key and the
    CA cert.
  Still pending under SEZ-6: agent-side cert rotation and
  agent-side buffering during a server outage.
- **Throughput probe** (`scripts/loadtest.py`). Stdlib-only Python
  load generator: fans out N concurrent POSTs to `/v1/events`,
  reports request rate, latency p50/p90/p99/max, and a failure
  mix. First baseline against the in-memory store on a single
  Linux host: ~812 req/s at concurrency 16, p50 18 ms, p99 51 ms.
- **Single-host Docker install.** Multi-stage `Dockerfile` and
  `compose.yaml` bring `ree0xq-server` up under a non-root user
  with `tini` as PID 1 and a `curl /healthz` HEALTHCHECK. Port is
  env-overridable (`REE0XQ_HOST_PORT`); `docker compose up -d` is
  the documented quickstart.
- **Release-binary acceptance smoke.** `scripts/acceptance.sh`
  drives the release CLIs end-to-end against a local TCP socket,
  seeds five deterministic events through `ree0xq-net from-zgrab`
  + `ree0xq-net live --pcap` + a hand-crafted `agility: locked`
  curl POST, and asserts `assets == 5`, `blocked_count == 1`,
  `org_q > 0`, and that the BLOCKED row points at the synthetic
  appliance.
- **`ree0xq-net` Phase 2.2 — libpcap live-interface capture.**
  Behind the `live-pcap` Cargo feature: `ree0xq-net live --iface
  <name>` opens a network interface via libpcap and feeds the
  same frame-handling code as the pcap-file replay. Ctrl-C
  drains in-flight packets cleanly. Build needs
  `libpcap-devel` / `libpcap-dev`; runtime needs `CAP_NET_RAW`.
- **`ree0xq-net` end-to-end smoke** (`crates/ree0xq-net/tests/
  end_to_end_smoke.rs`). Spins `ree0xq-server`'s router in-process
  on an ephemeral port, drives `observe_pcap` against the
  synthetic ClientHello fixture, POSTs each emitted event to
  `/v1/events`, and asserts the primitives (`X25519+ML-KEM-768`,
  `X25519`, `ML-DSA-65`, `AES-256-GCM`) survive the round trip.
- **Study 1 — Tranco-top-1k scan artefacts.** Captures
  (`scan-tranco-1k.json`, `pq-scan-tranco-1k.ndjson`), the pinned
  Tranco list (`tranco-6G8PX-1k.{csv,txt}`), the regenerable
  plots, and the analyser script `studies/study1/analyse_tranco.py`.
  Reproducibility-friendly: re-running the analyser regenerates
  the figures the paper cites without a fresh scan.
- **Paper drafts** under `docs/paper/`: magazine v0.4 and
  extended v0.3 (2026-05-18). Magazine §5.1 + extended §8.1
  carry the Tranco-1k headline (n = 1,000, 724 responsive, 317
  PQ = 43.8%); the 30-host curated pilot survives as a
  sample-selection-bias contrast.
- **TODO.md** punch list for the V1 critical path.
- **CONTRIBUTING.md** — contribution conventions including the
  no-AI-attribution rule and the citation-verification
  requirement.

### Changed

- **Paper tone.** Stripped style-tell phrasings (`We argue` openers,
  `Crucially,`, `Side-by-side,` framing, adjective-stacked
  self-description) across both magazine and extended drafts
  without changing technical claims, numbers, or citations.
- **`idq-deployments` citation.** Upgraded from the IACR ePrint
  preprint to the peer-reviewed EPJ Quantum Technology version
  (DOI `10.1140/epjqt/s40507-025-00350-5`); metadata
  cross-checked via the PMC open-access mirror.

### Existing surface (V1 scaffolding inherited from earlier work)

- **`ree0xq-core`** — `crypto_inventory_event` schema v1.1 with
  `channel_protection` and `agility` blocks plus the
  `QkdLink` / `QkdKme` asset kinds; ts-rs + JsonSchema codegen.
- **`ree0xq-server`** — `axum` collector backed by an in-memory
  `DashMap` store, the V1 REST surface
  (`/healthz`, `POST /v1/events`, `/v1/events/batch`,
  `GET /v1/events`, `/v1/inventory`, `/v1/posture`,
  `/v1/blocked`, `/v1/qkd/links`), the deadline-adjusted rollup
  library (`q_for_event`, `is_blocked`, `org_score`), and unit
  tests `worked_example_alpha/delta_q_matches_paper` that anchor
  the paper §3.1 numerics.
- **`ree0xq-net`** — TLS handshake byte parser, IANA-codepoint
  primitive mapping, zgrab2 JSON ingest adapter, Phase 2.0
  pcap-file replay, Phase 2.1 eBPF TC classifier skeleton
  (`live-interface` feature), and the PQ-capable probe used in
  Study 1.
