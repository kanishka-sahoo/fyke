# Fyke

Fyke is a single-host, non-executing SSH, Telnet, HTTP, and HTTPS honeypot for a dedicated Debian or Ubuntu VPS. Sensors accept hostile traffic, emulate a coherent fictional machine, and stream normalized evidence to a private controller. Attacker input is never passed to a host or container shell.

The project is licensed under Apache-2.0.

## Security model

- Sensors expose one protocol each and cannot write SQLite.
- Sensor events cross a versioned bidirectional gRPC stream authenticated by TLS certificates whose DNS SAN is `sensor.<id>`.
- Every event has a UUIDv7 ID plus a unique sensor, session, and sequence tuple. Replay is idempotent.
- Disconnected sensors spool encrypted records up to 512 MiB. A full spool backpressures the protocol path instead of silently deleting unacknowledged evidence.
- The controller leaves routing and investigation metadata searchable, while sealing credentials, command arguments, bodies, transcripts, and uploads to its generated X25519 age identity.
- The shell module interprets a fixed command vocabulary against a read-only persona and per-session memory overlay. There is no command-execution adapter.
- SFTP writes go to bounded encrypted quarantine. SCP execution is recorded and rejected. URLs are recorded and never fetched.
- Artifact previews are escaped text or hex. Downloads always use `application/octet-stream` and `Content-Disposition: attachment`.
- The dashboard is host-loopback only. Proxy identity headers are rejected unless the peer is configured as trusted.

Fyke is evidence collection software, not a security boundary by itself. Apply the generated host firewall after verifying a private administration path.

## Build

Prerequisites are Go 1.24+, Node 24+, and Docker Compose v2.

```sh
make ui
make test
make build
```

The Docker build compiles the React/Tailwind dashboard and then produces a CGO-free distroless image.

## Initialize and run

Never claim public port 22 until you have verified Tailscale or alternate-port SSH administration. Fyke does not modify `sshd`.

```sh
./fyke init --dir ./deployment
./fyke doctor --config ./deployment/config.yaml
export FYKE_ROOT=./deployment
export FYKE_UID=$(id -u)
export FYKE_GID=$(id -g)
docker compose build
docker compose up -d
```

The default public mappings are 22, 23, 80, and 443. Override them while validating a deployment:

```sh
FYKE_ROOT=./deployment FYKE_SSH_PORT=2222 FYKE_TELNET_PORT=2323 \
  FYKE_HTTP_PORT=8080 FYKE_HTTPS_PORT=8443 docker compose up -d
```

Verify the dashboard locally at `http://127.0.0.1:9080`. For remote access, use an SSH tunnel or host-managed Tailscale Serve. Do not enable Funnel.

```sh
ssh -N -L 9080:127.0.0.1:9080 admin@your-vps
```

After confirming private administration and normal controller ingestion, explicitly install the IPv4/IPv6 sensor egress policy:

```sh
sudo ./fyke firewall apply --config ./deployment/config.yaml
```

The rule set permits established traffic, leaves the internal controller bridge alone, and drops forwarded traffic originating on the public sensor bridge. Review `fyke firewall` output before applying it.

## Commands

| Command | Purpose |
| --- | --- |
| `fyke init` | Generate the fictional persona, local CA, mTLS identities, SSH host identity, age identity, and validated configuration. |
| `fyke controller` | Run the single SQLite writer, gRPC ingestion, API, dashboard, alerts, retention, metrics, liveness, and readiness. |
| `fyke sensor --id ID` | Run one configured protocol sensor with its encrypted spool. |
| `fyke doctor` | Validate configuration, persona, identities, and deployment warnings. |
| `fyke firewall apply` | Explicitly install the nftables sensor egress policy. |
| `fyke export` | Export normalized JSONL or CSV. `--include-sensitive` is explicit and audit logged. |
| `fyke backup` | Create a consistent database and artifact tar stream encrypted to an operator recovery recipient. |
| `fyke restore` | Decrypt, reject unsafe archive paths, verify every manifest hash, and restore into an empty directory. |

For a backup, first stop the controller so the database and artifact set cannot change between the SQLite snapshot and manifest walk:

```sh
FYKE_ROOT=./deployment docker compose stop controller
./fyke backup --config ./deployment/config.yaml \
  --recipient age1... --out fyke-$(date +%F).tar.age
FYKE_ROOT=./deployment docker compose start controller
```

Restore stays offline and refuses a non-empty target:

```sh
./fyke restore --backup fyke-2026-08-28.tar.age \
  --identity recovery.agekey --target ./restored-data
```

## API and operations

The controller serves `/api/v1` on loopback. Main resources are:

- `GET /overview`, `/events`, `/sessions`, `/sources`, `/artifacts`, and `/alerts`
- `GET /stream` for server-sent live events
- `GET /artifacts/{id}/preview` and `/download`
- `GET /exports?format=jsonl|csv&sensitive=false`
- `GET /health`, `/retention`, and `/preferences/alerts`
- `POST /retention/run` and `PUT /preferences/alerts`

The private metrics listener exposes `/metrics`, `/livez`, and `/readyz` at the configured loopback address. Alert templates cover successful emulated login, artifact upload, novel public-key fingerprint, source spikes, and unhealthy sensors. HTTPS webhook delivery has a bounded queue, bounded exponential retries, and a stable event ID idempotency key.

SQLite uses WAL, full synchronous durability, transactional migrations, normalized indexes, FTS5 metadata search, one serialized writer path, and integrity checks. Defaults retain metadata for 180 days, transcripts for 90 days, payloads for 30 days, and PCAP metadata for 14 days, with evidence eviction ordered before event metadata under the 20 GiB cap.

## Personas

Persona packs are versioned YAML, not executable plugins. A pack defines the fictional host, users, read-only filesystem, honey credentials, HTTP routes, and protocol banners. Validation rejects path traversal, executable filesystem entries, unknown HTTP methods, and unsupported pack versions.

Honey credentials authenticate immediately. Otherwise, the third failed attempt from one source and protocol inside ten minutes opens an emulated session.

## Current acceptance coverage

Automated tests cover UUIDv7 ordering, persona path safety, shell syntax rejection, URL non-fetch behavior, authentication windows, session limits, encrypted spooling and replay, age sealing, SQLite deduplication, evidence-at-rest encryption, retention ordering, Telnet negotiation, and bounded HTTP raw capture. Run all seed corpora and tests with `go test ./...`; run sustained fuzzing with standard Go fuzz flags.

The optional `NET_RAW` PCAP profile and full 500-session/100-event-per-second target-VPS benchmark are intentionally not enabled by the default Compose file. They require deployment-specific containment validation before use. `doctor` reports the isolation impact when `FYKE_PCAP` is set. Do not add `NET_RAW` to a sensor container casually.

## Repository map

```text
api/fyke/v1/          protobuf transport contract
cmd/fyke/             single binary command surface
internal/controller/  API, SSE, alerts, metrics
internal/cryptokit/   age identity and evidence sealing
internal/emulator/    stateful non-executing shell
internal/protocol/    SSH, Telnet, HTTP, HTTPS adapters
internal/spool/       bounded encrypted replay queue
internal/store/       SQLite schema, search, retention
frontend/             React, TypeScript, Vite, Tailwind source
internal/web/dist/    embedded production dashboard
```

## Responsible operation

Run Fyke only on infrastructure you own or are authorized to monitor. The operator is responsible for privacy notices, retention policy, access controls, and local law. Fyke sends no product telemetry and performs no automatic updates or active threat-intelligence lookups.
