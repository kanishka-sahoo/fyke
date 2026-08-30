# Fyke

Fyke is a single-host, non-executing SSH, Telnet, HTTP, and HTTPS honeypot for a dedicated Debian or Ubuntu VPS. Sensors accept hostile traffic, emulate a coherent fictional machine, and stream normalized evidence to a private controller. Attacker input is never passed to a host or container shell.

## Why “Fyke”?

A **fyke** is a long, bag-shaped fish trap made of netting held open by a series of circular hoops. The name fits this project: Fyke presents an inviting, contained path for hostile traffic, then holds and records the resulting evidence without letting attacker input reach a real shell.

The project is licensed under Apache-2.0.

## Quick start

The supported deployment target is a dedicated Debian or Ubuntu VPS. A standard deployment only requires Docker Engine with Compose v2; Go and Node are needed only for local development.

```sh
git clone https://github.com/ksahoo/fyke.git
cd fyke
./deploy.sh
```

If Docker is not installed, run `./install-docker.sh` first, then log out and back in if the installer adds you to the `docker` group.

The deployment helper builds the pinned image, creates a private deployment directory and identities on first run, validates them with `fyke doctor`, waits for the controller to become ready, and starts the sensors on safe validation ports:

- Dashboard: `http://127.0.0.1:9080`
- SSH: `2222`
- Telnet: `2323`
- HTTP: `8080`
- HTTPS: `8443`

The dashboard deliberately stays on host loopback. From another machine, open it through the VPS administration channel:

```sh
ssh -N -L 9080:127.0.0.1:9080 admin@your-vps
```

Or publish it privately to your tailnet with Tailscale Serve (never Funnel):

```sh
sudo tailscale serve --bg http://127.0.0.1:9080
tailscale serve status
```

Serve terminates HTTPS and forwards Tailscale identity headers to Fyke. Fyke accepts those headers only from loopback or the direct Docker host gateway; other containers and network peers cannot assert proxy identities.

Useful operator commands are:

```sh
./deploy.sh status
./deploy.sh logs
./deploy.sh stop
./deploy.sh firewall          # print and review the generated rules
./deploy.sh firewall apply    # explicitly apply them with nftables
./scripts/go-live.sh          # guided, rollback-aware live port cutover
```

The generated `.env` controls the sensor bind address, ports, runtime UID/GID, and deployment directory; `.env.example` documents every supported value. Never change `FYKE_SSH_PORT` to `22` until an alternate private administration path has been tested. `deploy.sh` refuses wildcard `0.0.0.0:22`; a live deployment must name the public-facing host IPv4 explicitly. Persistent controller data and encrypted sensor spools live in named Docker volumes; `./deploy.sh stop` does not delete them.

To update an existing checkout without replacing its deployment data:

```sh
git pull --ff-only
./deploy.sh
```

Back up `deployment/controller.agekey` separately and securely. It is required to decrypt collected evidence and is intentionally never copied into a sensor container.

## Go live with Tailscale-only administration

The supported cutover keeps real OpenSSH on host loopback and uses Tailscale Serve as its only remote path. Fyke binds the public-facing IPv4 separately, so the real and emulated SSH services can both use port 22 on different addresses:

| Reachability | Port | Destination |
| --- | ---: | --- |
| Public internet | `22` | Fyke SSH sensor |
| Public internet | `23` | Fyke Telnet sensor |
| Public internet | `80` | Fyke HTTP sensor |
| Public internet | `443` | Fyke HTTPS sensor |
| Tailnet only | `22222` | Tailscale TCP proxy to real OpenSSH on `127.0.0.1:22` |
| Tailnet only | HTTPS `443` | Tailscale HTTPS proxy to the dashboard on `127.0.0.1:9080` |

Run the guided cutover on the VPS:

```sh
./scripts/go-live.sh
```

The wizard creates a root-only backup, asks for the IPv4 actually assigned to the public-facing host interface, automatically discovers the VPS MagicDNS hostname from the local Tailscale daemon, walks through a least-privilege tailnet grant, creates both private paths, and requires a successful second SSH session before changing OpenSSH. It accounts for Ubuntu's `ssh.socket`, disables the old Tailscale SSH and HTTP-dashboard endpoints only after replacements work, writes `FYKE_BIND_IP` plus ports `22/23/80/443`, deploys, applies sensor-egress containment, and pauses for external verification.

Keep the original shell and a provider console open throughout the cutover. Tailscale grants are additive: adding an administrator-only grant does not cancel an existing broad allow rule, so review and narrow broader rules in the Access controls page. Tailscale Serve access follows the tailnet policy.

The explicit bind currently publishes the honeypot on IPv4 only. Leave unsolicited public IPv6 inbound closed unless you deliberately add and validate equivalent IPv6 sensor bindings. Do not delete the wizard's `/var/backups/fyke-cutover-*` directory until a reboot has completed and both private paths have been retested.

## Security model

- Sensors expose one protocol each and cannot write SQLite.
- Sensor events and health heartbeats cross a versioned bidirectional gRPC stream authenticated by TLS certificates whose DNS SAN is `sensor.<id>`.
- Every event has a UUIDv7 ID plus a unique sensor, session, and sequence tuple. Replay is idempotent.
- Disconnected sensors spool encrypted records up to 512 MiB. A full spool backpressures the protocol path instead of silently deleting unacknowledged evidence.
- The controller leaves routing and investigation metadata searchable, while sealing credentials, command arguments, bodies, transcripts, and uploads to its generated X25519 age identity.
- The shell module interprets a fixed command vocabulary against a read-only persona and per-session memory overlay. There is no command-execution adapter.
- SFTP writes go to bounded encrypted quarantine. SCP execution is recorded and rejected. URLs are recorded and never fetched.
- Artifact previews are escaped text or hex. Downloads always use `application/octet-stream` and `Content-Disposition: attachment`.
- The dashboard is host-loopback only. Proxy identity headers are rejected unless the peer is configured as trusted or is the verified local Docker host gateway.

Fyke is evidence collection software, not a security boundary by itself. Apply the generated host firewall after verifying a private administration path.

## Build from source

Developer prerequisites are Go 1.24+, Node 24+, and Docker Compose v2.

```sh
make ui
make test
make build
```

The Docker build compiles the React/Tailwind dashboard and then produces a CGO-free distroless image.

## Manual initialization and startup

Never claim public port 22 until you have verified Tailscale or alternate-port SSH administration. The Fyke binary and `deploy.sh` do not modify `sshd`; the explicit `scripts/go-live.sh` cutover does so only after confirmation, validation, and backup.

```sh
./fyke init --dir ./deployment
./fyke doctor --config ./deployment/config.yaml
export FYKE_ROOT=./deployment
export FYKE_UID=$(id -u)
export FYKE_GID=$(id -g)
export FYKE_BIND_IP=0.0.0.0
export FYKE_SSH_PORT=2222
export FYKE_TELNET_PORT=2323
export FYKE_HTTP_PORT=8080
export FYKE_HTTPS_PORT=8443
docker compose build
docker compose up -d
```

The Compose fallback mappings are 22, 23, 80, and 443, while `deploy.sh` and the manual example above use safe validation mappings. To run without exporting the variables into your shell, use the equivalent one-shot form:

```sh
FYKE_ROOT=./deployment FYKE_BIND_IP=0.0.0.0 \
  FYKE_SSH_PORT=2222 FYKE_TELNET_PORT=2323 \
  FYKE_HTTP_PORT=8080 FYKE_HTTPS_PORT=8443 docker compose up -d
```

Verify the dashboard locally at `http://127.0.0.1:9080`. For remote access, use an SSH tunnel or host-managed Tailscale Serve. Do not enable Funnel. The Quick start section includes both commands.

```sh
ssh -N -L 9080:127.0.0.1:9080 admin@your-vps
```

After confirming private administration and normal controller ingestion, explicitly install the IPv4/IPv6 sensor egress policy:

```sh
sudo ./fyke firewall apply --config ./deployment/config.yaml
```

The rule set permits established traffic, leaves the internal controller bridge alone, and drops forwarded traffic originating on the public sensor bridge. Review `fyke firewall print` output before applying it.

## Commands

| Command | Purpose |
| --- | --- |
| `fyke init` | Generate the fictional persona, local CA, mTLS identities, SSH host identity, age identity, and validated configuration. |
| `fyke controller` | Run the single SQLite writer, gRPC ingestion, API, dashboard, alerts, retention, metrics, liveness, and readiness. |
| `fyke sensor --id ID` | Run one configured protocol sensor with its encrypted spool. |
| `fyke doctor` | Validate configuration, persona, identities, and deployment warnings. |
| `fyke firewall print` / `apply` | Review or explicitly install the nftables sensor egress policy. |
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

The private metrics listener exposes `/metrics`, `/livez`, and `/readyz` at the configured loopback address. Compose uses `/readyz` to hold sensors until the controller is healthy. Alert templates cover successful emulated login, artifact upload, novel public-key fingerprint, source spikes, and unhealthy sensors. Sensor health transitions and alert preferences persist across restarts. HTTPS webhook delivery has a bounded queue, bounded exponential retries, and a stable event ID idempotency key.

SQLite uses WAL, full synchronous durability, transactional migrations, normalized indexes, FTS5 metadata search, one serialized writer path, and integrity checks. Defaults retain metadata for 180 days, transcripts for 90 days, payloads for 30 days, and submitted PCAP evidence for 14 days. The 20 GiB cap measures the complete controller data directory; encrypted evidence is evicted in priority order before old event metadata, and SQLite is compacted when metadata must be removed.

## Personas

Persona packs are versioned YAML, not executable plugins. A pack defines the fictional host, users, read-only filesystem, honey credentials, HTTP routes, and protocol banners. Validation rejects path traversal, executable filesystem entries, unknown HTTP methods, and unsupported pack versions.

Honey credentials authenticate immediately. Otherwise, the third failed attempt from one source and protocol inside ten minutes opens an emulated session.

## Current acceptance coverage

Automated tests cover UUIDv7 ordering, strict configuration parsing, generated deployment identities, persona path safety, shell syntax rejection, URL non-fetch behavior, authentication windows, session limits, authenticated health heartbeats, health-alert transitions, persisted alert preferences, encrypted spooling and replay, age sealing, SQLite deduplication, evidence-at-rest encryption, the full on-disk retention cap, Telnet negotiation, and bounded HTTP raw capture. Run all seed corpora and tests with `go test ./...`; run sustained fuzzing with standard Go fuzz flags.

Fyke does not ship a packet-capture profile and grants no sensor `NET_RAW` capability. The `pcap_days` retention setting only governs `pcap` evidence submitted by a separately developed, mutually authenticated sensor. Any packet-capture extension requires deployment-specific containment validation. The full 500-session/100-event-per-second target-VPS benchmark also remains an operator-run acceptance test rather than part of the default Compose startup.

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
