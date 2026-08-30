# Fyke

Fyke is a honeypot for one Debian or Ubuntu VPS. It provides fake SSH, Telnet, HTTP, and HTTPS services. All fake services show the same fictional system. Each sensor sends normalized evidence to a private controller. Fyke never sends attacker input to a host shell or a container shell.

## Why "Fyke"?

A **fyke** is a long, bag-shaped fish trap. Netting forms the bag. Circular hoops hold the bag open.

The name describes how this project works. Fyke gives hostile traffic an inviting path. It contains the traffic and records the evidence. It does not give the attacker a real shell.

Fyke uses the Apache-2.0 license.

## Quick start

Use a dedicated Debian or Ubuntu VPS. The VPS must have Docker Engine and Docker Compose v2. You need Go and Node only for development.

Run these commands:

```sh
git clone https://github.com/ksahoo/fyke.git
cd fyke
./deploy.sh
```

If Docker is not installed, run this command first:

```sh
./install-docker.sh
```

The installer can add your user to the `docker` group. If it does, log out and log in again. Then run `./deploy.sh`.

On the first run, `deploy.sh` does these tasks:

- It builds the Fyke container image from fixed dependency versions.
- It creates a private deployment directory.
- It creates the configuration, persona, keys, and certificates.
- It runs `fyke doctor` to check the new files.
- It waits for the controller to become ready.
- It starts the sensors on safe test ports.

The safe test ports are:

| Service | Address or port |
| --- | ---: |
| Dashboard | `http://127.0.0.1:9080` |
| Fake SSH | `2222` |
| Fake Telnet | `2323` |
| Fake HTTP | `8080` |
| Fake HTTPS | `8443` |

The dashboard listens on the local address only. To open it from another computer, create an SSH tunnel:

```sh
ssh -N -L 9080:127.0.0.1:9080 admin@your-vps
```

You can also use Tailscale Serve:

```sh
sudo tailscale serve --bg http://127.0.0.1:9080
tailscale serve status
```

Do not use Tailscale Funnel. Funnel would make the dashboard public.

Tailscale Serve ends the HTTPS connection and sends Tailscale identity headers to Fyke. Fyke trusts these headers only from the local address or the direct Docker host gateway. Other containers and network peers cannot set a trusted proxy identity.

Use these commands to operate Fyke:

```sh
./deploy.sh status             # Show the containers.
./deploy.sh logs               # Show new log entries.
./deploy.sh stop               # Stop Fyke.
./deploy.sh firewall           # Show the proposed firewall rule.
./deploy.sh firewall apply     # Install the firewall rule.
./scripts/go-live.sh           # Move Fyke to the public ports.
```

The `.env` file contains the sensor address, ports, user ID, group ID, and deployment directory. See `.env.example` for all settings.

Do not set `FYKE_SSH_PORT=22` until you test private access to real SSH. `deploy.sh` blocks `0.0.0.0:22` and `127.0.0.1:22`. For public port 22, set `FYKE_BIND_IP` to the public-facing IPv4 address on the VPS.

Fyke keeps controller data and encrypted sensor queues in named Docker volumes. `./deploy.sh stop` does not delete these volumes.

To update Fyke, run:

```sh
git pull --ff-only
./deploy.sh
```

Save a separate copy of `deployment/controller.agekey`. Keep this copy in a secure place. You need this key to decrypt the collected evidence. Fyke never copies this key into a sensor container.

## Use the public ports

Your tailnet is your private Tailscale network. MagicDNS gives each device in the tailnet a private DNS name.

The recommended setup keeps real OpenSSH on the local address. Tailscale Serve is the only remote path to real OpenSSH. Fyke uses the public-facing IPv4 address.

The public-facing IPv4 address must be an address on a VPS network interface. Do not use a cloud NAT address that is not on the VPS.

This design lets real SSH and fake SSH use port 22 on different addresses:

| Who can connect | Port | Service |
| --- | ---: | --- |
| Public internet | `22` | Fyke SSH sensor |
| Public internet | `23` | Fyke Telnet sensor |
| Public internet | `80` | Fyke HTTP sensor |
| Public internet | `443` | Fyke HTTPS sensor |
| Allowed tailnet users | `22222` | Real OpenSSH through Tailscale |
| Allowed tailnet users | HTTPS `443` | Fyke dashboard through Tailscale |

Run this script on the VPS:

```sh
./scripts/go-live.sh
```

The script reads the VPS MagicDNS name from the local Tailscale service. It does not contain a fixed tailnet domain.

The script guides you through these tasks:

1. Check the required programs and network values.
2. Save a backup that only root can read.
3. Limit access in the Tailscale policy.
4. Create private access to real SSH and the dashboard.
5. Test both private connections from a second device.
6. Move real OpenSSH to the local address.
7. Remove the old Tailscale connections.
8. Start Fyke on public ports 22, 23, 80, and 443.
9. Install the sensor firewall rule.
10. Test the finished setup.

Keep the first SSH window open while you use the script. Also open the provider console before you start. The provider console gives you access if an SSH test fails.

Tailscale grants add access. A new grant does not cancel an old grant or ACL. Check all rules that apply to the VPS. Remove access that is not required.

The public Fyke services listen on IPv4 only. Keep public IPv6 input blocked unless you add and test IPv6 sensor addresses.

The script saves backups in `/var/backups/fyke-public-setup-*`. Keep the backup until you restart the VPS. After the restart, test real SSH and the dashboard again.

## Security design

- Each sensor provides one protocol. A sensor cannot write to SQLite.
- Sensors use a versioned, two-way gRPC stream. They send events and health messages on this stream.
- TLS certificates authenticate the gRPC stream. Each sensor certificate has the DNS SAN `sensor.<id>`.
- Each event has a UUIDv7 ID. It also has a unique sensor, session, and sequence value.
- Fyke can receive the same event again without creating a second copy.
- A disconnected sensor keeps up to 512 MiB of encrypted records.
- If the sensor queue is full, the protocol waits. Fyke does not delete evidence that the controller has not received.
- The controller keeps routing and investigation data searchable.
- The controller encrypts credentials, command arguments, bodies, transcripts, and uploads with its X25519 age identity.
- The fake shell uses a fixed command list, a read-only persona, and temporary session memory.
- The fake shell has no adapter that can run a command.
- SFTP writes go to an encrypted quarantine with a size limit.
- Fyke records and rejects SCP execution.
- Fyke records URLs but never fetches them.
- Artifact previews contain escaped text or hexadecimal data.
- Artifact downloads use `application/octet-stream` and `Content-Disposition: attachment`.
- The dashboard listens on the local host only.
- Fyke rejects proxy identity headers from an untrusted peer.
- Fyke trusts the verified local Docker host gateway when it acts as the proxy.

Fyke collects evidence. It is not a complete security boundary. Test private administrator access before you install the Fyke host firewall rule.

## Build from source

For development, install Go 1.24 or later, Node 24 or later, and Docker Compose v2.

```sh
make ui
make test
make build
```

The Docker build compiles the React and Tailwind dashboard. It then builds a CGO-free program in a distroless image.

## Start Fyke without deploy.sh

Do not use public port 22 until you test private access to real SSH. The `fyke` program and `deploy.sh` do not change OpenSSH. Only `scripts/go-live.sh` changes OpenSSH. It asks for approval, checks the new settings, and saves a backup first.

Use safe test ports for the first manual start:

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

You can also set the values for one command:

```sh
FYKE_ROOT=./deployment FYKE_BIND_IP=0.0.0.0 \
  FYKE_SSH_PORT=2222 FYKE_TELNET_PORT=2323 \
  FYKE_HTTP_PORT=8080 FYKE_HTTPS_PORT=8443 docker compose up -d
```

The Compose file uses ports 22, 23, 80, and 443 if you do not set port values. `deploy.sh` and the examples above use safe test ports.

On the VPS, open `http://127.0.0.1:9080` to test the dashboard. For remote access, use an SSH tunnel or Tailscale Serve. Do not use Tailscale Funnel.

After you test private administrator access, show the sensor firewall rule:

```sh
sudo ./fyke firewall print --config ./deployment/config.yaml
```

Read the rule. Then install it:

```sh
sudo ./fyke firewall apply --config ./deployment/config.yaml
```

The rule permits established traffic. It does not change the private controller bridge. It blocks forwarded traffic from the public sensor bridge.

## Commands

| Command | Action |
| --- | --- |
| `fyke init` | Create the persona, local CA, mTLS identities, SSH host identity, age identity, and configuration. |
| `fyke controller` | Run the single SQLite writer, gRPC input, API, dashboard, alerts, retention, metrics, and health checks. |
| `fyke sensor --id ID` | Run one protocol sensor and its encrypted queue. |
| `fyke doctor` | Check the configuration, persona, identities, and deployment warnings. |
| `fyke firewall print` | Show the sensor firewall rule. |
| `fyke firewall apply` | Install the sensor firewall rule. |
| `fyke export` | Export normalized JSONL or CSV. |
| `fyke backup` | Create a consistent database and artifact tar stream. Encrypt it for a recovery recipient. |
| `fyke restore` | Check and restore a backup into an empty directory. |

`fyke export --include-sensitive` includes sensitive evidence. You must select this option. Fyke records the action in the audit log.

## Back up and restore data

Stop the controller before a backup. This stops changes to the database and artifacts during the backup.

```sh
FYKE_ROOT=./deployment docker compose stop controller
./fyke backup --config ./deployment/config.yaml \
  --recipient age1... --out fyke-$(date +%F).tar.age
FYKE_ROOT=./deployment docker compose start controller
```

Restore a backup while Fyke is offline. The target directory must be empty.

```sh
./fyke restore --backup fyke-2026-08-28.tar.age \
  --identity recovery.agekey --target ./restored-data
```

During a restore, Fyke rejects unsafe archive paths. It also checks each file hash in the manifest.

## API and operation

The controller provides `/api/v1` on the local address. The main resources are:

- `GET /overview`, `/events`, `/sessions`, `/sources`, `/artifacts`, and `/alerts`
- `GET /stream` for the live server-sent event stream
- `GET /artifacts/{id}/preview` and `/download`
- `GET /exports?format=jsonl|csv&sensitive=false`
- `GET /health`, `/retention`, and `/preferences/alerts`
- `POST /retention/run` and `PUT /preferences/alerts`

The private metrics service provides `/metrics`, `/livez`, and `/readyz`. It listens on the configured local address. Docker Compose waits for `/readyz` before it starts the sensors.

Fyke can alert on these events:

- A successful fake login
- An artifact upload
- A new public-key fingerprint
- A source traffic spike
- An unhealthy sensor

Fyke saves sensor health changes and alert preferences. These values remain after a restart.

The HTTPS webhook queue has a fixed size. Failed requests use bounded exponential retries. Each request has a stable event ID for idempotency.

SQLite uses WAL and full synchronous durability. Fyke uses transactions for migrations. It also uses normalized indexes, FTS5 metadata search, one serialized writer, and integrity checks.

The default retention periods are:

| Data | Retention period |
| --- | ---: |
| Metadata | 180 days |
| Transcripts | 90 days |
| Payloads | 30 days |
| Submitted PCAP evidence | 14 days |

The default storage limit is 20 GiB. Fyke measures the complete controller data directory. It removes encrypted evidence in priority order before it removes old event metadata. Fyke compacts SQLite when it must remove metadata.

## Personas

A persona pack is a versioned YAML file. It is not an executable plugin.

A persona defines the fake host, users, read-only file system, honey credentials, HTTP routes, and protocol banners. Fyke rejects path traversal, executable file entries, unknown HTTP methods, and unsupported persona versions.

Honey credentials open a fake session immediately. Other credentials fail two times. The third failed attempt opens a fake session. The three attempts must use one source and one protocol within ten minutes.

## Test coverage

Automated tests cover these functions:

- UUIDv7 ordering
- Strict configuration parsing
- Generated deployment identities
- Persona path safety
- Shell syntax rejection
- URL non-fetch behavior
- Authentication time windows
- Session limits
- Authenticated health messages
- Health alert changes
- Saved alert preferences
- Encrypted sensor queues and replay
- Age encryption
- SQLite duplicate rejection
- Encryption of stored evidence
- The complete storage limit
- Telnet negotiation
- Bounded HTTP raw capture

Run all tests and seed data with:

```sh
go test ./...
```

Use the standard Go fuzz options for longer fuzz tests.

Fyke does not include a packet-capture profile. Sensors do not have the `NET_RAW` capability. The `pcap_days` setting applies only to PCAP evidence from a separate, mutually authenticated sensor. Test the isolation of each packet-capture extension before deployment.

The target VPS benchmark is 500 sessions and 100 events each second. The operator must run this acceptance test. It is not part of the default Docker Compose start.

## Repository map

```text
api/fyke/v1/          protobuf transport contract
cmd/fyke/             command-line program
internal/controller/  API, SSE, alerts, and metrics
internal/cryptokit/   age identity and evidence encryption
internal/emulator/    fake shell with session state
internal/protocol/    SSH, Telnet, HTTP, and HTTPS sensors
internal/spool/       bounded encrypted replay queue
internal/store/       SQLite schema, search, and retention
frontend/             React, TypeScript, Vite, and Tailwind source
internal/web/dist/    dashboard files included in the program
```

## Responsible operation

Run Fyke only on systems that you own or have permission to monitor. You are responsible for privacy notices, retention settings, access controls, and local law.

Fyke does not send product telemetry. It does not update itself. It does not make active threat intelligence requests.
