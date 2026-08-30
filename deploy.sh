#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"
ACTION="${1:-up}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. On Debian or Ubuntu, run: ./install-docker.sh" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required. On Debian or Ubuntu, run: ./install-docker.sh" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "The Docker daemon is unavailable to this user. Start Docker, then log out and back in if you were just added to the docker group." >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  umask 077
  {
    echo "FYKE_ROOT=./deployment"
    echo "FYKE_UID=$(id -u)"
    echo "FYKE_GID=$(id -g)"
    echo "FYKE_BIND_IP=0.0.0.0"
    echo "FYKE_SSH_PORT=2222"
    echo "FYKE_TELNET_PORT=2323"
    echo "FYKE_HTTP_PORT=8080"
    echo "FYKE_HTTPS_PORT=8443"
  } >.env
  echo "Created .env with safe, non-privileged validation ports."
fi

while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  case "$key" in
    FYKE_ROOT|FYKE_UID|FYKE_GID|FYKE_BIND_IP|FYKE_SSH_PORT|FYKE_TELNET_PORT|FYKE_HTTP_PORT|FYKE_HTTPS_PORT)
      printf -v "$key" '%s' "$value"
      export "$key"
      ;;
    *)
      echo "Ignoring unsupported .env key: $key" >&2
      ;;
  esac
done <.env

FYKE_ROOT="${FYKE_ROOT:-./deployment}"
FYKE_UID="${FYKE_UID:-$(id -u)}"
FYKE_GID="${FYKE_GID:-$(id -g)}"
FYKE_BIND_IP="${FYKE_BIND_IP:-0.0.0.0}"
export FYKE_ROOT FYKE_UID FYKE_GID FYKE_BIND_IP

if [[ ! "$FYKE_UID" =~ ^[1-9][0-9]*$ || ! "$FYKE_GID" =~ ^[1-9][0-9]*$ ]]; then
  echo "FYKE_UID and FYKE_GID must be positive numeric IDs." >&2
  exit 1
fi

valid_ipv4() {
  local address="$1" octet
  local -a octets
  [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$address"
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
}

if ! valid_ipv4 "$FYKE_BIND_IP"; then
  echo "FYKE_BIND_IP must be an IPv4 address." >&2
  exit 1
fi

if [[ "$FYKE_BIND_IP" != 0.0.0.0 ]]; then
  if ! command -v ip >/dev/null 2>&1 || ! ip -4 address show | grep -Fqw "$FYKE_BIND_IP"; then
    echo "FYKE_BIND_IP must be assigned to a host interface; use the interface address rather than a cloud NAT address." >&2
    exit 1
  fi
fi

for port_name in FYKE_SSH_PORT FYKE_TELNET_PORT FYKE_HTTP_PORT FYKE_HTTPS_PORT; do
  port="${!port_name:-}"
  if [[ ! "$port" =~ ^[0-9]+$ || "$port" -lt 1 || "$port" -gt 65535 ]]; then
    echo "$port_name must be a TCP port between 1 and 65535." >&2
    exit 1
  fi
done

if [[ "$FYKE_SSH_PORT" == 22 && ( "$FYKE_BIND_IP" == 0.0.0.0 || "$FYKE_BIND_IP" == 127.* ) ]]; then
  echo "Refusing to publish Fyke SSH on wildcard or loopback port 22. Set FYKE_BIND_IP to the public-facing host IPv4 after private administration has been verified." >&2
  exit 1
fi

case "$FYKE_ROOT" in
  /|.|..|"")
    echo "FYKE_ROOT must identify a dedicated deployment directory." >&2
    exit 1
    ;;
esac

case "$ACTION" in
  status)
    docker compose ps
    exit 0
    ;;
  logs)
    docker compose logs --follow
    exit 0
    ;;
  stop)
    docker compose down
    exit 0
    ;;
  up|firewall) ;;
  *)
    echo "Usage: ./deploy.sh [up|status|logs|stop|firewall [apply]]" >&2
    exit 1
    ;;
esac

mkdir -p "$FYKE_ROOT"
DEPLOYMENT_DIR="$(cd "$FYKE_ROOT" && pwd)"

docker compose build

if [[ "$ACTION" == firewall ]]; then
  RULES_FILE="$(mktemp)"
  trap 'rm -f "$RULES_FILE"' EXIT
  docker run --rm fyke:local firewall print >"$RULES_FILE"
  if [[ "${2:-}" != apply ]]; then
    cat "$RULES_FILE"
    echo
    echo "Review the rules above, then apply them explicitly with: ./deploy.sh firewall apply"
    exit 0
  fi
  if ! command -v nft >/dev/null 2>&1; then
    echo "nftables is required. Install it with: sudo apt-get install nftables" >&2
    exit 1
  fi
  cat "$RULES_FILE"
  echo
  if [[ ${EUID} -eq 0 ]]; then
    nft delete table inet fyke 2>/dev/null || true
    nft -f "$RULES_FILE"
  else
    sudo nft delete table inet fyke 2>/dev/null || true
    sudo nft -f "$RULES_FILE"
  fi
  echo "Fyke sensor egress policy applied."
  exit 0
fi

if [[ ! -f "$DEPLOYMENT_DIR/config.yaml" ]]; then
  if [[ -n "$(find "$DEPLOYMENT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "$DEPLOYMENT_DIR is non-empty but has no config.yaml; refusing to overwrite it." >&2
    exit 1
  fi
  docker run --rm \
    --user "$FYKE_UID:$FYKE_GID" \
    --mount "type=bind,src=$DEPLOYMENT_DIR,dst=/deployment" \
    fyke:local init --dir /deployment
fi

docker run --rm \
  --user "$FYKE_UID:$FYKE_GID" \
  --mount "type=bind,src=$DEPLOYMENT_DIR,dst=/deployment,readonly" \
  fyke:local doctor --config /deployment/config.yaml

docker compose config --quiet
docker compose up -d --wait

echo
echo "Fyke is running:"
echo "  Sensor bind: ${FYKE_BIND_IP}"
echo "  Dashboard: http://127.0.0.1:9080"
echo "  SSH:       ${FYKE_SSH_PORT:-2222}"
echo "  Telnet:    ${FYKE_TELNET_PORT:-2323}"
echo "  HTTP:      ${FYKE_HTTP_PORT:-8080}"
echo "  HTTPS:     ${FYKE_HTTPS_PORT:-8443}"
echo
if [[ "$FYKE_SSH_PORT" == 22 ]]; then
  echo "Live SSH is published only on ${FYKE_BIND_IP}:22. Re-run scripts/go-live.sh verification before closing the administration shell."
else
  echo "These are validation ports. Run scripts/go-live.sh before moving SSH to public port 22."
fi
