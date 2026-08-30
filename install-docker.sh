#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /etc/os-release ]]; then
  echo "This script cannot identify the operating system." >&2
  echo "Install Docker Engine and Docker Compose v2 manually." >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
  ubuntu|debian) DOCKER_DISTRO="$ID" ;;
  *)
    echo "This script supports Debian and Ubuntu only." >&2
    echo "For ${PRETTY_NAME:-this system}, use https://docs.docker.com/engine/install/." >&2
    exit 1
    ;;
esac
if [[ -z "${VERSION_CODENAME:-}" ]]; then
  echo "VERSION_CODENAME is missing from /etc/os-release." >&2
  exit 1
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "Docker Engine and Compose v2 are already installed."
  exit 0
fi

if [[ ${EUID} -eq 0 ]]; then
  SUDO=()
  USER_TO_ADD="${SUDO_USER:-}"
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required to install Docker." >&2
    exit 1
  fi
  SUDO=(sudo)
  USER_TO_ADD="$USER"
fi

"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y ca-certificates curl
"${SUDO[@]}" install -m 0755 -d /etc/apt/keyrings
"${SUDO[@]}" curl -fsSL "https://download.docker.com/linux/$DOCKER_DISTRO/gpg" -o /etc/apt/keyrings/docker.asc
"${SUDO[@]}" chmod a+r /etc/apt/keyrings/docker.asc

ARCHITECTURE="$(dpkg --print-architecture)"
SOURCE_FILE="/etc/apt/sources.list.d/docker.sources"
TEMP_SOURCE="$(mktemp)"
trap 'rm -f "$TEMP_SOURCE"' EXIT
{
  echo "Types: deb"
  echo "URIs: https://download.docker.com/linux/$DOCKER_DISTRO"
  echo "Suites: $VERSION_CODENAME"
  echo "Components: stable"
  echo "Architectures: $ARCHITECTURE"
  echo "Signed-By: /etc/apt/keyrings/docker.asc"
} >"$TEMP_SOURCE"
"${SUDO[@]}" install -m 0644 "$TEMP_SOURCE" "$SOURCE_FILE"

"${SUDO[@]}" apt-get update
if ! "${SUDO[@]}" apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
  echo "An installed container program conflicts with the Docker packages." >&2
  echo "Use the removal steps at https://docs.docker.com/engine/install/$DOCKER_DISTRO/#uninstall-old-versions." >&2
  echo "Then run this script again." >&2
  exit 1
fi

"${SUDO[@]}" systemctl enable --now docker
if [[ -n "$USER_TO_ADD" && "$USER_TO_ADD" != root ]]; then
  "${SUDO[@]}" groupadd docker 2>/dev/null || true
  "${SUDO[@]}" usermod -aG docker "$USER_TO_ADD"
fi
"${SUDO[@]}" docker run --rm hello-world

echo
echo "Docker Engine and Compose v2 are installed."
if [[ -n "$USER_TO_ADD" && "$USER_TO_ADD" != root ]]; then
  echo "Added user '$USER_TO_ADD' to the docker group."
  echo "Log out and log in again. Then run ./deploy.sh."
else
  echo "Run ./deploy.sh as the non-root user who will manage Fyke."
fi
