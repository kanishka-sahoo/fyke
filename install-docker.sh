#!/usr/bin/env bash
set -euo pipefail

USER_TO_ADD="${SUDO_USER:-$USER}"

sudo apt remove -y docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc || true

sudo apt update
sudo apt install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<SRC
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
SRC

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker

sudo groupadd docker 2>/dev/null || true
sudo usermod -aG docker "$USER_TO_ADD"

sudo docker run --rm hello-world

echo
echo "Docker installed."
echo "User '$USER_TO_ADD' added to docker group."
echo "Log out and log back in, or run: newgrp docker"
echo "Then test with: docker run --rm hello-world"
