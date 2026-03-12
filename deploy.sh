#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PROJECT_DIR}/build-release"
SERVICE_NAME="fwsvc.service"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}"
ENV_DIR="/etc/fwsvc"
ENV_DST="${ENV_DIR}/fwsvc.env"

cmake -S "${PROJECT_DIR}" -B "${BUILD_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "${BUILD_DIR}"

SERVICE_EXISTS=0
if sudo systemctl cat "${SERVICE_NAME}" >/dev/null 2>&1; then
    SERVICE_EXISTS=1
    sudo systemctl stop "${SERVICE_NAME}"
fi

sudo cmake --install "${BUILD_DIR}" --prefix /usr/local

sudo install -d /etc/systemd/system
sudo install -m 0644 "${PROJECT_DIR}/deploy/fwsvc.service" "${SERVICE_DST}"

sudo install -d "${ENV_DIR}"
if [[ ! -f "${ENV_DST}" ]]; then
    sudo install -m 0640 "${PROJECT_DIR}/deploy/fwsvc.env" "${ENV_DST}"
fi

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"

if [[ ${SERVICE_EXISTS} -eq 1 ]]; then
    sudo systemctl start "${SERVICE_NAME}"
fi
