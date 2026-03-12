#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

source "${ROOT_DIR}/.env"

FW_DEBUG_VALUE="${FW_DEBUG:-1}"
FW_DATABASE_URL_VALUE="${FW_DATABASE_URL:-${DATABASE_URL:-}}"
PGPASSFILE_VALUE="${PGPASSFILE:-}"

cmake -S "${ROOT_DIR}" \
  -B "${BUILD_DIR}" \
  -G Ninja \
  -DCMAKE_C_COMPILER=/usr/bin/clang \
  -DCMAKE_BUILD_TYPE=Debug  

cmake --build "${BUILD_DIR}"


if [[ -z "${FW_DATABASE_URL_VALUE}" ]]; then
  echo "FW_DATABASE_URL or DATABASE_URL must be set" >&2
  exit 1
fi

if [[ "${EUID}" -eq 0 ]]; then
  export FW_DEBUG="${FW_DEBUG_VALUE}"
  export FW_DATABASE_URL="${FW_DATABASE_URL_VALUE}"
  if [[ -n "${PGPASSFILE_VALUE}" ]]; then
    export PGPASSFILE="${PGPASSFILE_VALUE}"
  fi
  exec "${BUILD_DIR}/fwsvc"
fi

#echo "FW_DATABASE_URL_VALUE=${FW_DATABASE_URL_VALUE}"

sudo_env=(env "FW_DEBUG=${FW_DEBUG_VALUE}" "FW_DATABASE_URL=${FW_DATABASE_URL_VALUE}")
if [[ -n "${PGPASSFILE_VALUE}" ]]; then
  sudo_env+=("PGPASSFILE=${PGPASSFILE_VALUE}")
fi

sudo "${sudo_env[@]}" "${BUILD_DIR}/fwsvc"

