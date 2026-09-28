#!/bin/bash
set -e

cd "$(dirname "$0")/.."

PICUS_IMAGE="${PICUS_IMAGE:-picus:138b151}"
PICUS_TIMEOUT_MS="${PICUS_TIMEOUT_MS:-20000}"
PICUS_LOG_LEVEL="${PICUS_LOG_LEVEL:-ACCOUNTING}"

if ! [ -x "$(command -v circom)" ]; then
    echo -e '\033[31mError: circom is not installed.\033[0m' >&2
    echo -e '\033[31mError: please install circom: https://docs.circom.io/getting-started/installation/.\033[0m' >&2
    exit 1
fi

if ! [ -x "$(command -v docker)" ] || ! docker info >/dev/null 2>&1; then
    echo -e '\033[31mError: docker is not installed or the daemon is not running.\033[0m' >&2
    echo -e '\033[31mError: please install and start Docker: https://docs.docker.com/get-docker/.\033[0m' >&2
    exit 1
fi

if ! [ -d node_modules/circomlib ]; then
    echo -e '\033[31mError: node_modules/circomlib is missing.\033[0m' >&2
    echo -e '\033[31mError: please run npm ci.\033[0m' >&2
    exit 1
fi

if ! docker image inspect "$PICUS_IMAGE" >/dev/null 2>&1; then
    echo -e "\033[33mDocker image $PICUS_IMAGE not found. Building it from scripts/picus/Dockerfile (takes a few minutes).\033[0m"
    docker build -t "$PICUS_IMAGE" scripts/picus
fi

for circuit in withdraw rln_single rln_multi rln_poseidon2_single rln_poseidon2_multi; do
    echo -e "\033[36m----------------------\033[0m"
    echo -e "\033[36mPICUS $circuit\033[0m"
    echo -e "\033[36m----------------------\033[0m"
    dir="$PWD/build/picus/$circuit"
    mkdir -p "$dir"
    circom "circuits/$circuit.circom" --O0 --r1cs --sym -o "$dir" -l node_modules
    docker run --rm --memory=8g -v "$dir":/w "$PICUS_IMAGE" \
        ./run-picus --solver cvc5 --timeout "$PICUS_TIMEOUT_MS" --log-level "$PICUS_LOG_LEVEL" "/w/$circuit.r1cs" || true
done
