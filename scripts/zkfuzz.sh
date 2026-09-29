#!/bin/bash
set -e

cd "$(dirname "$0")/.."

ZKFUZZ_MAX_GENERATIONS="${ZKFUZZ_MAX_GENERATIONS:-10}"
ZKFUZZ_LOG_LEVEL="${ZKFUZZ_LOG_LEVEL:-info}"

if ! [ -x "$(command -v zkfuzz)" ]; then
    echo -e '\033[31mError: zkfuzz is not installed.\033[0m' >&2
    echo -e '\033[31mError: please install zkfuzz: cargo install --git https://github.com/Koukyosyumei/zkFuzz zkfuzz (https://github.com/Koukyosyumei/zkFuzz).\033[0m' >&2
    exit 1
fi

if ! [ -d node_modules/circomlib ]; then
    echo -e '\033[31mError: node_modules/circomlib is missing.\033[0m' >&2
    echo -e '\033[31mError: please run npm ci.\033[0m' >&2
    exit 1
fi

settings="build/zkfuzz/settings.json"
mkdir -p "$(dirname "$settings")"
echo "{\"max_generations\": $ZKFUZZ_MAX_GENERATIONS}" > "$settings"

for circuit in withdraw withdraw_poseidon2 rln_single rln_multi rln_poseidon2_single rln_poseidon2_multi; do
    echo -e "\033[36m----------------------\033[0m"
    echo -e "\033[36mZKFUZZ $circuit ($ZKFUZZ_MAX_GENERATIONS generations)\033[0m"
    echo -e "\033[36m----------------------\033[0m"
    RUST_LOG="$ZKFUZZ_LOG_LEVEL" zkfuzz -l node_modules/circomlib/circuits \
        --path_to_mutation_setting "$settings" "circuits/$circuit.circom" || true
done
