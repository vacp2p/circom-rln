#!/bin/bash
set -e

cd "$(dirname "$0")/.."

if ! [ -x "$(command -v circomspect)" ]; then
    echo -e '\033[31mError: circomspect is not installed.\033[0m' >&2
    echo -e '\033[31mError: please install circomspect: cargo install circomspect (https://github.com/trailofbits/circomspect).\033[0m' >&2
    exit 1
fi

if ! [ -d node_modules/circomlib ]; then
    echo -e '\033[31mError: node_modules/circomlib is missing.\033[0m' >&2
    echo -e '\033[31mError: please run npm ci.\033[0m' >&2
    exit 1
fi

for circuit in circuits/*.circom; do
    echo -e "\033[36m----------------------\033[0m"
    echo -e "\033[36mCIRCOMSPECT $circuit\033[0m"
    echo -e "\033[36m----------------------\033[0m"
    circomspect -L node_modules/circomlib/circuits "$circuit" || true
done
