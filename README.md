<h1 align=center>Rate-Limiting Nullifier circuits in Circom</h1>
<p align="center">
    <img src="https://github.com/vacp2p/circom-rln/actions/workflows/test.yml/badge.svg" width="110">
</p>

<div align="center">

_Fork of [Rate-Limiting-Nullifier/circom-rln](https://github.com/Rate-Limiting-Nullifier/circom-rln)
at [v1.0.0](https://github.com/Rate-Limiting-Nullifier/circom-rln/releases/tag/v1.0.0)._

_Circuits at v1.0.0 were audited by Veridise, yAcademy fellows and PSE._

_The other circuits were added in this fork and have not been externally audited._

</div>

---

## What's RLN?

RLN is a zero-knowledge gadget that enables spam
prevention in anonymous environments.

The core parts of RLN are:

- zk-circuits in Circom (this repo);
- [registry smart-contract](https://github.com/Rate-Limiting-Nullifier/rln-contract);
- set of libraries to build app with RLN ([rlnjs](https://github.com/Rate-Limiting-Nullifier/rlnjs), [zerokit](https://github.com/vacp2p/zerokit)).

---

To learn more on RLN and how it works - check out [documentation](https://rate-limiting-nullifier.github.io/rln-docs/).

## Prerequisites

- Node.js 18 (`circom_tester` does not support newer versions)
- [circom](https://docs.circom.io/getting-started/installation/) 2.1.5, installed with `./scripts/install-circom.sh` (needs Rust)
- Run `npm ci` to install the Node.js dependencies (circomlib, snarkjs, circom_tester)

## Build

```bash
npm run build                          # every main circuit
./scripts/build-circuits.sh rln_single # a specific circuit
```

Compiles the circuit, runs the Groth16 setup and writes the artifacts to `zkeyFiles/<circuit>/`.

## Test

```bash
npm test
```

Runs the `ts-mocha` suite in `test/`: witness fixtures for every RLN circuit, official Poseidon2
reference vectors for every arity, and both withdraw circuits.

## Static analysis

Runs [circomspect](https://github.com/trailofbits/circomspect) on every circuit.

```bash
./scripts/circomspect.sh
```

Runs [Picus](https://github.com/Veridise/Picus) on every main circuit (needs Docker).

```bash
./scripts/picus.sh
```

Runs [zkFuzz](https://github.com/Koukyosyumei/zkFuzz) on every main circuit.

```bash
./scripts/zkfuzz.sh
```
