import * as path from "path";
import assert from "assert";
const tester = require("circom_tester").wasm;
const snarkjs = require("snarkjs");
import poseidon from "poseidon-lite";
import {
  calculateOutput,
  genFieldElement,
  genMerkleProof,
  getSignal,
} from "./utils";

const circuitPath = path.join(__dirname, "..", "circuits", "rln_single.circom");

// ffjavascript has no types so leave circuit with untyped
type CircuitT = any;

function calculateLeaf(identitySecret: bigint, userMessageLimit: bigint) {
  const identityCommitment = poseidon([identitySecret]);
  const rateCommitment = poseidon([identityCommitment, userMessageLimit]);
  return rateCommitment;
}

describe("Test rln_single.circom", function () {
  let circuit: CircuitT;

  this.timeout(30000);

  before(async function () {
    circuit = await tester(circuitPath);
  });

  it("Should generate witness with correct outputs", async () => {
    // Public inputs
    const x = genFieldElement();
    const externalNullifier = genFieldElement();
    // Private inputs
    const identitySecret = genFieldElement();
    const userMessageLimit = BigInt(10);
    const leaf = calculateLeaf(identitySecret, userMessageLimit);
    const merkleProof = genMerkleProof([leaf], 0);
    const merkleRoot = merkleProof.root;
    const messageId = userMessageLimit - BigInt(1);

    const inputs = {
      // Private inputs
      identitySecret,
      userMessageLimit,
      messageId,
      pathElements: merkleProof.siblings,
      identityPathIndex: merkleProof.pathIndices,
      // Public inputs
      x,
      externalNullifier,
    };

    // Test: should generate proof if inputs are correct
    const witness: bigint[] = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(witness);

    const { y, nullifier } = calculateOutput(
      identitySecret,
      x,
      externalNullifier,
      messageId,
    );

    const outputRoot = await getSignal(circuit, witness, "root");
    const outputY = await getSignal(circuit, witness, "y");
    const outputNullifier = await getSignal(circuit, witness, "nullifier");

    assert.equal(outputY, y);
    assert.equal(outputRoot, merkleRoot);
    assert.equal(outputNullifier, nullifier);
  });

  it("Should compute the root for a member at a non-zero index (path index bits set)", async () => {
    // Every other test proves membership at index 0, where all path index bits are 0 and
    // the hash order sibling/node never flips; index 3 sets the two lowest bits and
    // exercises the flipped order in MerkleTreeInclusionProof.
    const x = genFieldElement();
    const externalNullifier = genFieldElement();
    const identitySecret = genFieldElement();
    const userMessageLimit = BigInt(10);
    const messageId = BigInt(0);
    const leaf = calculateLeaf(identitySecret, userMessageLimit);
    const otherLeaves = [genFieldElement(), genFieldElement(), genFieldElement()];
    const merkleProof = genMerkleProof([...otherLeaves, leaf], 3);

    const inputs = {
      identitySecret,
      userMessageLimit,
      messageId,
      pathElements: merkleProof.siblings,
      identityPathIndex: merkleProof.pathIndices,
      x,
      externalNullifier,
    };

    const witness: bigint[] = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(witness);

    const { y, nullifier } = calculateOutput(
      identitySecret,
      x,
      externalNullifier,
      messageId,
    );

    assert.equal(await getSignal(circuit, witness, "root"), merkleProof.root);
    assert.equal(await getSignal(circuit, witness, "y"), y);
    assert.equal(await getSignal(circuit, witness, "nullifier"), nullifier);
  });

  it("Should fail to generate witness if messageId is not in range [0, userMessageLimit-1]", async function () {
    // Public inputs
    const x = genFieldElement();
    const externalNullifier = genFieldElement();
    // Private inputs
    const identitySecret = genFieldElement();
    const identitySecretCommitment = poseidon([identitySecret]);
    const merkleProof = genMerkleProof([identitySecretCommitment], 0);
    const userMessageLimit = BigInt(10);
    // valid message id is in the range [0, userMessageLimit-1]
    const invalidMessageIds = [userMessageLimit, userMessageLimit + BigInt(1)];

    for (const invalidMessageId of invalidMessageIds) {
      const inputs = {
        // Private inputs
        identitySecret,
        userMessageLimit,
        messageId: invalidMessageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        // Public inputs
        x,
        externalNullifier,
      };
      await assert.rejects(async () => {
        await circuit.calculateWitness(inputs, true);
      }, /Error: Assert Failed/);
    }
  });

  describe("Performance Tests", () => {
    it("Should measure zkSNARK proof generation time", async function () {
      this.timeout(600000);

      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = BigInt(0);
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);

      const inputs = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x,
        externalNullifier,
      };

      const numRuns = 20;
      const witnessTimes: number[] = [];
      const proofTimes: number[] = [];

      for (let i = 0; i < numRuns; i++) {
        const witnessStart = performance.now();
        const _ = await circuit.calculateWitness(inputs, true);
        const witnessTime = performance.now() - witnessStart;
        witnessTimes.push(witnessTime);

        const proofStart = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          inputs,
          path.join(
            __dirname,
            "..",
            "build",
            "rln_single_js",
            "rln_single.wasm",
          ),
          path.join(__dirname, "..", "zkeyFiles", "rln_single", "final.zkey"),
        );
        const proofTime = performance.now() - proofStart;
        proofTimes.push(proofTime);

        if (i === 0) {
          const vKey = require(
            path.join(
              __dirname,
              "..",
              "zkeyFiles",
              "rln_single",
              "verification_key.json",
            ),
          );
          const isValid = await snarkjs.groth16.verify(
            vKey,
            publicSignals,
            proof,
          );
          assert.equal(isValid, true, "Proof should be valid");
        }
      }

      const avgWitnessTime =
        witnessTimes.reduce((a, b) => a + b, 0) / witnessTimes.length;
      const avgProofTime =
        proofTimes.reduce((a, b) => a + b, 0) / proofTimes.length;
      const minWitnessTime = Math.min(...witnessTimes);
      const maxWitnessTime = Math.max(...witnessTimes);
      const minProofTime = Math.min(...proofTimes);
      const maxProofTime = Math.max(...proofTimes);

      console.log(`\n      === Single Message - Witness Generation Times ===`);
      console.log(`      - Average: ${avgWitnessTime.toFixed(2)}ms`);
      console.log(`      - Min: ${minWitnessTime.toFixed(2)}ms`);
      console.log(`      - Max: ${maxWitnessTime.toFixed(2)}ms`);
      console.log(
        `\n      === Single Message - Full Proof Generation Times ===`,
      );
      console.log(`      - Average: ${avgProofTime.toFixed(2)}ms`);
      console.log(`      - Min: ${minProofTime.toFixed(2)}ms`);
      console.log(`      - Max: ${maxProofTime.toFixed(2)}ms`);
      console.log(
        `      - Average proof-only time: ${(
          avgProofTime - avgWitnessTime
        ).toFixed(2)}ms\n`,
      );
    });
  });
});
