// Node path utilities for file path resolution
import * as path from "path";
// Assertion library for test validation
import assert from "assert";
// Circom tester for compiling and testing circuits (WASM backend)
const tester = require("circom_tester").wasm;
// SnarkJS library for generating and verifying zero-knowledge proofs
const snarkjs = require("snarkjs");
// Poseidon hash function optimized for zero-knowledge circuits
import poseidon from "poseidon-lite";
// Import test utility functions
import {
  calculateOutput,
  calculateMultiOutput,
  genFieldElement,
  genMerkleProof,
  getSignal,
  getSignalArray,
} from "./utils";

// Path to the RLN circuit file
const circuitPath = path.join(__dirname, "..", "circuits", "rln_multi.circom");

// Circuit type - circom_tester has no TypeScript types
type CircuitT = any;

// Maximum number of message slots in the circuit (must match circuit instantiation)
const MAX_OUT = 4; // Default MAX_OUT from circuit instantiation

/**
 * Calculate the rate commitment leaf value for Merkle tree insertion
 * This is the value that gets stored in the Merkle tree for each user
 *
 * @param identitySecret - User's secret identity
 * @param userMessageLimit - Maximum number of messages user can send per epoch
 * @returns rateCommitment = H(H(identitySecret), userMessageLimit)
 */
function calculateLeaf(identitySecret: bigint, userMessageLimit: bigint) {
  // Step 1: Calculate identity commitment from secret
  const identityCommitment = poseidon([identitySecret]);
  // Step 2: Calculate rate commitment (combines identity + rate limit)
  const rateCommitment = poseidon([identityCommitment, userMessageLimit]);
  return rateCommitment;
}

describe("Test rln_multi.circom", function () {
  let circuit: CircuitT;

  this.timeout(60000);

  before(async function () {
    circuit = await tester(circuitPath);
  });

  describe("RFC Compliant Tests - Single Slot Burns", () => {
    it("Should work with messageId=[0] - single slot burn", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 0, 0, 0]; // Only burn first slot

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(0), BigInt(0), BigInt(0)]; // Burn message_id 0
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);
      const merkleRoot = merkleProof.root;

      const inputs = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x,
        externalNullifier,
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      // Verify output matches expected value for message_id=0
      const { y, nullifier } = calculateOutput(
        identitySecret,
        x,
        externalNullifier,
        BigInt(0),
      );

      const outputRoot = await getSignal(circuit, witness, "root");
      const outputY0 = await getSignalArray(circuit, witness, "y", 0);
      const outputNullifier0 = await getSignalArray(
        circuit,
        witness,
        "nullifier",
        0,
      );

      assert.equal(outputY0, y);
      assert.equal(outputRoot, merkleRoot);
      assert.equal(outputNullifier0, nullifier);

      // Verify NULL outputs (slots 1,2,3 should be zero)
      for (let i = 1; i < MAX_OUT; i++) {
        const outputY_i = await getSignalArray(circuit, witness, "y", i);
        const outputNullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        assert.equal(outputY_i, BigInt(0), `y[${i}] should be NULL (0)`);
        assert.equal(
          outputNullifier_i,
          BigInt(0),
          `nullifier[${i}] should be NULL (0)`,
        );
      }
    });

    it("Should fail if messageId[0] >= userMessageLimit when selectorUsed[0]=1", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 0, 0, 0]; // Slot 0 is active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(5);
      const messageId = [BigInt(10), BigInt(0), BigInt(0), BigInt(0)]; // Invalid: 10 >= 5
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
        selectorUsed,
      };

      await assert.rejects(async () => {
        await circuit.calculateWitness(inputs, true);
      }, /Error: Assert Failed/);
    });
  });

  describe("Multi-burn Tests with Consecutive message_ids", () => {
    it("Should burn consecutive message_ids [0,1,2,3]", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 1, 1]; // All slots active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(1), BigInt(2), BigInt(3)]; // Consecutive
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);
      const merkleRoot = merkleProof.root;

      const inputs = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x,
        externalNullifier,
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      // Verify all outputs
      const { y, nullifier } = calculateMultiOutput(
        identitySecret,
        x,
        externalNullifier,
        messageId,
        selectorUsed,
        MAX_OUT,
      );

      const outputRoot = await getSignal(circuit, witness, "root");
      assert.equal(outputRoot, merkleRoot);

      for (let i = 0; i < MAX_OUT; i++) {
        const outputY_i = await getSignalArray(circuit, witness, "y", i);
        const outputNullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        assert.equal(outputY_i, y[i], `y[${i}] mismatch`);
        assert.equal(
          outputNullifier_i,
          nullifier[i],
          `nullifier[${i}] mismatch`,
        );
      }
    });

    it("Should burn partial [0,1] with NULL outputs for [2,3]", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 0, 0]; // Only first 2 active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(1), BigInt(0), BigInt(0)]; // Only first 2 matter
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);
      const merkleRoot = merkleProof.root;

      const inputs = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x,
        externalNullifier,
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      // Verify outputs with masking
      const { y, nullifier } = calculateMultiOutput(
        identitySecret,
        x,
        externalNullifier,
        messageId,
        selectorUsed,
        MAX_OUT,
      );

      const outputRoot = await getSignal(circuit, witness, "root");
      assert.equal(outputRoot, merkleRoot);

      for (let i = 0; i < MAX_OUT; i++) {
        const outputY_i = await getSignalArray(circuit, witness, "y", i);
        const outputNullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        assert.equal(outputY_i, y[i], `y[${i}] mismatch`);
        assert.equal(
          outputNullifier_i,
          nullifier[i],
          `nullifier[${i}] mismatch`,
        );
      }

      // Specifically verify NULL outputs for slots 2 and 3
      const outputY2 = await getSignalArray(circuit, witness, "y", 2);
      const outputY3 = await getSignalArray(circuit, witness, "y", 3);
      const outputNullifier2 = await getSignalArray(
        circuit,
        witness,
        "nullifier",
        2,
      );
      const outputNullifier3 = await getSignalArray(
        circuit,
        witness,
        "nullifier",
        3,
      );
      assert.equal(outputY2, BigInt(0), "y[2] should be NULL (0)");
      assert.equal(outputY3, BigInt(0), "y[3] should be NULL (0)");
      assert.equal(
        outputNullifier2,
        BigInt(0),
        "nullifier[2] should be NULL (0)",
      );
      assert.equal(
        outputNullifier3,
        BigInt(0),
        "nullifier[3] should be NULL (0)",
      );
    });
  });

  describe("Inactive Slot Validation", () => {
    it("Should NOT validate inactive messageIds (can be >= userMessageLimit)", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 0, 0]; // Only first 2 active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(5), BigInt(8), BigInt(999), BigInt(9999)]; // Last 2 invalid but inactive
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
        selectorUsed,
      };

      // Should succeed because inactive slots skip validation
      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      // Verify active slots have valid outputs
      const { y, nullifier } = calculateMultiOutput(
        identitySecret,
        x,
        externalNullifier,
        messageId,
        selectorUsed,
        MAX_OUT,
      );

      for (let i = 0; i < 2; i++) {
        const outputY_i = await getSignalArray(circuit, witness, "y", i);
        const outputNullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        assert.equal(outputY_i, y[i], `y[${i}] mismatch`);
        assert.equal(
          outputNullifier_i,
          nullifier[i],
          `nullifier[${i}] mismatch`,
        );
      }

      // Verify NULL outputs for inactive slots
      for (let i = 2; i < MAX_OUT; i++) {
        const outputY_i = await getSignalArray(circuit, witness, "y", i);
        const outputNullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        assert.equal(outputY_i, BigInt(0), `y[${i}] should be NULL (0)`);
        assert.equal(
          outputNullifier_i,
          BigInt(0),
          `nullifier[${i}] should be NULL (0)`,
        );
      }
    });
  });

  describe("Non-contiguous Selector Tests (RFC Feature)", () => {
    it("Should burn non-contiguous slots [1,0,1,0] - slots 0 and 2 only", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 0, 1, 0]; // Non-contiguous: slots 0 and 2

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(50);
      const messageId = [BigInt(5), BigInt(10), BigInt(15), BigInt(20)];
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
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      const { y, nullifier } = calculateMultiOutput(
        identitySecret,
        x,
        externalNullifier,
        messageId,
        selectorUsed,
        MAX_OUT,
      );

      for (let i = 0; i < MAX_OUT; i++) {
        const outputY_i = await getSignalArray(circuit, witness, "y", i);
        const outputNullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        assert.equal(outputY_i, y[i], `y[${i}] mismatch`);
        assert.equal(
          outputNullifier_i,
          nullifier[i],
          `nullifier[${i}] mismatch`,
        );
      }

      // Verify specific slots
      assert.notEqual(
        await getSignalArray(circuit, witness, "y", 0),
        BigInt(0),
        "y[0] should be active",
      );
      assert.equal(
        await getSignalArray(circuit, witness, "y", 1),
        BigInt(0),
        "y[1] should be NULL",
      );
      assert.notEqual(
        await getSignalArray(circuit, witness, "y", 2),
        BigInt(0),
        "y[2] should be active",
      );
      assert.equal(
        await getSignalArray(circuit, witness, "y", 3),
        BigInt(0),
        "y[3] should be NULL",
      );
    });

    it("Should burn only last slot [0,0,0,1]", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [0, 0, 0, 1]; // Only last slot

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(50);
      const messageId = [BigInt(5), BigInt(10), BigInt(15), BigInt(20)];
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
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      // Verify only last slot is active
      for (let i = 0; i < MAX_OUT - 1; i++) {
        const outputY_i = await getSignalArray(circuit, witness, "y", i);
        const outputNullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        assert.equal(outputY_i, BigInt(0), `y[${i}] should be NULL (0)`);
        assert.equal(
          outputNullifier_i,
          BigInt(0),
          `nullifier[${i}] should be NULL (0)`,
        );
      }

      // Last slot should be active
      const { y, nullifier } = calculateOutput(
        identitySecret,
        x,
        externalNullifier,
        BigInt(20),
      );
      const outputY3 = await getSignalArray(circuit, witness, "y", 3);
      const outputNullifier3 = await getSignalArray(
        circuit,
        witness,
        "nullifier",
        3,
      );
      assert.equal(outputY3, y, "y[3] should match");
      assert.equal(outputNullifier3, nullifier, "nullifier[3] should match");
    });

  });

  describe("Edge Cases and Validation", () => {
    it("Should fail with all-zero selector [0,0,0,0] - at least one slot must be active", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [0, 0, 0, 0]; // No slots active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
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
        selectorUsed,
      };

      await assert.rejects(async () => {
        await circuit.calculateWitness(inputs, true);
      }, /Error: Assert Failed/);
    });

    it("Should fail if active slots have duplicate messageIds", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 0, 0]; // Both slots active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      // Both active slots use the same messageId
      const messageId = [BigInt(5), BigInt(5), BigInt(0), BigInt(0)];
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
        selectorUsed,
      };

      await assert.rejects(async () => {
        await circuit.calculateWitness(inputs, true);
      }, /Error: Assert Failed/);
    });

    it("Should allow duplicate messageIds in inactive slots", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 0, 0, 0]; // Only first slot active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      // Inactive slots share the same (invalid) messageId - this is fine
      const messageId = [BigInt(5), BigInt(5), BigInt(5), BigInt(5)];
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
        selectorUsed,
      };

      // Should succeed - only active slots are checked for uniqueness
      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);
    });

    it("Should fail if selectorUsed contains non-binary value", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 2, 0, 0]; // Invalid: 2 is not binary

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(1), BigInt(2), BigInt(3)];
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
        selectorUsed,
      };

      await assert.rejects(async () => {
        await circuit.calculateWitness(inputs, true);
      }, /Error: Assert Failed/);
    });

    it("Should work when burning all allowed message_ids", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 1, 0]; // 3 active slots

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(3); // Exactly 3 allowed
      const messageId = [BigInt(0), BigInt(1), BigInt(2), BigInt(0)];
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);
      const merkleRoot = merkleProof.root;

      const inputs = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x,
        externalNullifier,
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      const outputRoot = await getSignal(circuit, witness, "root");
      assert.equal(outputRoot, merkleRoot);
    });

    it("Should work with userMessageLimit = 1 (single message allowed)", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 0, 0, 0]; // Only first slot

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(1); // Only 1 message allowed
      const messageId = [BigInt(0), BigInt(0), BigInt(0), BigInt(0)]; // Only 0 is valid
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
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      const { y, nullifier } = calculateOutput(
        identitySecret,
        x,
        externalNullifier,
        BigInt(0),
      );

      const outputY0 = await getSignalArray(circuit, witness, "y", 0);
      const outputNullifier0 = await getSignalArray(
        circuit,
        witness,
        "nullifier",
        0,
      );
      assert.equal(outputY0, y);
      assert.equal(outputNullifier0, nullifier);
    });
  });

  describe("Nullifier Uniqueness", () => {
    it("Should produce unique nullifiers for different message_ids", async () => {
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 1, 1]; // All active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(50);
      const messageId = [BigInt(5), BigInt(10), BigInt(15), BigInt(20)];
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
        selectorUsed,
      };

      const witness: bigint[] = await circuit.calculateWitness(inputs, true);
      await circuit.checkConstraints(witness);

      // Collect all nullifiers
      const nullifiers: bigint[] = [];
      for (let i = 0; i < MAX_OUT; i++) {
        const nullifier_i = await getSignalArray(
          circuit,
          witness,
          "nullifier",
          i,
        );
        nullifiers.push(nullifier_i);
      }

      // Verify all nullifiers are unique
      const uniqueNullifiers = new Set(nullifiers.map((n) => n.toString()));
      assert.equal(
        uniqueNullifiers.size,
        MAX_OUT,
        "All nullifiers should be unique",
      );
    });

    it("Should produce the same nullifier for same (identitySecret, externalNullifier, messageId)", async () => {
      const x1 = genFieldElement();
      const x2 = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 0, 0]; // First 2 active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(5), BigInt(7), BigInt(0), BigInt(0)];
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);

      // First proof
      const inputs1 = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x: x1,
        externalNullifier,
        selectorUsed,
      };

      const witness1: bigint[] = await circuit.calculateWitness(inputs1, true);
      const nullifier1_0 = await getSignalArray(
        circuit,
        witness1,
        "nullifier",
        0,
      );
      const nullifier1_1 = await getSignalArray(
        circuit,
        witness1,
        "nullifier",
        1,
      );

      // Second proof with different x
      const inputs2 = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x: x2,
        externalNullifier,
        selectorUsed,
      };

      const witness2: bigint[] = await circuit.calculateWitness(inputs2, true);
      const nullifier2_0 = await getSignalArray(
        circuit,
        witness2,
        "nullifier",
        0,
      );
      const nullifier2_1 = await getSignalArray(
        circuit,
        witness2,
        "nullifier",
        1,
      );

      // Nullifiers should be the same across proofs (independent of x)
      assert.equal(
        nullifier1_0,
        nullifier2_0,
        "nullifier[0] should match across proofs",
      );
      assert.equal(
        nullifier1_1,
        nullifier2_1,
        "nullifier[1] should match across proofs",
      );
    });

  });

  describe("Slashing Compatibility", () => {
    it("Should enable secret recovery from two proofs with same (externalNullifier, messageId)", async () => {
      const externalNullifier = genFieldElement();
      const messageIdValue = BigInt(5); // Using message_id = 5
      const selectorUsed = [1, 0, 0, 0]; // Single slot active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [messageIdValue, BigInt(0), BigInt(0), BigInt(0)];
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);

      // First proof with x1
      const x1 = genFieldElement();
      const inputs1 = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x: x1,
        externalNullifier,
        selectorUsed,
      };

      const witness1: bigint[] = await circuit.calculateWitness(inputs1, true);
      const y1 = await getSignalArray(circuit, witness1, "y", 0);

      // Second proof with x2 (same epoch and message_id - double spending!)
      const x2 = genFieldElement();
      const inputs2 = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x: x2,
        externalNullifier,
        selectorUsed,
      };

      const witness2: bigint[] = await circuit.calculateWitness(inputs2, true);
      const y2 = await getSignalArray(circuit, witness2, "y", 0);

      // Recover identity secret using Shamir's Secret Sharing
      // y1 = identitySecret + a1 * x1
      // y2 = identitySecret + a1 * x2
      // => (y1 - y2) = a1 * (x1 - x2)
      // => a1 = (y1 - y2) / (x1 - x2)
      // => identitySecret = y1 - a1 * x1

      const ffjavascript = require("ffjavascript");
      const SNARK_FIELD_SIZE = BigInt(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
      );
      const F = new ffjavascript.ZqField(SNARK_FIELD_SIZE);

      const a1 = F.div(F.sub(y1, y2), F.sub(x1, x2));
      const recoveredSecret = F.sub(y1, F.mul(a1, x1));

      assert.equal(
        recoveredSecret,
        identitySecret,
        "Should recover identity secret from two shares",
      );
    });

    it("Should enable slashing from multi-burn proof with double-signaling on one slot", async () => {
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 0, 0]; // 2 active slots

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(5), BigInt(7), BigInt(0), BigInt(0)];
      const leaf = calculateLeaf(identitySecret, userMessageLimit);
      const merkleProof = genMerkleProof([leaf], 0);

      // First multi-burn proof
      const x1 = genFieldElement();
      const inputs1 = {
        identitySecret,
        userMessageLimit,
        messageId,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x: x1,
        externalNullifier,
        selectorUsed,
      };

      const witness1: bigint[] = await circuit.calculateWitness(inputs1, true);
      const y1_slot0 = await getSignalArray(circuit, witness1, "y", 0);

      // Second proof reusing message_id=5 (slot 0) - double spending!
      const x2 = genFieldElement();
      const selectorUsed2 = [1, 0, 0, 0]; // Only slot 0
      const messageId2 = [BigInt(5), BigInt(0), BigInt(0), BigInt(0)]; // Same message_id

      const inputs2 = {
        identitySecret,
        userMessageLimit,
        messageId: messageId2,
        pathElements: merkleProof.siblings,
        identityPathIndex: merkleProof.pathIndices,
        x: x2,
        externalNullifier,
        selectorUsed: selectorUsed2,
      };

      const witness2: bigint[] = await circuit.calculateWitness(inputs2, true);
      const y2_slot0 = await getSignalArray(circuit, witness2, "y", 0);

      // Nullifiers should match (same identity, epoch, message_id)
      const nullifier1 = await getSignalArray(
        circuit,
        witness1,
        "nullifier",
        0,
      );
      const nullifier2 = await getSignalArray(
        circuit,
        witness2,
        "nullifier",
        0,
      );
      assert.equal(
        nullifier1,
        nullifier2,
        "Nullifiers should match for same message_id",
      );

      // Recover secret
      const ffjavascript = require("ffjavascript");
      const SNARK_FIELD_SIZE = BigInt(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
      );
      const F = new ffjavascript.ZqField(SNARK_FIELD_SIZE);

      const a1 = F.div(F.sub(y1_slot0, y2_slot0), F.sub(x1, x2));
      const recoveredSecret = F.sub(y1_slot0, F.mul(a1, x1));

      assert.equal(
        recoveredSecret,
        identitySecret,
        "Should recover identity secret from double-signaling",
      );
    });
  });

  describe("Performance Tests", () => {
    it("Should measure zkSNARK proof generation time with 1 message burn", async function () {
      this.timeout(600000);

      // Setup test inputs
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 0, 0, 0]; // 1 active slot

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
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
        selectorUsed,
      };

      const numRuns = 20;
      const witnessTimes: number[] = [];
      const proofTimes: number[] = [];

      for (let i = 0; i < numRuns; i++) {
        // Measure witness generation time
        const witnessStart = performance.now();
        const _ = await circuit.calculateWitness(inputs, true);
        const witnessTime = performance.now() - witnessStart;
        witnessTimes.push(witnessTime);

        // Measure full proof generation time (includes witness + proof)
        const proofStart = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          inputs,
          path.join(__dirname, "..", "build", "rln_multi_js", "rln_multi.wasm"),
          path.join(__dirname, "..", "zkeyFiles", "rln_multi", "final.zkey"),
        );
        const proofTime = performance.now() - proofStart;
        proofTimes.push(proofTime);

        // Verify the proof is valid on first run
        if (i === 0) {
          const vKey = require(
            path.join(
              __dirname,
              "..",
              "zkeyFiles",
              "rln_multi",
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

      // Calculate statistics
      const avgWitnessTime =
        witnessTimes.reduce((a, b) => a + b, 0) / witnessTimes.length;
      const avgProofTime =
        proofTimes.reduce((a, b) => a + b, 0) / proofTimes.length;
      const minWitnessTime = Math.min(...witnessTimes);
      const maxWitnessTime = Math.max(...witnessTimes);
      const minProofTime = Math.min(...proofTimes);
      const maxProofTime = Math.max(...proofTimes);

      // Log timing results
      console.log(`\n      === 1 Message Burn - Witness Generation Times ===`);
      console.log(`      - Average: ${avgWitnessTime.toFixed(2)}ms`);
      console.log(`      - Min: ${minWitnessTime.toFixed(2)}ms`);
      console.log(`      - Max: ${maxWitnessTime.toFixed(2)}ms`);
      console.log(
        `\n      === 1 Message Burn - Full Proof Generation Times ===`,
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

    it("Should measure zkSNARK proof generation time with 2 message burns", async function () {
      this.timeout(600000);

      // Setup test inputs
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 0, 0]; // 2 active slots

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(1), BigInt(0), BigInt(0)];
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
        selectorUsed,
      };

      const numRuns = 20;
      const witnessTimes: number[] = [];
      const proofTimes: number[] = [];

      for (let i = 0; i < numRuns; i++) {
        // Measure witness generation time
        const witnessStart = performance.now();
        const _ = await circuit.calculateWitness(inputs, true);
        const witnessTime = performance.now() - witnessStart;
        witnessTimes.push(witnessTime);

        // Measure full proof generation time (includes witness + proof)
        const proofStart = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          inputs,
          path.join(__dirname, "..", "build", "rln_multi_js", "rln_multi.wasm"),
          path.join(__dirname, "..", "zkeyFiles", "rln_multi", "final.zkey"),
        );
        const proofTime = performance.now() - proofStart;
        proofTimes.push(proofTime);

        // Verify the proof is valid on first run
        if (i === 0) {
          const vKey = require(
            path.join(
              __dirname,
              "..",
              "zkeyFiles",
              "rln_multi",
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

      // Calculate statistics
      const avgWitnessTime =
        witnessTimes.reduce((a, b) => a + b, 0) / witnessTimes.length;
      const avgProofTime =
        proofTimes.reduce((a, b) => a + b, 0) / proofTimes.length;
      const minWitnessTime = Math.min(...witnessTimes);
      const maxWitnessTime = Math.max(...witnessTimes);
      const minProofTime = Math.min(...proofTimes);
      const maxProofTime = Math.max(...proofTimes);

      // Log timing results
      console.log(`\n      === 2 Message Burns - Witness Generation Times ===`);
      console.log(`      - Average: ${avgWitnessTime.toFixed(2)}ms`);
      console.log(`      - Min: ${minWitnessTime.toFixed(2)}ms`);
      console.log(`      - Max: ${maxWitnessTime.toFixed(2)}ms`);
      console.log(
        `\n      === 2 Message Burns - Full Proof Generation Times ===`,
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

    it("Should measure zkSNARK proof generation time with 4 message burns", async function () {
      this.timeout(600000);

      // Setup test inputs
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 1, 1, 1]; // All 4 slots active

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(1), BigInt(2), BigInt(3)];
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
        selectorUsed,
      };

      const numRuns = 20;
      const witnessTimes: number[] = [];
      const proofTimes: number[] = [];

      for (let i = 0; i < numRuns; i++) {
        // Measure witness generation time
        const witnessStart = performance.now();
        const _ = await circuit.calculateWitness(inputs, true);
        const witnessTime = performance.now() - witnessStart;
        witnessTimes.push(witnessTime);

        // Measure full proof generation time (includes witness + proof)
        const proofStart = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          inputs,
          path.join(__dirname, "..", "build", "rln_multi_js", "rln_multi.wasm"),
          path.join(__dirname, "..", "zkeyFiles", "rln_multi", "final.zkey"),
        );
        const proofTime = performance.now() - proofStart;
        proofTimes.push(proofTime);

        // Verify the proof is valid on first run
        if (i === 0) {
          const vKey = require(
            path.join(
              __dirname,
              "..",
              "zkeyFiles",
              "rln_multi",
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

      // Calculate statistics
      const avgWitnessTime =
        witnessTimes.reduce((a, b) => a + b, 0) / witnessTimes.length;
      const avgProofTime =
        proofTimes.reduce((a, b) => a + b, 0) / proofTimes.length;
      const minWitnessTime = Math.min(...witnessTimes);
      const maxWitnessTime = Math.max(...witnessTimes);
      const minProofTime = Math.min(...proofTimes);
      const maxProofTime = Math.max(...proofTimes);

      // Log timing results
      console.log(`\n      === 4 Message Burns - Witness Generation Times ===`);
      console.log(`      - Average: ${avgWitnessTime.toFixed(2)}ms`);
      console.log(`      - Min: ${minWitnessTime.toFixed(2)}ms`);
      console.log(`      - Max: ${maxWitnessTime.toFixed(2)}ms`);
      console.log(
        `\n      === 4 Message Burns - Full Proof Generation Times ===`,
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

    it("Should measure zkSNARK proof generation time with non-contiguous burns [1,0,1,1]", async function () {
      this.timeout(600000);

      // Setup test inputs with non-contiguous selector pattern
      const x = genFieldElement();
      const externalNullifier = genFieldElement();
      const selectorUsed = [1, 0, 1, 1]; // Non-contiguous: 3 active, 1 NULL

      const identitySecret = genFieldElement();
      const userMessageLimit = BigInt(10);
      const messageId = [BigInt(0), BigInt(1), BigInt(2), BigInt(3)];
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
        selectorUsed,
      };

      const numRuns = 20;
      const witnessTimes: number[] = [];
      const proofTimes: number[] = [];

      for (let i = 0; i < numRuns; i++) {
        // Measure witness generation time
        const witnessStart = performance.now();
        const _ = await circuit.calculateWitness(inputs, true);
        const witnessTime = performance.now() - witnessStart;
        witnessTimes.push(witnessTime);

        // Measure full proof generation time (includes witness + proof)
        const proofStart = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          inputs,
          path.join(__dirname, "..", "build", "rln_multi_js", "rln_multi.wasm"),
          path.join(__dirname, "..", "zkeyFiles", "rln_multi", "final.zkey"),
        );
        const proofTime = performance.now() - proofStart;
        proofTimes.push(proofTime);

        // Verify the proof is valid on first run
        if (i === 0) {
          const vKey = require(
            path.join(
              __dirname,
              "..",
              "zkeyFiles",
              "rln_multi",
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

      // Calculate statistics
      const avgWitnessTime =
        witnessTimes.reduce((a, b) => a + b, 0) / witnessTimes.length;
      const avgProofTime =
        proofTimes.reduce((a, b) => a + b, 0) / proofTimes.length;
      const minWitnessTime = Math.min(...witnessTimes);
      const maxWitnessTime = Math.max(...witnessTimes);
      const minProofTime = Math.min(...proofTimes);
      const maxProofTime = Math.max(...proofTimes);

      // Log timing results
      console.log(
        `\n      === Non-contiguous [1,0,1,1] - Witness Generation Times ===`,
      );
      console.log(`      - Average: ${avgWitnessTime.toFixed(2)}ms`);
      console.log(`      - Min: ${minWitnessTime.toFixed(2)}ms`);
      console.log(`      - Max: ${maxWitnessTime.toFixed(2)}ms`);
      console.log(
        `\n      === Non-contiguous [1,0,1,1] - Full Proof Generation Times ===`,
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
