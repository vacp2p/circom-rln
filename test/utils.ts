// Merkle tree implementation from zk-kit library
import { IncrementalMerkleTree } from "@zk-kit/incremental-merkle-tree";
// Poseidon hash function optimized for zero-knowledge circuits
import poseidon from "poseidon-lite";
// Field arithmetic library for BN254 curve (no TypeScript types available)
const ffjavascript = require("ffjavascript");

// Import Merkle tree configuration constants
import { MERKLE_TREE_DEPTH, MERKLE_TREE_ZERO_VALUE } from "./configs";

// Circuit type - circom_tester has no TypeScript types
type CircuitT = any;

// BN254 scalar field size - the order of the finite field used in our zk-SNARKs
const SNARK_FIELD_SIZE = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);
// Field arithmetic helper for performing modular operations
const F = new ffjavascript.ZqField(SNARK_FIELD_SIZE);

/**
 * Generate a random field element in the BN254 scalar field
 * Used for creating random test inputs like identitySecret, x, externalNullifier
 */
export function genFieldElement() {
  return F.random();
}

/**
 * Generate a Merkle proof for a specific leaf
 * Creates a binary Merkle tree with Poseidon hash and generates inclusion proof
 *
 * @param elements - Array of leaf values to insert into the tree
 * @param leafIndex - Index of the leaf to generate proof for (0-based)
 * @returns Merkle proof object containing root, siblings (sibling hashes at each level), and pathIndices
 */
export function genMerkleProof(elements: BigInt[], leafIndex: number) {
  // Create a binary (arity=2) Merkle tree using Poseidon hash
  const tree = new IncrementalMerkleTree(
    poseidon,
    MERKLE_TREE_DEPTH,
    MERKLE_TREE_ZERO_VALUE,
    2,
  );
  // Insert all elements into the tree
  for (let i = 0; i < elements.length; i++) {
    tree.insert(elements[i]);
  }
  // Generate proof for the specified leaf
  const merkleProof = tree.createProof(leafIndex);
  // Extract first element from each sibling pair (library returns arrays)
  merkleProof.siblings = merkleProof.siblings.map((s) => s[0]);
  return merkleProof;
}

/**
 * Calculate expected circuit outputs for single message burn (original RLN behavior)
 * Replicates the circuit logic in JavaScript for testing and verification
 *
 * @param identitySecret - User's secret identity
 * @param x - Random challenge for Shamir's Secret Sharing
 * @param externalNullifier - Epoch/context identifier (e.g., timestamp, app ID)
 * @param messageId - Specific message ID being burned (0 to userMessageLimit-1)
 * @returns Object with {y, nullifier} matching circuit outputs
 */
export function calculateOutput(
  identitySecret: bigint,
  x: bigint,
  externalNullifier: bigint,
  messageId: bigint,
) {
  // Calculate a1: secret polynomial coefficient for this specific (epoch, messageId)
  // signal a1 <== Poseidon(3)([identitySecret, externalNullifier, messageId]);
  const a1 = poseidon([identitySecret, externalNullifier, messageId]);
  // Calculate SSS share: y = secret + coefficient * challenge
  // y <== identitySecret + a1 * x;
  const y = F.normalize(identitySecret + a1 * x);
  // Calculate nullifier to detect double-signaling
  const nullifier = poseidon([a1]);
  return { y, nullifier };
}

/**
 * Calculate expected circuit outputs for multi-burn scenario (RFC compliant)
 * Computes outputs with selector masking - unused slots produce explicit zero outputs
 *
 * @param identitySecret - User's secret identity
 * @param x - Random challenge for Shamir's Secret Sharing
 * @param externalNullifier - Epoch/context identifier
 * @param messageIds - Array of message IDs (length should be maxOut)
 * @param selectorUsed - Bit array indicating which slots are active (1) or NULL (0)
 * @param maxOut - Total number of slots (default: 4)
 * @returns Object with {y: bigint[], nullifier: bigint[]} arrays of length maxOut
 *          Unused slots (selectorUsed[i]=0) will have y[i]=0 and nullifier[i]=0
 */
export function calculateMultiOutput(
  identitySecret: bigint,
  x: bigint,
  externalNullifier: bigint,
  messageIds: bigint[],
  selectorUsed: number[],
  maxOut: number = 4,
) {
  const y: bigint[] = [];
  const nullifier: bigint[] = [];

  // Compute for all slots with RFC-compliant masking
  for (let i = 0; i < maxOut; i++) {
    // Calculate a1 for messageIds[i]
    const a1 = poseidon([identitySecret, externalNullifier, messageIds[i]]);
    // Calculate unmasked SSS share
    const y_unmasked = F.normalize(identitySecret + a1 * x);
    // Calculate unmasked nullifier
    const nullifier_unmasked = poseidon([a1]);

    // Apply selector masking (RFC compliant)
    // When selectorUsed[i] = 1: use unmasked values (active slot)
    // When selectorUsed[i] = 0: output zero (NULL output)
    const y_i = selectorUsed[i] === 1 ? y_unmasked : BigInt(0);
    const nullifier_i = selectorUsed[i] === 1 ? nullifier_unmasked : BigInt(0);

    y.push(y_i);
    nullifier.push(nullifier_i);
  }

  return { y, nullifier };
}

/**
 * Extract a single output signal value from the witness
 * The witness is a flat array containing all signal values from the circuit execution
 *
 * @param circuit - The compiled circuit object
 * @param witness - The computed witness array (contains all intermediate and output signal values)
 * @param name - Signal name without "main." prefix (e.g., "root", "y", "nullifier")
 * @returns The signal's value as a bigint
 */
export async function getSignal(
  circuit: CircuitT,
  witness: bigint[],
  name: string,
) {
  const prefix = "main";
  // E.g. the full name of the signal "root" is "main.root"
  // You can look up the signal names using `circuit.getDecoratedOutput(witness))`
  const signalFullName = `${prefix}.${name}`;
  // Load symbol table mapping signal names to witness indices
  await circuit.loadSymbols();
  // symbols[n] = { labelIdx: 1, varIdx: 1, componentIdx: 142 },
  const signalMeta = circuit.symbols[signalFullName];
  // Assigned value of the signal is located in the `varIdx`th position
  // of the witness array
  const indexInWitness = signalMeta.varIdx;
  return BigInt(witness[indexInWitness]);
}

/**
 * Extract a specific array element from circuit outputs
 * Used for multi-output signals like y[0], y[1], nullifier[0], etc.
 *
 * @param circuit - The compiled circuit object
 * @param witness - The computed witness array
 * @param name - Base array name (e.g., "y", "nullifier")
 * @param index - Array index to retrieve (0-based)
 * @returns The signal's value at the specified index
 */
export async function getSignalArray(
  circuit: CircuitT,
  witness: bigint[],
  name: string,
  index: number,
) {
  // Construct array element name (e.g., "y[2]" for name="y", index=2)
  const signalName = `${name}[${index}]`;
  return await getSignal(circuit, witness, signalName);
}
