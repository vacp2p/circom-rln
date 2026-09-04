import * as path from "path";
import assert from "assert";
const tester = require("circom_tester").wasm;
import poseidon from "poseidon-lite";
import { genFieldElement, getSignal } from "./utils";

// Path to the withdraw circuit file
const circuitPath = path.join(__dirname, "..", "circuits", "withdraw.circom");

// Circuit type - circom_tester has no TypeScript types
type CircuitT = any;

/**
 * The withdraw circuit is separate from RLN and allows users to prove
 * knowledge of their identitySecret and link it to a withdrawal address.
 * This is NOT affected by the multi-burn RLN changes.
 */
describe("Test withdraw.circom", function () {
  let circuit: CircuitT;

  // Increase timeout for circuit compilation
  this.timeout(30000);

  before(async function () {
    // Compile the withdraw circuit
    circuit = await tester(circuitPath);
  });

  it("Should generate witness with correct outputs", async () => {
    // Private input: the secret that generates the identity commitment
    const identitySecret = genFieldElement();
    // Public input: the destination address for withdrawal
    const address = genFieldElement();

    // Generate proof - circuit verifies knowledge of identitySecret
    const witness: bigint[] = await circuit.calculateWitness(
      { identitySecret, address },
      true,
    );
    // Verify all constraints are satisfied
    await circuit.checkConstraints(witness);

    // Expected output: identityCommitment = H(identitySecret)
    const expectedIdentityCommitment = poseidon([identitySecret]);
    const outputIdentityCommitment = await getSignal(
      circuit,
      witness,
      "identityCommitment",
    );
    // Verify the output matches expected value
    assert.equal(outputIdentityCommitment, expectedIdentityCommitment);
  });
});
