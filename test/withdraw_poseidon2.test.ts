import * as path from "path";
import assert from "assert";
const tester = require("circom_tester").wasm;
import { genFieldElement, getSignal } from "./utils";

// Path to the Poseidon2 withdraw circuit file
const circuitPath = path.join(
  __dirname,
  "..",
  "circuits",
  "withdraw_poseidon2.circom",
);

// Circuit type - circom_tester has no TypeScript types
type CircuitT = any;

// Poseidon2(1)([1]) in the compression layout of the Logos ecosystem, generated with the
// Logos reference implementation https://github.com/logos-storage/rust-poseidon-bn254-pure
// and pinned by the zerokit Rust tests (same vector as in poseidon2.test.ts).
const identitySecret = 1n;
const expectedIdentityCommitment =
  4220003009428892662276135118827607177546592752204629865937061707152838643028n;

/**
 * The Poseidon2 withdraw circuit mirrors withdraw.circom with the identity commitment
 * hash swapped to Poseidon2, so the expected output comes from a fixed reference vector
 * instead of a JavaScript hash implementation.
 */
describe("Test withdraw_poseidon2.circom", function () {
  let circuit: CircuitT;

  // Increase timeout for circuit compilation
  this.timeout(30000);

  before(async function () {
    // Compile the Poseidon2 withdraw circuit
    circuit = await tester(circuitPath);
  });

  it("Should generate witness with correct outputs", async () => {
    // Public input: the destination address for withdrawal
    const address = genFieldElement();

    // Generate proof - circuit verifies knowledge of identitySecret
    const witness: bigint[] = await circuit.calculateWitness(
      { identitySecret, address },
      true,
    );
    // Verify all constraints are satisfied
    await circuit.checkConstraints(witness);

    // Expected output: identityCommitment = Poseidon2(identitySecret)
    const outputIdentityCommitment = await getSignal(
      circuit,
      witness,
      "identityCommitment",
    );
    // Verify the output matches the reference vector
    assert.equal(outputIdentityCommitment, expectedIdentityCommitment);
  });
});
