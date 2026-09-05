import * as path from "path";
import assert from "assert";
const tester = require("circom_tester").wasm;
const snarkjs = require("snarkjs");
import { getSignal } from "./utils";

const circuitPath = path.join(
  __dirname,
  "..",
  "circuits",
  "rln_poseidon2_single.circom",
);

// ffjavascript has no types so leave circuit with untyped
type CircuitT = any;

// Witness fixture computed with zerokit's Poseidon2 implementation (POSEIDON2_ROUND_PARAMS,
// HorizenLabs constant set): identitySecret = 1, userMessageLimit = 100, messageId = 1,
// x = 2, externalNullifier = 3, member at index 0 of a depth-20 tree with zero default
// leaves (pathElements = all-zero subtree roots).
const pathElements = [
  "0",
  "21177166670744647784289648293577786481357446166129397094207318338605633126018",
  "11412255550844107711536575504528929861093703399407220327184557298158187213474",
  "8478109936589916886180206575753849450681587490297488674358400223694190389931",
  "1881841127942451416534579038641753055878888726728184728044096839990169683445",
  "18942029160367954044020383033633711177299282967277063189097411472682390749320",
  "14446284585321005330629653150178659104499275904832183584861698613112830445903",
  "18793378517416573448074833754494972700226140838483062238361810378030364016863",
  "7253949174089745481378841434617749257222822664731503456628965709538919130187",
  "137441956371504345945695021264026605873899146151003318692553571288350186563",
  "146353049808418340311941573107319324132958995680137380387512715637140265777",
  "14066033167951234205633528235511417504459040931616268600752881070303746612037",
  "3967331992550942615899962652954021681468913675976662251855209270543455613399",
  "15362108721764047884208462829928787751228159573476615263857687297308054603808",
  "9411880059472358804127278460535485607948923617103750705977259713086951828216",
  "12160551399066502022875882886634895701896385542360456440834335648900725212947",
  "5250350326572541944090853983389034270821619580142229914337886536788121418070",
  "13227224870768820194218913695054135460311431221319545823205139712557852944149",
  "3279267570938399892271672241912758823175035324898514733329518044202204328938",
  "12786313475252470237986081484895078756396559394771267230765049138183248760842",
];

const expectedRoot =
  12682954411600017268285369100721799648035063185341666973076012199806890875041n;
// Same tree with the member at index 3 instead: siblings stay the default subtree
// roots, but identityPathIndex = [1, 1, 0, ...] flips the hash order on two levels.
const expectedRootIndex3 =
  14522171345704239266196933356401879379577552531820525723026580733252232694251n;
const expectedY =
  20938025628206935079806095292978281978881206897950975409588596090736365442405n;
const expectedNullifier =
  2719672741528710067383228142226305697018339266864014447403577182501773461561n;

describe("Test rln_poseidon2_single.circom", function () {
  let circuit: CircuitT;

  this.timeout(60000);

  before(async function () {
    circuit = await tester(circuitPath);
  });

  it("Should generate witness with outputs matching the zerokit Poseidon2 fixture", async () => {
    const witness = await circuit.calculateWitness(
      {
        identitySecret: 1n,
        userMessageLimit: 100n,
        messageId: 1n,
        pathElements,
        identityPathIndex: new Array(20).fill(0),
        x: 2n,
        externalNullifier: 3n,
      },
      true,
    );
    await circuit.checkConstraints(witness);

    assert.equal(await getSignal(circuit, witness, "root"), expectedRoot);
    assert.equal(await getSignal(circuit, witness, "y"), expectedY);
    assert.equal(
      await getSignal(circuit, witness, "nullifier"),
      expectedNullifier,
    );
  });

  it("Should compute the root for a member at index 3 (path index bits set)", async () => {
    const witness = await circuit.calculateWitness(
      {
        identitySecret: 1n,
        userMessageLimit: 100n,
        messageId: 1n,
        pathElements,
        identityPathIndex: [1, 1, ...new Array(18).fill(0)],
        x: 2n,
        externalNullifier: 3n,
      },
      true,
    );
    await circuit.checkConstraints(witness);

    assert.equal(await getSignal(circuit, witness, "root"), expectedRootIndex3);
    assert.equal(await getSignal(circuit, witness, "y"), expectedY);
    assert.equal(
      await getSignal(circuit, witness, "nullifier"),
      expectedNullifier,
    );
  });

  it("Should fail to generate witness if messageId is not in range [0, userMessageLimit-1]", async () => {
    for (const invalidMessageId of [100n, 101n]) {
      await assert.rejects(async () => {
        await circuit.calculateWitness(
          {
            identitySecret: 1n,
            userMessageLimit: 100n,
            messageId: invalidMessageId,
            pathElements,
            identityPathIndex: new Array(20).fill(0),
            x: 2n,
            externalNullifier: 3n,
          },
          true,
        );
      }, /Error: Assert Failed/);
    }
  });

  describe("Performance Tests", () => {
    it("Should measure zkSNARK proof generation time", async function () {
      this.timeout(600000);

      const inputs = {
        identitySecret: 1n,
        userMessageLimit: 100n,
        messageId: 1n,
        pathElements,
        identityPathIndex: new Array(20).fill(0),
        x: 2n,
        externalNullifier: 3n,
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
            "rln_poseidon2_single_js",
            "rln_poseidon2_single.wasm",
          ),
          path.join(
            __dirname,
            "..",
            "zkeyFiles",
            "rln_poseidon2_single",
            "final.zkey",
          ),
        );
        const proofTime = performance.now() - proofStart;
        proofTimes.push(proofTime);

        if (i === 0) {
          const vKey = require(
            path.join(
              __dirname,
              "..",
              "zkeyFiles",
              "rln_poseidon2_single",
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
