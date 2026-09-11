import * as path from "path";
import assert from "assert";
const tester = require("circom_tester").wasm;
const snarkjs = require("snarkjs");
import { getSignal, getSignalArray } from "./utils";

const circuitPath = path.join(
  __dirname,
  "..",
  "circuits",
  "rln_poseidon2_multi.circom",
);

// ffjavascript has no types so leave circuit with untyped
type CircuitT = any;

// Witness fixture computed with zerokit's Poseidon2 implementation (POSEIDON2_ROUND_PARAMS,
// HorizenLabs constant set): identitySecret = 1, userMessageLimit = 100,
// messageId = [1, 2, 3, 4], selectorUsed = [1, 1, 1, 1], x = 2, externalNullifier = 3,
// member at index 0 of a depth-20 tree with zero default leaves.
const pathElements = [
  "0",
  "21177166670744647784289648293577786481357446166129397094207318338605633126018",
  "2249539345451497493144246897850968253428736573412734137389950829236304858943",
  "13605996452423506159752435765799807887247216726015922647433308845728394066830",
  "17487822691240867617096179725111865601507112285934637721081926760965581033519",
  "6233474108348988536350471001106263097262010555268340678732850035028293900952",
  "12875864858339814209075691792066496801391601835572983226187177269087704327441",
  "6304868519332237690944709822164188188492802434827191059031961232265578437416",
  "15329579260036669902873875390176560324604230862589750666045935825705594737003",
  "4100318408121872562908141494497941696019218702469920673997582189444506571297",
  "676407046767664456447874482346419544590708035436180759461094970062200912577",
  "203318508436347851580652900329871456449620984432953185072016095389432067634",
  "17644659363314128538692630458945548624105957012302696455792355601725353684879",
  "15996120611567234372541895833071980790615053197269415759815367945854579659094",
  "11693796767877886001256512404837335287030569457175951780813431004314962772866",
  "3023824634441834936684501913698981473826233489917400996775164867053478956318",
  "718361993823459938254959425546557518877522829360141911801954600458939833207",
  "14852665972303905513407493951253983613035190300952722829946137346054046733269",
  "928313627215347131258669007409451479777550474912168717926444481366418328615",
  "596212348862457079982631474604232593003744975599797860590285172546813106073",
];

const expectedRoot =
  4142175899637021305357119656566318852960392972236309645700385516802342708626n;
const expectedY = [
  17393225925671802892208879624405038177919528778156662811814655144758852714406n,
  20690314025155261036219551155536628155047296031054170243759252593315826150296n,
  718075937201548882589528897794153725255670338879281324236617948719373122830n,
  17162772475236700295987850479696710517089947031342130833073420090123996575244n,
];
const expectedNullifier = [
  9777659611843035168661054209408528542091258941468977849206766656894018210534n,
  5633588330186841229134113797765519913377140178510833959442762062902362964219n,
  13034680569490649653356456238179000721274708161196108304015794555760853326243n,
  11213603355948080400879835882794585611399841491994979170543039005833199926194n,
];

describe("Test rln_poseidon2_multi.circom", function () {
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
        messageId: [1n, 2n, 3n, 4n],
        pathElements,
        identityPathIndex: new Array(20).fill(0),
        x: 2n,
        externalNullifier: 3n,
        selectorUsed: [1, 1, 1, 1],
      },
      true,
    );
    await circuit.checkConstraints(witness);

    assert.equal(await getSignal(circuit, witness, "root"), expectedRoot);
    for (let i = 0; i < 4; i++) {
      assert.equal(
        await getSignalArray(circuit, witness, "y", i),
        expectedY[i],
      );
      assert.equal(
        await getSignalArray(circuit, witness, "nullifier", i),
        expectedNullifier[i],
      );
    }
  });

  // The selector/masking checks are copied circuit logic, so they get their own coverage
  // (mirroring the rln_multi suite). The root is a circuit output, not validated
  // in-circuit, so the fixture path elements serve every case below.
  const fixtureInputs = (
    messageId: bigint[],
    selectorUsed: number[],
  ): Record<string, unknown> => ({
    identitySecret: 1n,
    userMessageLimit: 100n,
    messageId,
    pathElements,
    identityPathIndex: new Array(20).fill(0),
    x: 2n,
    externalNullifier: 3n,
    selectorUsed,
  });

  it("Should fail if an active messageId is not in range [0, userMessageLimit-1]", async () => {
    await assert.rejects(async () => {
      await circuit.calculateWitness(
        fixtureInputs([100n, 0n, 0n, 0n], [1, 0, 0, 0]),
        true,
      );
    }, /Error: Assert Failed/);
  });

  it("Should fail if no selector is active", async () => {
    await assert.rejects(async () => {
      await circuit.calculateWitness(
        fixtureInputs([1n, 2n, 3n, 4n], [0, 0, 0, 0]),
        true,
      );
    }, /Error: Assert Failed/);
  });

  it("Should fail if two active slots share a messageId", async () => {
    await assert.rejects(async () => {
      await circuit.calculateWitness(
        fixtureInputs([1n, 1n, 0n, 0n], [1, 1, 0, 0]),
        true,
      );
    }, /Error: Assert Failed/);
  });

  it("Should fail if selectorUsed contains a non-binary value", async () => {
    await assert.rejects(async () => {
      await circuit.calculateWitness(
        fixtureInputs([1n, 2n, 3n, 4n], [1, 2, 0, 0]),
        true,
      );
    }, /Error: Assert Failed/);
  });

  it("Should burn non-contiguous slots [1,0,1,0] and mask the interleaved inactive ones", async () => {
    // Active slots 0 and 2 carry the fixture messageIds 1 and 3, so their outputs must
    // equal the fixture values while the interleaved inactive slots mask to zero.
    const witness = await circuit.calculateWitness(
      fixtureInputs([1n, 0n, 3n, 0n], [1, 0, 1, 0]),
      true,
    );
    await circuit.checkConstraints(witness);

    assert.equal(await getSignal(circuit, witness, "root"), expectedRoot);
    for (const i of [0, 2]) {
      assert.equal(await getSignalArray(circuit, witness, "y", i), expectedY[i]);
      assert.equal(
        await getSignalArray(circuit, witness, "nullifier", i),
        expectedNullifier[i],
      );
    }
    for (const i of [1, 3]) {
      assert.equal(await getSignalArray(circuit, witness, "y", i), 0n);
      assert.equal(await getSignalArray(circuit, witness, "nullifier", i), 0n);
    }
  });

  it("Should skip validation of inactive messageIds and mask their outputs", async () => {
    // Slots 2 and 3 carry out-of-range messageIds but are inactive: the witness must
    // still generate, the active slots must produce the fixture outputs (messageIds 1
    // and 2), and the inactive outputs must be masked to zero.
    const witness = await circuit.calculateWitness(
      fixtureInputs([1n, 2n, 999n, 9999n], [1, 1, 0, 0]),
      true,
    );
    await circuit.checkConstraints(witness);

    assert.equal(await getSignal(circuit, witness, "root"), expectedRoot);
    for (let i = 0; i < 2; i++) {
      assert.equal(await getSignalArray(circuit, witness, "y", i), expectedY[i]);
      assert.equal(
        await getSignalArray(circuit, witness, "nullifier", i),
        expectedNullifier[i],
      );
    }
    for (let i = 2; i < 4; i++) {
      assert.equal(await getSignalArray(circuit, witness, "y", i), 0n);
      assert.equal(await getSignalArray(circuit, witness, "nullifier", i), 0n);
    }
  });

  describe("Performance Tests", () => {
    it("Should measure zkSNARK proof generation time with 4 message burns", async function () {
      this.timeout(600000);

      const inputs = {
        identitySecret: 1n,
        userMessageLimit: 100n,
        messageId: [1n, 2n, 3n, 4n],
        pathElements,
        identityPathIndex: new Array(20).fill(0),
        x: 2n,
        externalNullifier: 3n,
        selectorUsed: [1, 1, 1, 1],
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
            "rln_poseidon2_multi_js",
            "rln_poseidon2_multi.wasm",
          ),
          path.join(
            __dirname,
            "..",
            "zkeyFiles",
            "rln_poseidon2_multi",
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
              "rln_poseidon2_multi",
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
  });
});
