import * as path from "path";
import assert from "assert";
const tester = require("circom_tester").wasm;
import { getSignal } from "./utils";

// ffjavascript has no types so leave circuit with untyped
type CircuitT = any;

// One-shot Poseidon2 reference vectors (state [0, inputs..] -> state[0], HorizenLabs constant
// set). Sources: arity 2 generated with jf-poseidon2 (constants adapted from HorizenLabs;
// the (1, 2) case equals state[0] of the HorizenLabs known-answer test for permute([0,1,2]));
// arities 1 and 3 evaluated with the HorizenLabs generation script poseidon2_rust_params.sage
// (its evaluator computes poseidon2([0..t-1]), exactly these one-shot states). The same
// values are pinned by the zerokit Rust tests.
const vectors: { arity: number; inputs: bigint[]; expected: bigint }[] = [
  {
    arity: 1,
    inputs: [1n],
    expected:
      13120422956170837922441672802975889424559262309139960702680326932494325745547n,
  },
  {
    arity: 2,
    inputs: [1n, 2n],
    expected:
      5297208644449048816064511434384511824916970985131888684874823260532015509555n,
  },
  {
    arity: 2,
    inputs: [0n, 0n],
    expected:
      21177166670744647784289648293577786481357446166129397094207318338605633126018n,
  },
  {
    arity: 2,
    inputs: [1n, 1n],
    expected:
      6244710744212918225541182980747176473975170934996674195251555650524813642975n,
  },
  {
    arity: 2,
    inputs: [3n, 4n],
    expected:
      17876044324362893302450557747690880223450114576345709251654422037230086863116n,
  },
  {
    arity: 2,
    inputs: [123456789n, 987654321n],
    expected:
      7948274567296627520074104938313042724061892674643171639138083556112484336070n,
  },
  {
    arity: 3,
    inputs: [1n, 2n, 3n],
    expected:
      786823568102245344938517132468097745676732687098822989626730198331658606391n,
  },
];

// Field-boundary vectors (every input = p - 1), computed with zerokit's Poseidon2
// implementation.
const P_MINUS_1 =
  21888242871839275222246405745257275088548364400416034343698204186575808495616n;
const boundaryVectors: { arity: number; inputs: bigint[]; expected: bigint }[] =
  [
    {
      arity: 1,
      inputs: [P_MINUS_1],
      expected:
        9849028002773229048108099498985127427784903672147957416419205112067949414072n,
    },
    {
      arity: 2,
      inputs: [P_MINUS_1, P_MINUS_1],
      expected:
        3825721696347434793895301427783270724842815170837942670345447586004010071815n,
    },
    {
      arity: 3,
      inputs: [P_MINUS_1, P_MINUS_1, P_MINUS_1],
      expected:
        177837355444519217241630555404229869324135948559180898586828936756759764048n,
    },
  ];

describe("Test poseidon2.circom", function () {
  this.timeout(60000);

  const circuits: { [arity: number]: CircuitT } = {};

  before(async function () {
    for (const arity of [1, 2, 3]) {
      const circuitPath = path.join(
        __dirname,
        "circuits",
        `poseidon2_arity${arity}.circom`,
      );
      circuits[arity] = await tester(circuitPath);
    }
  });

  it("Should match the Poseidon2 reference vectors for every arity", async () => {
    for (const { arity, inputs, expected } of vectors) {
      const circuit = circuits[arity];
      const witness = await circuit.calculateWitness({ inputs }, true);
      await circuit.checkConstraints(witness);
      const out = await getSignal(circuit, witness, "out");
      assert.equal(
        out,
        expected,
        `Poseidon2 mismatch for arity ${arity} inputs [${inputs}]`,
      );
    }
  });

  it("Should match the native Poseidon2 at the field boundary (p - 1 inputs)", async () => {
    for (const { arity, inputs, expected } of boundaryVectors) {
      const circuit = circuits[arity];
      const witness = await circuit.calculateWitness({ inputs }, true);
      await circuit.checkConstraints(witness);
      const out = await getSignal(circuit, witness, "out");
      assert.equal(
        out,
        expected,
        `Poseidon2 mismatch for arity ${arity} at the field boundary`,
      );
    }
  });
});
