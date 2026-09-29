pragma circom 2.1.0;

include "./utils.circom";
include "./poseidon2.circom";

// The RLN circuit of rln_single.circom with every hash swapped to Poseidon2; the range check,
// the Shamir share computation and the public signal layout are unchanged.
template RLNPoseidon2(DEPTH, LIMIT_BIT_SIZE) {
    // Private signals
    signal input identitySecret;
    signal input userMessageLimit;
    signal input messageId;
    signal input pathElements[DEPTH];
    signal input identityPathIndex[DEPTH];

    // Public signals
    signal input x;
    signal input externalNullifier;

    // Outputs
    signal output y;
    signal output root;
    signal output nullifier;

    signal identityCommitment <== Poseidon2(1)([identitySecret]);
    signal rateCommitment <== Poseidon2(2)([identityCommitment, userMessageLimit]);

    // Membership check
    root <== MerkleTreeInclusionProofPoseidon2(DEPTH)(rateCommitment, identityPathIndex, pathElements);

    // messageId range check
    RangeCheck(LIMIT_BIT_SIZE)(messageId, userMessageLimit);

    // SSS share calculations
    signal a1 <== Poseidon2(3)([identitySecret, externalNullifier, messageId]);
    y <== identitySecret + a1 * x;

    // nullifier calculation
    nullifier <== Poseidon2(1)([a1]);
}

component main { public [x, externalNullifier] } = RLNPoseidon2(20, 16);
