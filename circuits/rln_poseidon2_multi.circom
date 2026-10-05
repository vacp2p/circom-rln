pragma circom 2.1.0;

include "./utils.circom";
include "./poseidon2.circom";

// The RLN circuit of rln_multi.circom with every hash swapped to Poseidon2; the selector
// logic, the range checks, the Shamir share computation and the public signal layout are
// unchanged.
template RLNPoseidon2Multi(DEPTH, LIMIT_BIT_SIZE, MAX_OUT) {
    // Private signals
    signal input identitySecret;
    signal input userMessageLimit;
    signal input messageId[MAX_OUT];
    signal input pathElements[DEPTH];
    signal input identityPathIndex[DEPTH];

    // Public signals
    signal input x;
    signal input externalNullifier;
    signal input selectorUsed[MAX_OUT];

    // Outputs
    signal output y[MAX_OUT];
    signal output root;
    signal output nullifier[MAX_OUT];

    signal identityCommitment <== Poseidon2(1)([identitySecret]);
    signal rateCommitment <== Poseidon2(2)([identityCommitment, userMessageLimit]);

    // Membership check
    root <== MerkleTreeInclusionProofPoseidon2(DEPTH)(rateCommitment, identityPathIndex, pathElements);

    // At least one active messageId
    var selectorSumVar = 0;
    for (var i = 0; i < MAX_OUT; i++) {
        selectorSumVar += selectorUsed[i];
    }
    signal selectorSum <== selectorSumVar;
    signal noActiveSelector <== IsZero()(selectorSum);
    noActiveSelector === 0;

    // Active messageId checks
    signal pairBothActive[MAX_OUT][MAX_OUT];
    signal pairSameId[MAX_OUT][MAX_OUT];
    for (var i = 0; i < MAX_OUT; i++) {
        ConditionalRangeCheck(LIMIT_BIT_SIZE)(messageId[i], userMessageLimit, selectorUsed[i]);
        for (var j = i + 1; j < MAX_OUT; j++) {
            pairBothActive[i][j] <== selectorUsed[i] * selectorUsed[j];
            pairSameId[i][j] <== IsZero()(messageId[i] - messageId[j]);
            pairBothActive[i][j] * pairSameId[i][j] === 0;
        }
    }

    // SSS share and nullifier calculations
    signal a1[MAX_OUT];
    signal yUnmasked[MAX_OUT];
    signal nullifierUnmasked[MAX_OUT];
    for (var i = 0; i < MAX_OUT; i++) {
        a1[i] <== Poseidon2(3)([identitySecret, externalNullifier, messageId[i]]);
        yUnmasked[i] <== identitySecret + a1[i] * x;
        nullifierUnmasked[i] <== Poseidon2(1)([a1[i]]);
        y[i] <== selectorUsed[i] * yUnmasked[i];
        nullifier[i] <== selectorUsed[i] * nullifierUnmasked[i];
    }
}

component main { public [x, externalNullifier, selectorUsed] } = RLNPoseidon2Multi(20, 16, 4);
