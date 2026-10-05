pragma circom 2.1.0;

include "./poseidon2.circom";

// The withdraw circuit of withdraw.circom with the identity commitment hash swapped to
// Poseidon2; the address binding and the public signal layout are unchanged.
template WithdrawPoseidon2() {
    signal input identitySecret;
    signal input address;

    signal output identityCommitment <== Poseidon2(1)([identitySecret]);

    // Dummy constraint to prevent compiler optimizing it
    signal addressSquared <== address * address;
}

component main { public [address] } = WithdrawPoseidon2();
