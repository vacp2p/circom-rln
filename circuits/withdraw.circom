pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

// Proves knowledge of the identity secret behind an identity commitment while binding
// the withdrawal address into the proof (the address square keeps it constrained).
template Withdraw() {
    signal input identitySecret;
    signal input address;

    signal output identityCommitment <== Poseidon(1)([identitySecret]);

    // Dummy constraint to prevent compiler optimizing it
    signal addressSquared <== address * address;
}

component main { public [address] } = Withdraw();