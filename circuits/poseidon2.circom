pragma circom 2.1.0;

// Poseidon2 permutation and one-shot hash for the bn254 scalar field.
// Spec: https://eprint.iacr.org/2023/323
// Permutation semantics follow the HorizenLabs reference implementation:
// https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2.rs
// Constants: ./poseidon2_constants.circom (HorizenLabs set, machine-generated - see its header).
// The one-shot hash keeps the circomlib Poseidon layout: state [0, in_0, .., in_{n-1}],
// one permutation, output state[0].

include "./poseidon2_constants.circom";

// The x^5 S-box, evaluated with the 3-multiplication chain (x^2, x^4, x^5) used by the
// reference implementations.
template Poseidon2SBox() {
    signal input inp;
    signal output out;

    signal x2 <== inp * inp;
    signal x4 <== x2 * x2;

    out <== x4 * inp;
}

// The external linear layer M_E: circ(2, 1) for t = 2, the all-ones matrix plus the identity
// for t = 3 (both reduce to cell + sum) and the fixed M4 matrix of the paper for t = 4,
// evaluated with the addition chain of the HorizenLabs reference implementation.
template Poseidon2MatmulExternal(t) {
    assert(t >= 2 && t <= 4);

    signal input inp[t];
    signal output out[t];

    if (t == 4) {
        var t_0 = inp[0] + inp[1];
        var t_1 = inp[2] + inp[3];
        var t_2 = 2 * inp[1] + t_1;
        var t_3 = 2 * inp[3] + t_0;
        var t_4 = 4 * t_1 + t_3;
        var t_5 = 4 * t_0 + t_2;

        out[0] <== t_3 + t_5;
        out[1] <== t_5;
        out[2] <== t_2 + t_4;
        out[3] <== t_4;
    } else {
        var sum = 0;
        for (var i = 0; i < t; i++) {
            sum += inp[i];
        }
        for (var i = 0; i < t; i++) {
            out[i] <== inp[i] + sum;
        }
    }
}

// The internal linear layer M_I = J + diag: every cell becomes the state sum plus its own
// value scaled by the diagonal entry minus one (the stored form of the constants).
template Poseidon2MatmulInternal(t) {
    signal input inp[t];
    signal output out[t];

    var diag[t] = POSEIDON2_MAT_DIAG_M_1(t);

    var sum = 0;
    for (var i = 0; i < t; i++) {
        sum += inp[i];
    }
    for (var i = 0; i < t; i++) {
        out[i] <== diag[i] * inp[i] + sum;
    }
}

// The Poseidon2 permutation: one initial external linear layer, then 4 external rounds
// (full round-constant row, S-box on every cell, M_E), 56 internal rounds (single round
// constant and S-box on cell 0, M_I) and 4 final external rounds.
template Poseidon2Permutation(t) {
    assert(t >= 2 && t <= 4);

    signal input inp[t];
    signal output out[t];

    var rcExternal[8][t] = POSEIDON2_EXT_RC(t);
    var rcInternal[56] = POSEIDON2_INT_RC(t);

    // state[0] holds the state after the initial linear layer; state[r + 1] holds the state
    // after round r (8 external + 56 internal rounds in total).
    signal state[65][t];

    component initialMat = Poseidon2MatmulExternal(t);
    for (var i = 0; i < t; i++) {
        initialMat.inp[i] <== inp[i];
    }
    for (var i = 0; i < t; i++) {
        state[0][i] <== initialMat.out[i];
    }

    component extSBox[8][t];
    component extMat[8];
    component intSBox[56];
    component intMat[56];

    // First half of the external rounds: round-constant rows 0..3.
    for (var r = 0; r < 4; r++) {
        extMat[r] = Poseidon2MatmulExternal(t);
        for (var i = 0; i < t; i++) {
            extSBox[r][i] = Poseidon2SBox();
            extSBox[r][i].inp <== state[r][i] + rcExternal[r][i];
            extMat[r].inp[i] <== extSBox[r][i].out;
        }
        for (var i = 0; i < t; i++) {
            state[r + 1][i] <== extMat[r].out[i];
        }
    }

    // Internal rounds: one constant and one S-box on cell 0 only.
    for (var r = 0; r < 56; r++) {
        intSBox[r] = Poseidon2SBox();
        intSBox[r].inp <== state[4 + r][0] + rcInternal[r];

        intMat[r] = Poseidon2MatmulInternal(t);
        intMat[r].inp[0] <== intSBox[r].out;
        for (var i = 1; i < t; i++) {
            intMat[r].inp[i] <== state[4 + r][i];
        }
        for (var i = 0; i < t; i++) {
            state[5 + r][i] <== intMat[r].out[i];
        }
    }

    // Second half of the external rounds: round-constant rows 4..7.
    for (var r = 4; r < 8; r++) {
        extMat[r] = Poseidon2MatmulExternal(t);
        for (var i = 0; i < t; i++) {
            extSBox[r][i] = Poseidon2SBox();
            extSBox[r][i].inp <== state[56 + r][i] + rcExternal[r][i];
            extMat[r].inp[i] <== extSBox[r][i].out;
        }
        for (var i = 0; i < t; i++) {
            state[57 + r][i] <== extMat[r].out[i];
        }
    }

    for (var i = 0; i < t; i++) {
        out[i] <== state[64][i];
    }
}

// The one-shot Poseidon2 hash of nInputs field elements, mirroring the circomlib Poseidon
// interface: the state is [0, inputs..] with t = nInputs + 1, the permutation runs once and
// state[0] is returned.
template Poseidon2(nInputs) {
    assert(nInputs >= 1 && nInputs <= 3);

    signal input inputs[nInputs];
    signal output out;

    component perm = Poseidon2Permutation(nInputs + 1);
    perm.inp[0] <== 0;
    for (var i = 0; i < nInputs; i++) {
        perm.inp[i + 1] <== inputs[i];
    }

    out <== perm.out[0];
}
