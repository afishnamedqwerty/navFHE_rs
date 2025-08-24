pub mod joye;

//#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct JoyeParams {
    /// secure bound: |x| < 2^(t-2)
    pub t: u32, // bit-length bound for |x|
    pub slack: u32, // extra random bits λ for masking, e.g., 32..64
}

#[derive(Clone, Copy, Debug)]
pub enum ComparatorKind { Joye, DGK }

pub struct ComparatorConfig {
    pub kind: ComparatorKind,
    pub joye: Option<JoyeParams>,
    pub dgk:  Option<DGKParams>,
}

pub struct DGKParams {
    pub t: u32,      // plaintext bit bound (same shape as Joye for now)
    pub slack: u32,  // masking slack
    // add DGK public params as needed: (n, g, h) small-plaintext hom-enc keys, etc.
}

#[derive(Clone, Debug)]
pub struct JoyeClientState {
    pub r: rug::Integer,     // Alice’s random mask
    pub r_low: rug::Integer, // r mod 2^t (cached)
}

#[derive(Clone, Debug)]
pub struct JoyeToBob {
    pub c_masked: super::Ciphertext, // Enc_B(x + r)
}

#[derive(Clone, Debug)]
pub struct JoyeFromBob {
    // All under Bob’s Paillier public key
    pub y_low: super::Ciphertext,   // Enc_B( (x + r) mod 2^t )
    pub is_zero: super::Ciphertext, // Enc_B( [x == 0] )
}

pub enum JoyeCmpOutcome {
    Encrypted {
        lt: super::Ciphertext, // Enc_B([x < 0])
        eq: super::Ciphertext, // Enc_B([x == 0])
        gt: super::Ciphertext, // Enc_B([x > 0])
    },
}
