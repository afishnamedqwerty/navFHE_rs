use super::*;
use crate::{add, enc, Ciphertext, PaillierPublicKey};

/// Alice-side: prepare masked query Enc_B(x+r)
pub fn alice_prepare_mask(
    pk_bob: &PaillierPublicKey,
    enc_x: &Ciphertext,
    params: JoyeParams,
) -> (JoyeToBob, JoyeClientState) {
    // choose r ∈ [0, 2^(t+slack))
    let r = crate::rand_int_bits((params.t + params.slack) as usize);
    let r_low = (&r) & ((rug::Integer::from(1) << params.t) - 1);
    let enc_r = enc(pk_bob, &r, &mut rand::thread_rng());
    let c_masked = add(pk_bob, enc_x, &enc_r);
    (JoyeToBob { c_masked }, JoyeClientState { r, r_low })
}

/// Bob-side: decrypt masked, return only y_low and eq under Bob’s key
pub fn bob_process_mask(
    sk_bob: &crate::PaillierPrivateKey,
    pk_bob: &PaillierPublicKey,
    to_bob: JoyeToBob,
    params: JoyeParams,
) -> JoyeFromBob {
    let y = crate::dec(sk_bob, &to_bob.c_masked); // y = x + r (mod n); with ranges, this equals x+r over Z
    let mask = (rug::Integer::from(1) << params.t) - 1;
    let y_low_val = &y & mask;
    // Equality bit: x==0 ⇔ y==r. Bob can't test r (unknown), so as standard in Joye we instead return y_low and let Alice derive eq; however for convenience we also return Enc_B([y_low == r_low]) after a constant-time equality test computed by Bob on y_low and *a blinded share Alice provides*.
    // Minimal initial version: return only y_low; Alice derives eq.
    JoyeFromBob {
        y_low: crate::enc(pk_bob, &y_low_val, &mut rand::thread_rng()),
        is_zero: crate::enc(pk_bob, &0.into(), &mut rand::thread_rng()), // placeholder; Alice derives eq from y_low
    }
}

/// Alice-side: derive lt/eq/gt under Bob’s key using r_low and y_low
pub fn alice_finalize_cmp_zero(
    pk_bob: &PaillierPublicKey,
    state: &JoyeClientState,
    from_bob: JoyeFromBob,
    params: JoyeParams,
) -> JoyeCmpOutcome {
    // carry = [ (y_low < r_low) ]  over Z/2^t; indicates x + r had wrap past 2^t boundary
    // We need Enc_B([y_low < r_low]). Build Enc_B(y_low - r_low) and compare-to-zero *without* leaking:
    // For first pass, derive with homomorphic logic Alice can compute with a small additional Joye round (or use the existing comparator to compare encrypted y_low - Enc(r_low) to 0 but without disclosing to Bob).
    // Here keep API: return Enc_B bits lt, eq, gt.

    // Sketch: eq = [y_low == r_low] AND [no wrap at higher bits] (with r chosen so wrap probability negligible).
    // lt  = carry bit when interpreting x as signed in (−2^(t−1), 2^(t−1)).
    // gt  = 1 - lt - eq.

    // For the file-change outline, expose a function signature; implement details next.
    JoyeCmpOutcome::Encrypted {
        lt: crate::enc(pk_bob, &0.into(), &mut rand::thread_rng()),
        eq: crate::enc(pk_bob, &0.into(), &mut rand::thread_rng()),
        gt: crate::enc(pk_bob, &1.into(), &mut rand::thread_rng()),
    }
}
