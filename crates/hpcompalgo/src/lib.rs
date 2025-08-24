use anyhow::Result;
use hpcompcrypto::{
    add, add_plain, blind_pair, dec, enc, unblind_product, mul_plain, Ciphertext, EncInt, PaillierPublicKey, PaillierPrivateKey, RemoteComparator,
    RemoteMultiplier,
};
use rug::Integer;
use serde::{Deserialize, Serialize};
use rug::Complete;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    pub static ALLOW_RAW_MULT: Cell<bool> = Cell::new(false);
}

#[inline]
fn int_from_be_bytes(bytes: &[u8]) -> rug::Integer {
    let mut x = rug::Integer::from(0);
    for &b in bytes {
        x <<= 8;
        x += rug::Integer::from(b);
    }
    x
}

#[inline]
pub fn crate_rand_bits(bits: usize) -> rug::Integer {
    use rand::RngCore;
    if bits == 0 { return rug::Integer::from(0); }
    let nbytes = (bits + 7) / 8;
    let mut bytes = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut bytes);
    let excess = 8 * nbytes - bits;
    if excess > 0 { bytes[0] &= 0xFFu8 >> excess; } // mask so < 2^bits
    int_from_be_bytes(&bytes)
}

#[inline]
pub fn crate_rand_mod_n(pk: &PaillierPublicKey) -> rug::Integer {
    let n = pk.n();
    let bits = n.significant_bits() as usize;
    loop {
        let c = crate_rand_bits(bits);      // uniform in [0, 2^bits)
        if c < n { return c; }              // reject if ≥ n → uniform in Z_n
    }
}

pub fn crate_rand() -> rug::Integer { //bits: usize
    // returns a non-negative Integer uniformly in [0, 2^bits)
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    int_from_be_bytes(&bytes)
    /*let nbytes = (bits + 7) / 8;
    let mut bytes = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut bytes);

    if nbytes > 0 {
        // mask off any extra MSBs so the value < 2^bits
        let excess = 8 * nbytes - bits;
        if excess > 0 {
            let mask = 0xFFu8 >> excess;
            bytes[0] &= mask;
        }
    }
    Integer::from_digits(&bytes, Order::MsfBe)*/
}

pub fn bool_and(
    pk: &PaillierPublicKey,
    a: &Ciphertext,
    b: &Ciphertext,
    mult: &mut dyn RemoteMultiplier,
) -> anyhow::Result<Ciphertext> {
    /*let pairs = vec![(a.clone(), b.clone())];
    let prods = mult.mult_batch(&pairs)?;
    Ok(prods[0].clone())*/
    mul_ct_ct(pk, a, b, mult)
}

pub fn bool_or(
    pk: &PaillierPublicKey,
    a: &Ciphertext,
    b: &Ciphertext,
    mult: &mut dyn RemoteMultiplier,
) -> anyhow::Result<Ciphertext> {
    //let ab = bool_and(pk, a, b, mult)?;
    let ab = mul_ct_ct(pk, a, b, mult)?;
    let sum = add(pk, a, b);
    let neg_ab = mul_plain(pk, &ab, &rug::Integer::from(-1));
    Ok(add(pk, &sum, &neg_ab))
}

fn bool_xor(
    pk: &PaillierPublicKey,
    a: &Ciphertext,
    b: &Ciphertext,
    mult: &mut dyn RemoteMultiplier,
) -> anyhow::Result<Ciphertext> {
    //let ab = bool_and(pk, a, b, mult)?;
    let ab = mul_ct_ct(pk, a, b, mult)?;
    let twoab = mul_plain(pk, &ab, &rug::Integer::from(2));
    let sum = add(pk, a, b);
    let neg = mul_plain(pk, &twoab, &rug::Integer::from(-1));
    Ok(add(pk, &sum, &neg))
}

fn one_minus(pk: &PaillierPublicKey, a: &Ciphertext) -> Ciphertext {
    let one = enc(pk, &rug::Integer::from(1), &mut rand::thread_rng());
    let neg_a = mul_plain(pk, a, &rug::Integer::from(-1));
    add(pk, &one, &neg_a)
}

fn select(
    pk: &PaillierPublicKey,
    cond: &Ciphertext,
    x: &EncInt,
    y: &EncInt,
    mult: &mut dyn RemoteMultiplier,
) -> anyhow::Result<EncInt> {
    let one_minus_c = one_minus(pk, cond);
    //let cx = mult.mult_batch(&[(cond.clone(), x.c.clone())])?[0].clone();
    //let cy = mult.mult_batch(&[(one_minus_c.clone(), y.c.clone())])?[0].clone();
    let cx = mul_ct_ct(pk, cond, &x.c, mult)?;
    let cy = mul_ct_ct(pk, &one_minus_c, &y.c, mult)?;
    Ok(EncInt::new(add(pk, &cx, &cy)))
}

// Fresh-random blinded multiply for two ciphertexts.
pub fn mul_ct_ct(
    pk: &PaillierPublicKey,
    x: &Ciphertext,
    y: &Ciphertext,
    mult: &mut dyn RemoteMultiplier,
) -> anyhow::Result<Ciphertext> {
    // wrap operands
    use hpcompcrypto::{blind_pair, unblind_product};
    let ex = EncInt::new(x.clone());
    let ey = EncInt::new(y.clone());
    // fresh blinders every call
    let a = crate_rand_mod_n(pk);   // use your existing rand_int() / rand_int_bits helper
    let b = crate_rand_mod_n(pk);
    let (xb, yb) = blind_pair(pk, &ex, &ey, &a, &b);
    //let prod_blinded = mult.mult_batch(&[(xb, yb)])?.remove(0);
    //let un = unblind_product(pk, &ex, &ey, &prod_blinded, &a, &b);
    #[cfg(test)]
    let prod_blinded = crate::ALLOW_RAW_MULT.with(|flag| {
        flag.set(true);
        let r = mult.mult_batch(&[(xb, yb)]);
        flag.set(false);
        r
    })?.remove(0);

    #[cfg(not(test))]
    let prod_blinded = mult.mult_batch(&[(xb, yb)])?.remove(0);

    let un = unblind_product(pk, &ex, &ey, &prod_blinded, &a, &b);
    Ok(un.c)
}

use rand::RngCore;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pt {
    pub x: EncInt,
    pub y: EncInt,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Seg {
    pub p: Pt,
    pub q: Pt,
}

pub struct ProtoCtx<'a> {
    pub pk: &'a PaillierPublicKey,
    pub mult: &'a mut dyn RemoteMultiplier,
    pub cmp: &'a mut dyn RemoteComparator,
}

#[derive(Clone, Debug)]
pub struct EncTriSign {
    pub lt: Ciphertext,
    pub eq: Ciphertext,
    pub gt: Ciphertext,
}

pub fn enc_int(pk: &PaillierPublicKey, v: i64) -> EncInt {
    EncInt::new(enc(pk, &Integer::from(v), &mut rand::thread_rng()))
}

/// Compute encrypted orientation sign for (p, q, r).

pub fn orient(p: &Pt, q: &Pt, r: &Pt, ctx: &mut ProtoCtx) -> Result<EncTriSign> {
    let pk = ctx.pk;
    // Δ = (qy - py)*(rx - qx) - (qx - px)*(ry - qy)
    let qy_minus_py = EncInt::new(add(
        pk,
        &q.y.c,
        &mul_plain(pk, &p.y.c, &Integer::from(-1)),
    ));
    let rx_minus_qx = EncInt::new(add(
        pk,
        &r.x.c,
        &mul_plain(pk, &q.x.c, &Integer::from(-1)),
    ));
    let qx_minus_px = EncInt::new(add(
        pk,
        &q.x.c,
        &mul_plain(pk, &p.x.c, &Integer::from(-1)),
    ));
    let ry_minus_qy = EncInt::new(add(
        pk,
        &r.y.c,
        &mul_plain(pk, &q.y.c, &Integer::from(-1)),
    ));

    use hpcompcrypto::{blind_pair, unblind_product};
    // t1 = (qy - py)*(rx - qx)  via blinded multiply
    //let a1 = crate_rand(); //rand_int();
    //let b1 = crate_rand(); //rand_int();
    //let (xa1, yb1) = blind_pair(pk, &qy_minus_py, &rx_minus_qx, &a1, &b1);
    //let prod1 = ctx.mult.mult_batch(&[(xa1, yb1)])?.remove(0);
    //let t1 = unblind_product(pk, &qy_minus_py, &rx_minus_qx, &prod1, &a1, &b1);
    let t1 = mul_ct_ct(pk, &qy_minus_py.c, &rx_minus_qx.c, ctx.mult)?;
    let t2 = mul_ct_ct(pk, &qx_minus_px.c, &ry_minus_qy.c, ctx.mult)?;

    // t2 = (qx - px)*(ry - qy)  via blinded multiply
    //let a2 = crate_rand(); //rand_int();
    //let b2 = crate_rand(); //rand_int();
    //let (xa2, yb2) = blind_pair(pk, &qx_minus_px, &ry_minus_qy, &a2, &b2);
    //let prod2 = ctx.mult.mult_batch(&[(xa2, yb2)])?.remove(0);
    //let t2 = unblind_product(pk, &qx_minus_px, &ry_minus_qy, &prod2, &a2, &b2);

    // Δ = t1 - t2
    //let neg_t2 = EncInt::new(mul_plain(pk, &t2.c, &rug::Integer::from(-1)));
    let neg_t2 = mul_plain(pk, &t2, &Integer::from(-1));
    let delta = EncInt::new(add(pk, &t1, &neg_t2));

    // sign(Δ)
    let (lt, eq, gt) = ctx.cmp.cmp_zero(&delta.c)?;
    Ok(EncTriSign { lt, eq, gt })
}

fn enc_minmax(
    pk: &PaillierPublicKey,
    a: &EncInt,
    b: &EncInt,
    ctx: &mut ProtoCtx,
) -> Result<(EncInt, EncInt)> {
    // Dev-oracle comparator returns encrypted lt/eq/gt bits.
    let (lt, eq, gt) = ctx.cmp.cmp_zero(&{
        // compute a - b
        let neg_b = EncInt::new(mul_plain(pk, &b.c, &Integer::from(-1)));
        let diff = EncInt::new(add(pk, &a.c, &neg_b.c));
        diff.c
    })?;
    // min = if a<b then a else b ; max = a+b-min
    // In Paillier we cannot branch; for dev/demo we'll just return (a,b) and let higher level use compares explicitly.
    Ok((
        EncInt::new(a.c.clone()),
        EncInt::new(b.c.clone()),
    ))
}

pub fn on_segment(p: &Pt, a: &Pt, b: &Pt, ctx: &mut ProtoCtx) -> Result<Ciphertext> {
    let pk = ctx.pk;
    // Determine ordering for x
    let ax_minus_bx = EncInt::new(add(
        pk,
        &a.x.c,
        &mul_plain(pk, &b.x.c, &rug::Integer::from(-1)),
    ));
    let (ltx, eqx, _gtx) = ctx.cmp.cmp_zero(&ax_minus_bx.c)?;
    let a_le_b_x = bool_or(pk, &ltx, &eqx, ctx.mult)?;
    let minx = select(pk, &a_le_b_x, &a.x, &b.x, ctx.mult)?;
    let maxx = select(pk, &a_le_b_x, &b.x, &a.x, ctx.mult)?;
    // Determine ordering for y
    let ay_minus_by = EncInt::new(add(
        pk,
        &a.y.c,
        &mul_plain(pk, &b.y.c, &rug::Integer::from(-1)),
    ));
    let (lty, eqy, _gty) = ctx.cmp.cmp_zero(&ay_minus_by.c)?;
    let a_le_b_y = bool_or(pk, &lty, &eqy, ctx.mult)?;
    let miny = select(pk, &a_le_b_y, &a.y, &b.y, ctx.mult)?;
    let maxy = select(pk, &a_le_b_y, &b.y, &a.y, ctx.mult)?;

    // px in [minx, maxx]
    let px_minus_minx = EncInt::new(add(
        pk,
        &p.x.c,
        &mul_plain(pk, &minx.c, &Integer::from(-1)),
    ));
    let (_lt1, eq1, gt1) = ctx.cmp.cmp_zero(&px_minus_minx.c)?;
    let ge_minx = bool_or(pk, &gt1, &eq1, ctx.mult)?;
    let maxx_minus_px = EncInt::new(add(
        pk,
        &maxx.c,
        &mul_plain(pk, &p.x.c, &Integer::from(-1)),
    ));
    let (_lt2, eq2, gt2) = ctx.cmp.cmp_zero(&maxx_minus_px.c)?;
    let le_maxx = bool_or(pk, &gt2, &eq2, ctx.mult)?;

    // py in [miny, maxy]
    let py_minus_miny = EncInt::new(add(
        pk,
        &p.y.c,
        &mul_plain(pk, &miny.c, &Integer::from(-1)),
    ));
    let (_lt3, eq3, gt3) = ctx.cmp.cmp_zero(&py_minus_miny.c)?;
    let ge_miny = bool_or(pk, &gt3, &eq3, ctx.mult)?;
    let maxy_minus_py = EncInt::new(add(
        pk,
        &maxy.c,
        &mul_plain(pk, &p.y.c, &Integer::from(-1)),
    ));
    let (_lt4, eq4, gt4) = ctx.cmp.cmp_zero(&maxy_minus_py.c)?;
    let le_maxy = bool_or(pk, &gt4, &eq4, ctx.mult)?;

    let in_x = bool_and(pk, &ge_minx, &le_maxx, ctx.mult)?;
    let in_y = bool_and(pk, &ge_miny, &le_maxy, ctx.mult)?;
    let on = bool_and(pk, &in_x, &in_y, ctx.mult)?;
    Ok(on)
}

pub fn segments_intersect(a: &Seg, b: &Seg, ctx: &mut ProtoCtx) -> Result<Ciphertext> {
    let pk = ctx.pk;
    let o1 = orient(&a.p, &a.q, &b.p, ctx)?;
    let o2 = orient(&a.p, &a.q, &b.q, ctx)?;
    let o3 = orient(&b.p, &b.q, &a.p, ctx)?;
    let o4 = orient(&b.p, &b.q, &a.q, ctx)?;

    let gt1_lt2 = bool_and(pk, &o1.gt, &o2.lt, ctx.mult)?;
    let lt1_gt2 = bool_and(pk, &o1.lt, &o2.gt, ctx.mult)?;
    let opp12 = bool_or(pk, &gt1_lt2, &lt1_gt2, ctx.mult)?;

    let gt3_lt4 = bool_and(pk, &o3.gt, &o4.lt, ctx.mult)?;
    let lt3_gt4 = bool_and(pk, &o3.lt, &o4.gt, ctx.mult)?;
    let opp34 = bool_or(pk, &gt3_lt4, &lt3_gt4, ctx.mult)?;

    let gen = bool_and(pk, &opp12, &opp34, ctx.mult)?;

    let on1 = on_segment(&b.p, &a.p, &a.q, ctx)?;
    let on2 = on_segment(&b.q, &a.p, &a.q, ctx)?;
    let on3 = on_segment(&a.p, &b.p, &b.q, ctx)?;
    let on4 = on_segment(&a.q, &b.p, &b.q, ctx)?;

    let c1 = bool_and(pk, &o1.eq, &on1, ctx.mult)?;
    let c2 = bool_and(pk, &o2.eq, &on2, ctx.mult)?;
    let c3 = bool_and(pk, &o3.eq, &on3, ctx.mult)?;
    let c4 = bool_and(pk, &o4.eq, &on4, ctx.mult)?;

    let col_a = bool_or(pk, &c1, &c2, ctx.mult)?;
    let col_b = bool_or(pk, &c3, &c4, ctx.mult)?;
    let col = bool_or(pk, &col_a, &col_b, ctx.mult)?;

    Ok(bool_or(pk, &gen, &col, ctx.mult)?)
}

/// Encrypted AABB overlap: returns encrypted {0,1} whether the bounding boxes of a and b overlap.
pub fn aabb_overlap(a: &Seg, b: &Seg, ctx: &mut ProtoCtx) -> Result<Ciphertext> {
    let pk = ctx.pk;
    // For each segment, compute min/max for x/y
    let (a_minx, a_maxx) = {
        let diff = EncInt::new(add(
            pk,
            &a.p.x.c,
            &mul_plain(pk, &b.p.x.c, &rug::Integer::from(0)),
        )); // dummy to reuse API
        let ax_minus_bx = EncInt::new(add(
            pk,
            &a.p.x.c,
            &mul_plain(pk, &a.q.x.c, &rug::Integer::from(-1)),
        ));
        let (ltx, eqx, _) = ctx.cmp.cmp_zero(&ax_minus_bx.c)?;
        let a_le = bool_or(pk, &ltx, &eqx, ctx.mult)?;
        let minx = select(pk, &a_le, &a.p.x, &a.q.x, ctx.mult)?;
        let maxx = select(pk, &a_le, &a.q.x, &a.p.x, ctx.mult)?;
        (minx, maxx)
    };
    let (a_miny, a_maxy) = {
        let ay_minus_by = EncInt::new(add(
            pk,
            &a.p.y.c,
            &mul_plain(pk, &a.q.y.c, &rug::Integer::from(-1)),
        ));
        let (lty, eqy, _) = ctx.cmp.cmp_zero(&ay_minus_by.c)?;
        let a_le = bool_or(pk, &lty, &eqy, ctx.mult)?;
        let miny = select(pk, &a_le, &a.p.y, &a.q.y, ctx.mult)?;
        let maxy = select(pk, &a_le, &a.q.y, &a.p.y, ctx.mult)?;
        (miny, maxy)
    };
    let (b_minx, b_maxx) = {
        let xdiff = EncInt::new(add(
            pk,
            &b.p.x.c,
            &mul_plain(pk, &b.q.x.c, &rug::Integer::from(-1)),
        ));
        let (ltx, eqx, _) = ctx.cmp.cmp_zero(&xdiff.c)?;
        let b_le = bool_or(pk, &ltx, &eqx, ctx.mult)?;
        let minx = select(pk, &b_le, &b.p.x, &b.q.x, ctx.mult)?;
        let maxx = select(pk, &b_le, &b.q.x, &b.p.x, ctx.mult)?;
        (minx, maxx)
    };
    let (b_miny, b_maxy) = {
        let ydiff = EncInt::new(add(
            pk,
            &b.p.y.c,
            &mul_plain(pk, &b.q.y.c, &rug::Integer::from(-1)),
        ));
        let (lty, eqy, _) = ctx.cmp.cmp_zero(&ydiff.c)?;
        let b_le = bool_or(pk, &lty, &eqy, ctx.mult)?;
        let miny = select(pk, &b_le, &b.p.y, &b.q.y, ctx.mult)?;
        let maxy = select(pk, &b_le, &b.q.y, &b.p.y, ctx.mult)?;
        (miny, maxy)
    };

    // Overlap if a.minx <= b.maxx && b.minx <= a.maxx && a.miny <= b.maxy && b.miny <= a.maxy
    let a_minx_le_b_maxx = {
        let diff = EncInt::new(add(
            pk,
            &a_minx.c,
            &mul_plain(pk, &b_maxx.c, &rug::Integer::from(-1)),
        ));
        let (lt, eq, _) = ctx.cmp.cmp_zero(&diff.c)?;
        bool_or(pk, &lt, &eq, ctx.mult)?
    };
    let b_minx_le_a_maxx = {
        let diff = EncInt::new(add(
            pk,
            &b_minx.c,
            &mul_plain(pk, &a_maxx.c, &rug::Integer::from(-1)),
        ));
        let (lt, eq, _) = ctx.cmp.cmp_zero(&diff.c)?;
        bool_or(pk, &lt, &eq, ctx.mult)?
    };
    let a_miny_le_b_maxy = {
        let diff = EncInt::new(add(
            pk,
            &a_miny.c,
            &mul_plain(pk, &b_maxy.c, &rug::Integer::from(-1)),
        ));
        let (lt, eq, _) = ctx.cmp.cmp_zero(&diff.c)?;
        bool_or(pk, &lt, &eq, ctx.mult)?
    };
    let b_miny_le_a_maxy = {
        let diff = EncInt::new(add(
            pk,
            &b_miny.c,
            &mul_plain(pk, &a_maxy.c, &rug::Integer::from(-1)),
        ));
        let (lt, eq, _) = ctx.cmp.cmp_zero(&diff.c)?;
        bool_or(pk, &lt, &eq, ctx.mult)?
    };

    let x_ok = bool_and(pk, &a_minx_le_b_maxx, &b_minx_le_a_maxx, ctx.mult)?;
    let y_ok = bool_and(pk, &a_miny_le_b_maxy, &b_miny_le_a_maxy, ctx.mult)?;
    bool_and(pk, &x_ok, &y_ok, ctx.mult)
}

#[cfg(test)]
mod enc_vs_cleartext {
    use super::*;
    use hpcompcrypto::*;
    use rand::Rng;
    // ---- Test-only debug helpers ----

    #[inline]
    fn delta_ct(
        pk: &PaillierPublicKey,
        p: &Pt,
        q: &Pt,
        r: &Pt,
        mult: &mut dyn RemoteMultiplier,
    ) -> anyhow::Result<Ciphertext> {
        // Δ = (qy - py)*(rx - qx) - (qx - px)*(ry - qy)
        let qy_minus_py = EncInt::new(add(pk, &q.y.c, &mul_plain(pk, &p.y.c, &Integer::from(-1))));
        let rx_minus_qx = EncInt::new(add(pk, &r.x.c, &mul_plain(pk, &q.x.c, &Integer::from(-1))));
        let qx_minus_px = EncInt::new(add(pk, &q.x.c, &mul_plain(pk, &p.x.c, &Integer::from(-1))));
        let ry_minus_qy = EncInt::new(add(pk, &r.y.c, &mul_plain(pk, &q.y.c, &Integer::from(-1))));

        let t1 = mul_ct_ct(pk, &qy_minus_py.c, &rx_minus_qx.c, mult)?;
        let t2 = mul_ct_ct(pk, &qx_minus_px.c, &ry_minus_qy.c, mult)?;

        let neg_t2 = mul_plain(pk, &t2, &Integer::from(-1));
        Ok(add(pk, &t1, &neg_t2))
    }

    #[inline]
    fn debug_print_deltas_and_flags(
        label: &str,
        pk: &PaillierPublicKey,
        sk: &PaillierPrivateKey,
        a: &Seg,
        b: &Seg,
        mult: &mut dyn RemoteMultiplier,
    ) -> anyhow::Result<()> {
        // Encrypted deltas for the four triplets
        let d1 = delta_ct(pk, &a.p, &a.q, &b.p, mult)?;
        let d2 = delta_ct(pk, &a.p, &a.q, &b.q, mult)?;
        let d3 = delta_ct(pk, &b.p, &b.q, &a.p, mult)?;
        let d4 = delta_ct(pk, &b.p, &b.q, &a.q, mult)?;

        // Decrypt to centered representatives (using the same centering as comparator)
        let n = pk.n();
        let c = |mut v: Integer| {
            let mut h = n.clone(); h >>= 1;
            if v > h { v -= &n; }
            v
        };
        let dd1 = c(dec(sk, &d1));
        let dd2 = c(dec(sk, &d2));
        let dd3 = c(dec(sk, &d3));
        let dd4 = c(dec(sk, &d4));

        // Also print on-segment flags (decrypt)
        // (These call your existing on_segment(), which uses blinded multiplies.)
        let mut cmp_oracle = LocalOracle { pk: pk.clone(), sk: sk.clone() };
        let mut ctx = ProtoCtx { pk, mult, cmp: &mut cmp_oracle };

        let on1 = dec(sk, &on_segment(&b.p, &a.p, &a.q, &mut ctx)?);
        let on2 = dec(sk, &on_segment(&b.q, &a.p, &a.q, &mut ctx)?);
        let on3 = dec(sk, &on_segment(&a.p, &b.p, &b.q, &mut ctx)?);
        let on4 = dec(sk, &on_segment(&a.q, &b.p, &b.q, &mut ctx)?);

        println!(
            "[{label}] deltas centered: d1={dd1}, d2={dd2}, d3={dd3}, d4={dd4}; on1={on1}, on2={on2}, on3={on3}, on4={on4}"
        );
        Ok(())
    }

    #[cfg(test)]
    use std::cell::Cell;

    // Map a Paillier residue in [0, n-1] to a centered representative in (-n/2, n/2]
    fn centered(v: Integer, n: &Integer) -> Integer {
        // compute half_n without lazy shifts
        let mut half_n = n.clone();
        half_n >>= 1;
        if v > half_n { v - n } else { v }
    }

    // Local non-leaking oracle used only in tests:
    // - mult_batch: decrypts blind factors (as Bob would), multiplies in Z, re-encrypts
    // - cmp_zero: decrypts and compares in *centered* domain to produce encrypted lt/eq/gt
    struct LocalOracle {
        sk: PaillierPrivateKey,
        pk: PaillierPublicKey,
    }
    impl RemoteMultiplier for LocalOracle {
        fn mult_batch(
            &mut self,
            blinded_pairs: &[(Ciphertext, Ciphertext)],
        ) -> anyhow::Result<Vec<Ciphertext>> {
            Ok(blinded_pairs
                .iter()
                .map(|(x, y)| {
                    let xv = dec(&self.sk, x);
                    let yv = dec(&self.sk, y);
                    enc(&self.pk, &(xv * yv), &mut rand::thread_rng())
                })
                .collect())
        }
    }
    impl RemoteComparator for LocalOracle {
        fn cmp_zero(
            &mut self,
            x: &Ciphertext,
        ) -> anyhow::Result<(Ciphertext, Ciphertext, Ciphertext)> {
            // Simulate a private comparator: decrypt locally (test-only)
            let v = dec(&self.sk, x);
            //let n = self.pk.n();
            //let s = if v > (n >> 1) { v - n } else { v };
            let s = centered(v, &self.pk.n());//(&n >> 1).complete(); half_n
            //let mut s = v;
            //if s > half_n {
            //    s -= &n;
            //}
            let lt = if s < 0 { 1 } else { 0 };
            let eq = if s == 0 { 1 } else { 0 };
            let gt = if s > 0 { 1 } else { 0 };
            Ok((
                enc(&self.pk, &lt.into(), &mut rand::thread_rng()),
                enc(&self.pk, &eq.into(), &mut rand::thread_rng()),
                enc(&self.pk, &gt.into(), &mut rand::thread_rng()),
            ))
        }
    }
    #[inline]
    fn orient_plain(p: (i64, i64), q: (i64, i64), r: (i64, i64)) -> i64 {
        let val: i128 =
        (q.1 - p.1) as i128 * (r.0 - q.0) as i128
      - (q.0 - p.0) as i128 * (r.1 - q.1) as i128;
        val as i64
    }

    #[inline]
    fn onseg_plain(p: (i64, i64), a: (i64, i64), b: (i64, i64)) -> bool {
        let (minx, maxx) = (a.0.min(b.0), a.0.max(b.0));
        let (miny, maxy) = (a.1.min(b.1), a.1.max(b.1));
        p.0 >= minx && p.0 <= maxx && p.1 >= miny && p.1 <= maxy
    }

    #[inline]
    fn inter_plain(a: ((i64, i64), (i64, i64)), b: ((i64, i64), (i64, i64))) -> bool {
        let o1 = orient_plain(a.0, a.1, b.0);
        let o2 = orient_plain(a.0, a.1, b.1);
        let o3 = orient_plain(b.0, b.1, a.0);
        let o4 = orient_plain(b.0, b.1, a.1);
        if (o1 > 0 && o2 < 0 || o1 < 0 && o2 > 0) && (o3 > 0 && o4 < 0 || o3 < 0 && o4 > 0) {
            return true;
        }
        if o1 == 0 && onseg_plain(b.0, a.0, a.1) {
            return true;
        }
        if o2 == 0 && onseg_plain(b.1, a.0, a.1) {
            return true;
        }
        if o3 == 0 && onseg_plain(a.0, b.0, b.1) {
            return true;
        }
        if o4 == 0 && onseg_plain(a.1, b.0, b.1) {
            return true;
        }
        false
    }

    // ----- Helpers to encrypt points/segments -----

    fn enc_pt(pk: &PaillierPublicKey, p:(i64,i64)) -> Pt {
        let mut rng = rand::thread_rng();
        Pt{
            x: EncInt::new(enc(pk, &Integer::from(p.0), &mut rng)),
            y: EncInt::new(enc(pk, &Integer::from(p.1), &mut rng)),
        }
    }
    fn enc_seg(pk:&PaillierPublicKey, a:(i64,i64), b:(i64,i64)) -> Seg {
        Seg{ p: enc_pt(pk, a), q: enc_pt(pk, b) }
    }

    #[cfg(test)]
    struct GuardedMult<M>(M);

    #[cfg(test)]
    impl<M: RemoteMultiplier> RemoteMultiplier for GuardedMult<M> {
        fn mult_batch(&mut self, pairs: &[(Ciphertext, Ciphertext)]) -> anyhow::Result<Vec<Ciphertext>> {
            let allowed = crate::ALLOW_RAW_MULT.with(|f| f.get());
            assert!(allowed, "ct×ct multiply must go through mul_ct_ct (blinded, uniform Z_n).");
            self.0.mult_batch(pairs)
        }
    }


    #[test]
    fn signed_compare_centered_zero() {
        let (pk, sk) = keygen(512, &mut rand::thread_rng());
        let mut oracle = LocalOracle{ pk: pk.clone(), sk };
        // small integers around zero
        for x in -20..=20 {
            let ct = enc(&pk, &Integer::from(x), &mut rand::thread_rng());
            let (lt, eq, gt) = oracle.cmp_zero(&ct).unwrap();
            let lt = dec(&oracle.sk, &lt).to_i32_wrapping();
            let eq = dec(&oracle.sk, &eq).to_i32_wrapping();
            let gt = dec(&oracle.sk, &gt).to_i32_wrapping();
            assert_eq!(lt, (x < 0) as i32);
            assert_eq!(eq, (x == 0) as i32);
            assert_eq!(gt, (x > 0) as i32);
        }
    }

    #[test]
    fn random_pairs_match_plain() {
        let (pk, sk_master) = keygen(512, &mut rand::thread_rng());
        let mut mult_oracle = GuardedMult(LocalOracle { pk: pk.clone(), sk: sk_master.clone() });
        let mut cmp_oracle = LocalOracle{ pk: pk.clone(), sk: sk_master.clone() };
        let sk_dec = sk_master;
        let mut rng = rand::thread_rng();
        for _ in 0..300 {
            let a0 = (rng.gen_range(-50..50), rng.gen_range(-50..50));
            let a1 = (rng.gen_range(-50..50), rng.gen_range(-50..50));
            let b0 = (rng.gen_range(-50..50), rng.gen_range(-50..50));
            let b1 = (rng.gen_range(-50..50), rng.gen_range(-50..50));

            let pa = Pt {
                x: EncInt::new(enc(&pk, &a0.0.into(), &mut rng)),
                y: EncInt::new(enc(&pk, &a0.1.into(), &mut rng)),
            };
            let qa = Pt {
                x: EncInt::new(enc(&pk, &a1.0.into(), &mut rng)),
                y: EncInt::new(enc(&pk, &a1.1.into(), &mut rng)),
            };
            let pb = Pt {
                x: EncInt::new(enc(&pk, &b0.0.into(), &mut rng)),
                y: EncInt::new(enc(&pk, &b0.1.into(), &mut rng)),
            };
            let qb = Pt {
                x: EncInt::new(enc(&pk, &b1.0.into(), &mut rng)),
                y: EncInt::new(enc(&pk, &b1.1.into(), &mut rng)),
            };

            let sa = Seg { p: pa, q: qa };
            let sb = Seg { p: pb, q: qb };
            let mut ctx = ProtoCtx {
                pk: &pk,
                mult: &mut mult_oracle,
                cmp: &mut cmp_oracle,
            };
            let e = segments_intersect(&sa, &sb, &mut ctx).unwrap();
            let v = dec(&sk_dec, &e);
            let v = if v == 0 { 0 } else { 1 };
            let plain = if inter_plain((a0, a1), (b0, b1)) {
                1
            } else {
                0
            };
            if v != plain {
                // Print Δ’s and on-segment flags before we panic
                debug_print_deltas_and_flags("random_pairs", &pk, &sk_dec, &sa, &sb, ctx.mult).ok(); //&mut
                assert_eq!(v, plain, "mismatch for {:?}-{:?} vs {:?}-{:?}", a0, a1, b0, b1);
            }
            //assert_eq!(v, plain, "mismatch for {:?}-{:?} vs {:?}-{:?}", a0, a1, b0, b1);
        }
    }

    #[test]
    fn collinear_overlap_and_touch_cases() {
        let (pk, sk_master) = keygen(512, &mut rand::thread_rng());
        let mut mult_oracle = GuardedMult(LocalOracle{ pk: pk.clone(), sk: sk_master.clone() });
        let mut cmp_oracle  = LocalOracle{ pk: pk.clone(), sk: sk_master.clone() };
        let sk_dec = sk_master;

        // Full overlap
        let a = enc_seg(&pk, (0,0), (10,0));
        let b = enc_seg(&pk, (3,0), (7,0));
        let mut ctx = ProtoCtx{ pk:&pk, mult:&mut mult_oracle, cmp:&mut cmp_oracle };
        let e1 = segments_intersect(&a, &b, &mut ctx).unwrap();
        assert_eq!(dec(&sk_dec, &e1) != 0, true);

        // Touch at endpoint
        let a = enc_seg(&pk, (0,0), (10,10));
        let b = enc_seg(&pk, (10,10), (20,0));
        let e2 = segments_intersect(&a, &b, &mut ctx).unwrap();
        assert_eq!(dec(&sk_dec, &e2) != 0, true);

        // Nearly collinear but disjoint
        let a = enc_seg(&pk, (0,0), (10,0));
        let b = enc_seg(&pk, (11,0), (20,0));
        let e3 = segments_intersect(&a, &b, &mut ctx).unwrap();
        let got = dec(&sk_dec, &e3) != 0;
        let want = false;
        if got != want {
            debug_print_deltas_and_flags("collinear_case", &pk, &sk_dec, &a, &b, ctx.mult).ok();
            assert_eq!(got, want);
        }
        //assert_eq!(dec(&sk_dec, &e3) != 0, false);
    }

    #[test]
    fn aabb_prefilter_parity() -> Result<(), Box<dyn std::error::Error>> {
        let (pk, sk_master) = keygen(512, &mut rand::thread_rng());
        let mut oracle1 = LocalOracle{ pk: pk.clone(), sk: sk_master.clone() };
        let mut oracle2 = LocalOracle{ pk: pk.clone(), sk: sk_master.clone() };
        let sk_dec = sk_master;
        let mut rng = rand::thread_rng();

        for _ in 0..150 {
            let a0 = (rng.gen_range(-60..60), rng.gen_range(-60..60));
            let a1 = (rng.gen_range(-60..60), rng.gen_range(-60..60));
            let b0 = (rng.gen_range(-60..60), rng.gen_range(-60..60));
            let b1 = (rng.gen_range(-60..60), rng.gen_range(-60..60));
            let sa = enc_seg(&pk, a0, a1);
            let sb = enc_seg(&pk, b0, b1);

            // with prefilter
            let mut ctx1 = ProtoCtx{ pk:&pk, mult:&mut oracle1, cmp:&mut oracle2 };
            let ov = aabb_overlap(&sa, &sb, &mut ctx1).unwrap();
            let full = segments_intersect(&sa, &sb, &mut ctx1).unwrap();
            // ov & full
            //let ov_full = ctx1.mult.mult_batch(&[(ov.clone(), full.clone())]).unwrap().remove(0);
            let ov_full = mul_ct_ct(ctx1.pk, &ov, &full, ctx1.mult)?;
            let res1 = dec(&sk_dec, &ov_full) != 0;

            // without prefilter (just full)
            let mut ctx2 = ProtoCtx{ pk:&pk, mult:&mut oracle1, cmp:&mut oracle2 };
            let full2 = segments_intersect(&sa, &sb, &mut ctx2).unwrap();
            let res2 = dec(&sk_dec, &full2) != 0;

            assert_eq!(res1, res2, "AABB parity mismatch for {:?}-{:?} vs {:?}-{:?}", a0, a1, b0, b1);
        }
        Ok(())
    }
}
