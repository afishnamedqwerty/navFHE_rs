//! hpcomp-crypto: Minimal Paillier implementation, ciphertext utilities,
//! and client-side helpers for interactive multiplication and comparison.
//!
//! SECURITY NOTE: Comparison backend is **scaffolded**; a dev-oracle mode is
//! available for bring-up and testing but **leaks** sign info to Bob.

use anyhow::{anyhow, Result};
use rand::RngCore;
use rug::integer::Order;
use rug::{Assign, Integer};
use serde::{Deserialize, Serialize};

// ---------------- Paillier core ----------------

pub mod compare;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    #[serde(with = "serde_bytes")]
    pub n: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub n2: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierPrivateKey {
    #[serde(with = "serde_bytes")]
    pub lambda: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub mu: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub n: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub n2: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncBool {
    pub c: Ciphertext,
}

impl PaillierPublicKey {
    pub fn n(&self) -> Integer {
        int_from_be(&self.n)
    }
    pub fn n2(&self) -> Integer {
        int_from_be(&self.n2)
    }
}
impl PaillierPrivateKey {
    pub fn n(&self) -> Integer {
        int_from_be(&self.n)
    }
    pub fn n2(&self) -> Integer {
        int_from_be(&self.n2)
    }
    pub fn lambda(&self) -> Integer {
        int_from_be(&self.lambda)
    }
    pub fn mu(&self) -> Integer {
        int_from_be(&self.mu)
    }
}

#[inline]
fn int_from_be(bytes: &[u8]) -> Integer {
    Integer::from_digits(bytes, Order::MsfBe)
}

#[inline]
fn int_to_be(i: &Integer) -> Vec<u8> {
    i.to_digits::<u8>(Order::MsfBe)
}

pub fn rand_int_bits(bits: usize) -> Integer {
    // returns a non-negative Integer uniformly in [0, 2^bits)
    let nbytes = (bits + 7) / 8;
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
    Integer::from_digits(&bytes, Order::MsfBe)
}

pub fn keygen(
    bits: u32,
    rng: &mut impl rand::RngCore,
) -> (PaillierPublicKey, PaillierPrivateKey) {
    use rug::integer::IsPrime;
    let half = bits / 2;
    let mut gen_prime = |bits: u32| -> Integer {
        loop {
            let mut bytes = vec![0u8; (bits as usize + 7) / 8];
            rng.fill_bytes(&mut bytes);
            // force top bit and odd
            if let Some(b) = bytes.first_mut() {
                *b |= 0x80;
            }
            if let Some(b) = bytes.last_mut() {
                *b |= 1;
            }
            let mut p = Integer::from_digits(&bytes, Order::MsfBe);
            //let mut p = int_from_be(&bytes);
            p.next_prime_mut();
            if p.is_probably_prime(25) != IsPrime::No {
                return p;
            }
        }
    };
    let p = gen_prime(half);
    let q = gen_prime(half);
    // let n = &p * &q;
    let n: Integer = (&p * &q).into();
    //let n2 = Integer::from(&n * &n);
    let n2: Integer = (&n * &n).into();
    let lambda = lcm(&(p.clone() - 1), &(q.clone() - 1));
    //let g = n.clone() + 1; // standard Paillier g = n+1
    let g: Integer = {
        let mut tmp = n.clone();
        tmp += 1;
        tmp
    };
    /*let mu = {
        // mu = (L(g^lambda mod n^2))^{-1} mod n
        let mut gl = g.pow_mod(&lambda, &n2).unwrap();
        let l = L(&mut gl, &n);
        let mu = l.invert(&n).expect("invert exists");
        mu
    };
    let pk = PaillierPublicKey { n: n.to_digits::<u8>(rug::integer::Order::MsfBe),
                                 n2: n2.to_digits::<u8>(rug::integer::Order::MsfBe) };
    let sk = PaillierPrivateKey { lambda: lambda.to_digits::<u8>(rug::integer::Order::MsfBe),
                                  mu: mu.to_digits::<u8>(rug::integer::Order::MsfBe),
                                  n: pk.n.clone(),
                                  n2: pk.n2.clone() };
    (pk, sk)*/
    let mut gl: Integer = g.pow_mod(&lambda, &n2).unwrap();
    let l_val = L(&mut gl, &n);
    let mu = l_val.invert(&n).expect("invert exists");

    // store bytes
    let pk = PaillierPublicKey {
        n: int_to_be(&n),
        n2: int_to_be(&n2),
    };
    let sk = PaillierPrivateKey {
        lambda: int_to_be(&lambda),
        mu: int_to_be(&mu),
        n: pk.n.clone(),
        n2: pk.n2.clone(),
    };
    (pk, sk)
}

fn L(x: &mut Integer, n: &Integer) -> Integer {
    // L(u) = (u - 1) / n
    //let mut t = Integer::from(x);
    let mut t = x.clone();
    t -= 1;
    t / n
}

fn gcd(mut a: Integer, mut b: Integer) -> Integer {
    while b != 0 {
        let r: Integer = (&a % &b).into();
        a = b;
        b = r;
    }
    a
}

fn lcm(a: &Integer, b: &Integer) -> Integer {
    //(a * b) / a.gcd_ref(b).into_owned()
    let g = gcd(a.clone(), b.clone());
    let prod: Integer = (a * b).into();
    prod / g
}

pub fn enc(pk: &PaillierPublicKey, m: &Integer, rng: &mut impl rand::RngCore) -> Ciphertext {
    let n = pk.n();
    let n2 = pk.n2();
    let mut r_bytes = vec![0u8; (n.significant_bits() as usize + 7) / 8];
    rng.fill_bytes(&mut r_bytes);
    let mut r = Integer::from_digits(&r_bytes, Order::MsfBe);
    //let mut r = int_from_be(&r_bytes);
    r %= &n;
    if r == 0 {
        r.assign(1);
    }
    //let g = &n + 1;
    let g: Integer = {
        let mut t = n.clone();
        t += 1;
        t
    };
    let c = (g.pow_mod(m, &n2).unwrap() * r.pow_mod(&n, &n2).unwrap()) % n2;
    Ciphertext(c.to_digits::<u8>(Order::MsfBe))
}

pub fn dec(sk: &PaillierPrivateKey, c: &Ciphertext) -> Integer {
    let n = sk.n();
    let n2 = sk.n2();
    //let mut ci = Integer::from(c.0.as_slice());
    let mut ci = int_from_be(&c.0);
    let mut u = ci.pow_mod(&sk.lambda(), &n2).unwrap();
    let l = L(&mut u, &n);
    //let mut m = (l * sk.mu()) % &n;
    //m
    (l * sk.mu()) % &n
}

pub fn add(pk: &PaillierPublicKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    let n2 = pk.n2();
    //let ai = Integer::from(a.0.as_slice());
    //let bi = Integer::from(b.0.as_slice());
    let ai = int_from_be(&a.0);
    let bi = int_from_be(&b.0);
    Ciphertext(((ai * bi) % n2).to_digits::<u8>(Order::MsfBe))
}

pub fn add_plain(pk: &PaillierPublicKey, a: &Ciphertext, k: &Integer) -> Ciphertext {
    let n = pk.n();
    let n2 = pk.n2();
    //let ai = Integer::from(a.0.as_slice());
    let ai = int_from_be(&a.0);
    //let g = &n + 1;
    let g: Integer = {
        let mut t = n.clone();
        t += 1;
        t
    };
    let ek = g.pow_mod(k, &n2).unwrap();
    Ciphertext(((ai * ek) % n2).to_digits::<u8>(Order::MsfBe))
}

pub fn mul_plain(pk: &PaillierPublicKey, a: &Ciphertext, k: &Integer) -> Ciphertext {
    let n2 = pk.n2();
    //let mut ai = Integer::from(a.0.as_slice());
    let mut ai = int_from_be(&a.0);
    // exponentiate by k modulo n^2 (handles negative via mod n)
    let mut kk = k.clone();
    if kk.is_negative() {
        let n = pk.n();
        kk = (kk % &n + &n) % &n;
    }
    ai.pow_mod_mut(&kk, &n2).unwrap();
    Ciphertext(ai.to_digits::<u8>(Order::MsfBe))
}

pub fn rerandomize(
    pk: &PaillierPublicKey,
    a: &Ciphertext,
    rng: &mut dyn rand::RngCore,
) -> Ciphertext {
    let n = pk.n();
    let n2 = pk.n2();
    let mut r_bytes = vec![0u8; (n.significant_bits() as usize + 7) / 8];
    rng.fill_bytes(&mut r_bytes);
    //let mut r = Integer::from(r_bytes.as_slice());
    let mut r = int_from_be(&r_bytes);
    r %= &n;
    if r == 0 {
        r.assign(1);
    }
    let ri = r.pow_mod(&n, &n2).unwrap();
    //let ai = Integer::from(a.0.as_slice());
    let ai = int_from_be(&a.0);
    Ciphertext(((ai * ri) % n2).to_digits::<u8>(rug::integer::Order::MsfBe))
}

pub fn enc_const(pk: &PaillierPublicKey, k: i64) -> Ciphertext {
    enc(pk, &Integer::from(k), &mut rand::thread_rng())
}

pub fn hash_key(pk: &PaillierPublicKey) -> String {
    let mut h = blake3::Hasher::new();
    h.update(&pk.n);
    h.update(&pk.n2);
    h.finalize().to_hex().to_string()
}

// ------------- Protocol helper traits -------------

/// Interface for sending blinded pairs to a counterpart (Bob) for
/// ciphertext×ciphertext multiplication.
pub trait RemoteMultiplier {
    fn mult_batch(&mut self, blinded_pairs: &[(Ciphertext, Ciphertext)])
        -> Result<Vec<Ciphertext>>;
}

/// Interface for (privately) comparing an encrypted integer against zero,
/// returning encrypted indicator bits. In dev-oracle, Bob learns the sign.
pub trait RemoteComparator {
    fn cmp_zero(&mut self, x: &Ciphertext) -> Result<(Ciphertext, Ciphertext, Ciphertext)>; // (lt, eq, gt) as EncBool
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncInt {
    pub c: Ciphertext,
}

impl EncInt {
    pub fn new(c: Ciphertext) -> Self {
        Self { c }
    }
    pub fn add(&self, pk: &PaillierPublicKey, other: &EncInt) -> EncInt {
        EncInt::new(add(pk, &self.c, &other.c))
    }
    pub fn add_plain(&self, pk: &PaillierPublicKey, k: &Integer) -> EncInt {
        EncInt::new(add_plain(pk, &self.c, k))
    }
    pub fn mul_plain(&self, pk: &PaillierPublicKey, k: &Integer) -> EncInt {
        EncInt::new(mul_plain(pk, &self.c, k))
    }
    pub fn rerand(&self, pk: &PaillierPublicKey, rng: &mut dyn rand::RngCore) -> EncInt {
        EncInt::new(rerandomize(pk, &self.c, rng))
    }
}

/// Client-side blinding for secure multiplication.
pub fn blind_pair(
    pk: &PaillierPublicKey,
    x: &EncInt,
    y: &EncInt,
    a: &Integer,
    b: &Integer,
) -> (Ciphertext, Ciphertext) {
    let enc_a = enc(pk, a, &mut rand::thread_rng());
    let enc_b = enc(pk, b, &mut rand::thread_rng());
    let xa = add(pk, &x.c, &enc_a);
    let yb = add(pk, &y.c, &enc_b);
    (xa, yb)
}

/// Client-side unblinding: given J(x+a)(y+b)K plus JxK,JyK and (a,b), compute JxyK.
pub fn unblind_product(
    pk: &PaillierPublicKey,
    x: &EncInt,
    y: &EncInt,
    prod_blinded: &Ciphertext,
    a: &Integer,
    b: &Integer,
) -> EncInt {
    // JxyK = J(x+a)(y+b)K ⊕ (−b)⊗JxK ⊕ (−a)⊗JyK ⊕ J(−ab)K
    /*let nb = Integer::from(-b);
    let na = Integer::from(-a);
    let nab = Integer::from(-a * b);
    let term1 = EncInt::new(prod_blinded.clone());
    let term2 = x.mul_plain(pk, &nb);
    let term3 = y.mul_plain(pk, &na);
    let term4 = EncInt::new(add_plain(pk, &enc(pk, &Integer::from(0), &mut rand::thread_rng()), &nab));
    let tmp = term1.add(pk, &term2).add(pk, &term3).add(pk, &term4);*/
    // nb = -b ; na = -a ; nab = -(a*b)
    let nb: Integer = (-(b)).into();
    let na: Integer = (-(a)).into();
    let ab: Integer = (a * b).into();
    let nab: Integer = (-(ab)).into();

    let term1 = EncInt::new(prod_blinded.clone());
    let term2 = x.mul_plain(pk, &nb);
    let term3 = y.mul_plain(pk, &na);

    // J(−ab)K
    let term4 = EncInt::new(add_plain(
        pk,
        &enc(pk, &Integer::from(0), &mut rand::thread_rng()),
        &nab,
    ));

    let tmp = term1.add(pk, &term2).add(pk, &term3).add(pk, &term4);
    tmp
}

// --- Simple JSON (de)serialization helpers for keys ---

pub fn save_json<T: Serialize>(path: &str, value: &T) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}
pub fn load_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    let data = std::fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

// ------------------- Tests -------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    // Canonical modulo: returns z in [0, n-1]
    fn mod_n(mut z: Integer, n: &Integer) -> Integer {
        z %= n;
        if z.is_negative() {
            z += n;
        }
        z
    }

    #[test]
    fn paillier_add_mul_plain_roundtrip() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen(512, &mut rng);
        let n = pk.n();

        for _ in 0..50 {
            let a: i64 = rng.gen_range(-1_000_000..1_000_000);
            let b: i64 = rng.gen_range(-1_000_000..1_000_000);
            let ca = enc(&pk, &Integer::from(a), &mut rng);
            let cb = enc(&pk, &Integer::from(b), &mut rng);
            // Homomorphic add: Dec(E(a) * E(b)) == (a + b) mod n
            let sum_dec = dec(&sk, &add(&pk, &ca, &cb));
            let sum_exp = mod_n(Integer::from(a) + Integer::from(b), &n);
            assert_eq!(sum_dec, sum_exp, "add: Dec(E(a)+E(b)) != (a+b) mod n");
            // let s = dec(&sk, &add(&pk, &ca, &cb)).to_i64().unwrap();
            //assert_eq!(s, (a + b).rem_euclid(Integer::from_bytes_be(rug::integer::Order::MsfBe, &pk.n).to_i64().unwrap() as i64));
            //assert_eq!(s, (a + b).rem_euclid(int_from_be(&pk.n).to_i64().unwrap() as i64));
            // Scalar multiply: Dec(E(a)^k) == (a * k) mod n
            let k: i64 = rng.gen_range(-1000..1000);
            let prod_dec = dec(&sk, &mul_plain(&pk, &ca, &Integer::from(k)));
            let prod_exp = mod_n(Integer::from(a) * Integer::from(k), &n);
            assert_eq!(prod_dec, prod_exp, "mul_plain: Dec(E(a)^k) != (a*k) mod n");
            //let p = dec(&sk, &mul_plain(&pk, &ca, &Integer::from(k))).to_i64().unwrap();
            //assert_eq!(p, (a * k) % Integer::from_digits(&pk.n, rug::integer::Order::MsfBe));
        }
    }

    #[test]
    fn blind_unblind_product() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen(512, &mut rng);
        let n = pk.n();

        let x = Integer::from(12345);
        let y = Integer::from(-54321);
        let ex = EncInt::new(enc(&pk, &x, &mut rng));
        let ey = EncInt::new(enc(&pk, &y, &mut rng));
        // fresh, non-trivial blinders (can be negative)
        let a = Integer::from(777);
        let b = Integer::from(-333);
        let (xa, yb) = blind_pair(&pk, &ex, &ey, &a, &b);
        // Bob multiplies plaintexts of the blinded cts:
        let xb_p = dec(&sk, &xa);
        let yb_p = dec(&sk, &yb);
        let prod_blinded = Integer::from(&xb_p * &yb_p).into();
        let enc_prod_blinded = enc(&pk, &prod_blinded, &mut rng);
        // Alice unblinds -> should equal E(x*y)
        let xy_enc = unblind_product(&pk, &ex, &ey, &enc_prod_blinded, &a, &b);
        let xy_dec = dec(&sk, &xy_enc.c);
        let xy_exp = mod_n(((&x * &y).into()), &n);
        assert_eq!(xy_dec, xy_exp, "unblind_product: Dec != (x*y) mod n");
    }
}
