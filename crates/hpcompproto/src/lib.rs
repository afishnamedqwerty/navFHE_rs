
use serde::{Serialize, Deserialize};
use hpcompcrypto::{PaillierPublicKey, Ciphertext};
use rug::integer::Order;
use rug::Integer;
use bincode;

pub const PROTO_VER: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct JoyeParamsSerde(
    #[serde(with = "joye_params_v1")] 
    pub hpcompcrypto::compare::JoyeParams
);

// Optional: opaque Debug so messages remain Debug-printable
impl core::fmt::Debug for JoyeParamsSerde {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JoyeParamsSerde(<opaque>)")
    }
}

// Mirror we serialize on the wire. Integers as big-endian byte arrays.
#[derive(serde::Serialize, serde::Deserialize)]
struct JoyeParamsMirror {
    // Big-endian encodings for big integers
    n: Vec<u8>,
    gamma: Vec<u8>,
    beta: Vec<u8>,
    // Small parameter (example)
    t: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hello {
    pub proto_ver: u32,
    pub features: u64,
    pub alice_nonce: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    pub pk: PaillierPublicKey,
    pub compare_scheme: CompareScheme,
    pub bob_nonce: [u8; 16],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompareScheme {
    DevOracle,
    Joye, // scaffold
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteMeta {
    pub seg_count: u32,
    pub scale: i64, // fixed-point scale
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteEncSeg {
    pub ax: hpcompcrypto::Ciphertext,
    pub ay: hpcompcrypto::Ciphertext,
    pub bx: hpcompcrypto::Ciphertext,
    pub by: hpcompcrypto::Ciphertext,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteEnc {
    pub segs: Vec<RouteEncSeg>,
//}

    pub seg_count: u32,
    pub scale: i64, // fixed-point scale
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchReq {
    pub blinded_pairs: Vec<(Ciphertext, Ciphertext)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchResp {
    pub enc_products: Vec<Ciphertext>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CmpZeroReq {
    pub x: Ciphertext,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CmpZeroResp {
    // Encrypted bits (lt, eq, gt) under Bob's Paillier
    pub lt: Ciphertext,
    pub eq: Ciphertext,
    pub gt: Ciphertext,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RevealReq {
    pub masked_bit: hpcompcrypto::Ciphertext, // under Bob's PK
    pub alice_pk: hpcompcrypto::PaillierPublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevealResp {
    pub masked_bit_alice: hpcompcrypto::Ciphertext, // under Alice's PK
}

#[derive(Serialize, Deserialize)]
pub struct JoyeCmpReq {
    pub params: JoyeParamsSerde,//hpcompcrypto::compare::JoyeParams,
    pub c_masked: hpcompcrypto::Ciphertext, // Enc_B(x+r)
    // (Optional) extra blinded helpers if you add constant-time equality paths
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JoyeCmpResp {
    pub y_low: hpcompcrypto::Ciphertext,    // Enc_B((x+r) mod 2^t)
    // optional helpers
}

// these must produce a stable encoding
fn joye_params_to_bytes(p: &hpcompcrypto::compare::JoyeParams) -> Vec<u8> {
    // Envelope: "JOYEPARAMS" | version=1 | t | slack   (all big-endian u32s)
    let mut out = Vec::with_capacity(10 + 4 + 4 + 4);
    out.extend_from_slice(b"JOYEPARAMS");        // 10-byte tag
    out.extend_from_slice(&1u32.to_be_bytes());  // version 1
    out.extend_from_slice(&p.t.to_be_bytes());
    out.extend_from_slice(&p.slack.to_be_bytes());
    out
}

fn joye_params_from_bytes(bytes: &[u8]) -> anyhow::Result<hpcompcrypto::compare::JoyeParams> {
    use anyhow::bail;

    let mut cur = bytes;
    fn take<'a>(buf: &mut &'a [u8], n: usize) -> anyhow::Result<&'a [u8]> {
        if buf.len() < n { anyhow::bail!("short input"); }
        let (h, t) = buf.split_at(n);
        *buf = t;
        Ok(h)
    }

    let tag = take(&mut cur, 10)?; // "JOYEPARAMS"
    if tag != b"JOYEPARAMS" { bail!("bad JoyeParams tag"); }

    let ver = u32::from_be_bytes(take(&mut cur, 4)?.try_into().unwrap());
    if ver != 1 { bail!("unsupported JoyeParams version: {ver}"); }

    let t     = u32::from_be_bytes(take(&mut cur, 4)?.try_into().unwrap());
    let slack = u32::from_be_bytes(take(&mut cur, 4)?.try_into().unwrap());

    Ok(hpcompcrypto::compare::JoyeParams { t, slack })
}


mod joye_params_v1 {
    use super::*;
    use serde::{Serializer, Deserializer};
    use serde::de::Error as DeError;

    pub fn serialize<S>(
        jp: &hpcompcrypto::compare::JoyeParams,
        s: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = joye_params_to_bytes(jp);
        // encode as bytes in the message
        s.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(
        d: D,
    ) -> Result<hpcompcrypto::compare::JoyeParams, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: std::borrow::Cow<'de, [u8]> = serde::de::Deserialize::deserialize(d)?;
        joye_params_from_bytes(&bytes).map_err(D::Error::custom)
    }
}


enum Msg {
  // ...
  JoyeCmpReq(JoyeCmpReq),
  JoyeCmpResp(JoyeCmpResp),
}

#[test]
fn roundtrip_joyeparams_v1() {
    let jp0 = hpcompcrypto::compare::JoyeParams { t: 31, slack: 48 };
    let bytes = joye_params_to_bytes(&jp0);
    let jp1 = joye_params_from_bytes(&bytes).unwrap();
    assert_eq!(jp0.t, jp1.t);
    assert_eq!(jp0.slack, jp1.slack);
}


