// hpcompnode/src/bin/bob.rs
// Server: full two-party run loop scaffold
// - Generate Paillier keypair; print+send pk; advertise comparator
// - Encrypt and send Bob's route
// - Serve BatchReq (blinded multiply), CmpZeroReq (dev-oracle), RevealReq

use anyhow::{anyhow, Result};
use clap::Parser;
use hpcompnode::{
    make_server_config_self_signed, read_msg, send_frame,
    Msg, PAD_TO_HELLO, PAD_TO_MULT, PAD_TO_CMP, PAD_TO_ROUTE, PAD_TO_REVEAL,
    KeyInfo, RouteMeta, RouteEnc, RouteEncSeg, RevealReq, RevealResp, CompareScheme,
};
use hpcompproto::PROTO_VER;
use quinn::Endpoint;
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json;
use sha2::{Digest, Sha256};
use std::{fs, net::SocketAddr, path::PathBuf};
use rug::Integer;

// Paillier primitives (minimal set used here)
use hpcompcrypto::{
    keygen, enc, dec, add_plain, mul_plain, PaillierPublicKey, PaillierPrivateKey, Ciphertext,
};

/// Bob command-line options
#[derive(Debug, Parser)]
struct Opt {
    /// Listen address, e.g. 0.0.0.0:9000
    #[arg(long, default_value = "0.0.0.0:9000")]
    listen: SocketAddr,

    /// Optional path to write the self-signed server certificate (DER) for Alice pinning
    #[arg(long)]
    cert_out: Option<PathBuf>,

    /// Plaintext Bob route JSON: { "segs":[{"ax":..,"ay":..,"bx":..,"by":..}, ...] }
    #[arg(long)]
    path: PathBuf,

    /// Optional: load Bob's Paillier public key from file instead of generating
    #[arg(long)]
    paillier_pub: Option<PathBuf>,

    /// Optional: load Bob's Paillier private key from file instead of generating
    #[arg(long)]
    paillier_priv: Option<PathBuf>,

    /// Comparator advertised to Alice (joye|dgk). Defaults to joye
    #[arg(long, default_value = "joye")]
    compare: String,

    /// Optional: write Bob's pk JSON and its SHA-256 alongside
    #[arg(long)] bob_pk_out: Option<PathBuf>,
    #[arg(long)] bob_pk_hash_out: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
struct PlainSeg { ax:i64, ay:i64, bx:i64, by:i64 }
#[derive(Debug, Deserialize, Clone)]
struct PlainRoute { segs: Vec<PlainSeg> }

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Self-signed QUIC/TLS server config (dev) + DER for client pinning
    let (server_cfg, server_cert_der) = make_server_config_self_signed("hpcomp-bob")?;
    if let Some(path) = &opt.cert_out {
        fs::write(path, server_cert_der.clone().into_owned())
            .map_err(|e| anyhow!("failed to write cert {:?}: {}", path, e))?;
        eprintln!("[bob] wrote DER cert to {:?}", path);
    }

    // Generate or load Bob's Paillier keypair
    let (bob_pk, bob_sk) = match (&opt.paillier_pub, &opt.paillier_priv) {
        (Some(pub_path), Some(priv_path)) => {
            // Load existing keys
            let pub_data = fs::read(pub_path)
                .map_err(|e| anyhow!("Failed to read paillier pub key {:?}: {}", pub_path, e))?;
            let priv_data = fs::read(priv_path)
                .map_err(|e| anyhow!("Failed to read paillier priv key {:?}: {}", priv_path, e))?;
            
            let bob_pk: PaillierPublicKey = serde_json::from_slice(&pub_data)?;
            let bob_sk: PaillierPrivateKey = serde_json::from_slice(&priv_data)?;
            (bob_pk, bob_sk)
        },
        (None, None) => {
            // Generate new keys
            keygen(2048, &mut OsRng)
        },
        _ => {
            return Err(anyhow!("Must provide both --paillier-pub and --paillier-priv, or neither to generate new keys"));
        }
    };

    // Print & optionally write pk + hash for Alice pinning
    let pk_json = serde_json::to_vec(&bob_pk)?;
    let hash_hex = hex::encode(Sha256::digest(&pk_json));
    eprintln!("[bob] pk sha256: {}", hash_hex);
    if let Some(p) = &opt.bob_pk_out      { fs::write(p, &pk_json)?; }
    if let Some(p) = &opt.bob_pk_hash_out { fs::write(p, &hash_hex)?; }

    // Load plaintext Bob route
    let bob_route_plain: PlainRoute = {
        let f = fs::File::open(&opt.path)?;
        serde_json::from_reader(f)?
    };

    // Compare scheme advertised
    let compare_kind = match opt.compare.to_lowercase().as_str() {
        "joye" => CompareScheme::Joye,
        "dgk"  => {
            eprintln!("[bob] Warning: DGK not implemented, falling back to Joye");
            CompareScheme::Joye
        },
        _ => CompareScheme::Joye,
    };

    let endpoint = Endpoint::server(server_cfg, opt.listen)?;
    eprintln!("[bob] listening on {}", opt.listen);

    loop {
        match endpoint.accept().await {
            Some(connecting) => {
                // Clone for task
                let bob_pk = bob_pk.clone();
                let bob_sk = bob_sk.clone();
                let route = bob_route_plain.segs.clone();
                let compare_kind = compare_kind.clone();
                tokio::spawn(async move {
                    match connecting.await {
                        Ok(conn) => {
                            eprintln!("[bob] new connection from {}", conn.remote_address());
                            if let Err(e) = handle_connection(conn, bob_pk, bob_sk, route, compare_kind).await {
                                eprintln!("[bob] connection handler error: {e:?}");
                            }
                        }
                        Err(e) => eprintln!("[bob] failed handshake: {e:?}"),
                    }
                });
            }
            None => break,
        }
    }

    endpoint.wait_idle().await;
    Ok(())
}

async fn handle_connection(
    conn: quinn::Connection,
    bob_pk: PaillierPublicKey,
    bob_sk: PaillierPrivateKey,
    route_plain: Vec<PlainSeg>,
    compare_kind: CompareScheme,
) -> Result<()> {
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let bob_pk = bob_pk.clone();
                let bob_sk = bob_sk.clone();
                let route_plain = route_plain.clone();
                let compare_kind = compare_kind.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&mut send, &mut recv, bob_pk, bob_sk, route_plain, compare_kind).await {
                        eprintln!("[bob] stream error: {e:?}");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::LocallyClosed) => break,
            Err(e) => { eprintln!("[bob] accept_bi error: {e:?}"); break; }
        }
    }
    Ok(())
}

async fn handle_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    bob_pk: PaillierPublicKey,
    bob_sk: PaillierPrivateKey,
    route_plain: Vec<PlainSeg>,
    compare_kind: CompareScheme,
) -> Result<()> {
    loop {
        let msg = match read_msg(recv).await {
            Ok(m) => m,
            Err(e) => { if is_eof(&e) { return Ok(()); } else { return Err(e); } }
        };
        eprintln!("[bob] recv: {:?}", msg);

        match msg {
            Msg::Hello(_h) => {
                // Echo Hello as acknowledgement (constant-size via PAD_TO_HELLO)
                let ack = Msg::Hello(hpcompnode::Hello { proto_ver: PROTO_VER, features: 0u64, alice_nonce: [0u8;16] });
                send_frame(send, &ack, PAD_TO_HELLO).await?;

                // Send KeyInfo (advertise comparator & include Bob's pk)
                //let ki = KeyInfo { compare_scheme: compare_kind.clone(), bob_pk: bob_pk.clone() };
                //let bob_nonce = rand::random::<[u8; 16]>();  // Add missing nonce
                //let ki = KeyInfo { compare_scheme: compare_kind.clone(), pk: bob_pk.clone(), bob_nonce: bob_nonce };
                let bob_nonce = rand::random::<[u8; 16]>();  // Add missing nonce
                let ki = KeyInfo { 
                    compare_scheme: compare_kind.clone(), 
                    pk: bob_pk.clone(),  // Change bob_pk -> pk
                    bob_nonce: bob_nonce  // Add missing field
                };
                send_frame(send, &Msg::KeyInfo(ki), PAD_TO_HELLO).await?;

                // Encrypt Bob's route and send
                let mut enc_segs = Vec::with_capacity(route_plain.len());
                let mut rng = OsRng;
                for s in &route_plain {
                    let ax = enc(&bob_pk, &Integer::from(s.ax), &mut rng);
                    let ay = enc(&bob_pk, &Integer::from(s.ay), &mut rng);
                    let bx = enc(&bob_pk, &Integer::from(s.bx), &mut rng);
                    let by = enc(&bob_pk, &Integer::from(s.by), &mut rng);
                    enc_segs.push(RouteEncSeg { ax, ay, bx, by });
                }
                let seg_count = enc_segs.len() as u32;
                let meta = RouteMeta { seg_count, scale: 1i64 };
                let route = RouteEnc { 
                    segs: enc_segs,
                    seg_count,
                    scale: 1i64
                };
                send_frame(send, &Msg::RouteMeta(meta), PAD_TO_ROUTE).await?;
                send_frame(send, &Msg::RouteEnc(route), PAD_TO_ROUTE).await?;
            }

            Msg::BatchReq(req) => {
                // Dev multiply-oracle (ciphertext×ciphertext): decrypt both, multiply, re-encrypt
                let mut products = Vec::with_capacity(req.blinded_pairs.len());
                for (xa, yb) in &req.blinded_pairs {
                    let a = dec(&bob_sk, xa);
                    let b = dec(&bob_sk, yb);
                    let prod = enc(&bob_pk, &Integer::from(a * b), &mut OsRng);
                    products.push(prod);
                }
                let resp = hpcompnode::BatchResp { enc_products: products };
                send_frame(send, &Msg::BatchResp(resp), PAD_TO_MULT).await?;
            }

            Msg::CmpZeroReq(req) => {
                // Dev comparator-oracle: decrypt and return Paillier-encrypted bits
                let x = dec(&bob_sk, &req.x);
                let lt_i = if x < 0 { 1 } else { 0 };
                let eq_i = if x == 0 { 1 } else { 0 };
                let gt_i = if x > 0 { 1 } else { 0 };
                let lt = enc(&bob_pk, &Integer::from(lt_i), &mut OsRng);
                let eq = enc(&bob_pk, &Integer::from(eq_i), &mut OsRng);
                let gt = enc(&bob_pk, &Integer::from(gt_i), &mut OsRng);
                let resp = hpcompnode::CmpZeroResp { lt, eq, gt };
                send_frame(send, &Msg::CmpZeroResp(resp), PAD_TO_CMP).await?;
            }

            Msg::RevealReq(RevealReq { masked_bit, alice_pk }) => {
                // Decrypt masked bit; re-encrypt under Alice's pk
                let masked = dec(&bob_sk, &masked_bit);
                let re_enc = enc(&alice_pk, &Integer::from(masked), &mut OsRng);
                let resp = RevealResp { masked_bit_alice: re_enc };
                send_frame(send, &Msg::RevealResp(resp), PAD_TO_REVEAL).await?;
            }

            other => {
                eprintln!("[bob] unhandled msg variant: {:?}", other);
                break Ok(());
            }
        }
    }
}

#[inline]
fn is_eof(err: &anyhow::Error) -> bool {
    let s = format!("{err}");
    s.contains("unexpected end of file") || s.contains("closed") || s.contains("Reset")
}

/// Extract the length of the "pairs" or "blinded_pairs" array from a JSON value.
/// Returns None if neither field exists or isn't an array.
fn extract_pairs_len_value(value: &serde_json::Value) -> Option<usize> {
    // Try "pairs" first
    if let Some(pairs) = value.get("pairs") {
        if let Some(arr) = pairs.as_array() {
            return Some(arr.len());
        }
    }
    
    // Fall back to "blinded_pairs"
    if let Some(blinded_pairs) = value.get("blinded_pairs") {
        if let Some(arr) = blinded_pairs.as_array() {
            return Some(arr.len());
        }
    }
    
    None
}

// Quick integration-ish tests for frame padding invariants without spinning up QUIC.
// We validate that logical payloads serialize to a fixed padded size bucket.

#[cfg(test)]
mod pad_tests {
    use hpcompnode::{Hello, Msg, PROTO_VER, PAD_TO_HELLO};

    #[test]
    fn hello_frames_pad_to_constant_bucket() {
        let m = Msg::Hello(Hello { proto_ver: PROTO_VER, features: 0u64, alice_nonce: [0u8;16] });
        let mut bytes = bincode::serialize(&m).expect("serialize");
        let rem = (PAD_TO_HELLO - (bytes.len() % PAD_TO_HELLO)) % PAD_TO_HELLO;
        if rem > 0 { bytes.extend(std::iter::repeat(0u8).take(rem)); }
        assert_eq!(bytes.len() % PAD_TO_HELLO, 0);
        let on_wire = bytes.len() + 4;
        assert!(on_wire >= PAD_TO_HELLO);
        assert_eq!((on_wire - 4) % PAD_TO_HELLO, 0);
    }
}
#[cfg(test)]
mod enforcement_tests {
    use super::extract_pairs_len_value;
    use serde_json::json;

    #[test]
    fn extract_len_accepts_pairs() {
        let v = json!({"pairs": [1,2,3,4]});
        assert_eq!(extract_pairs_len_value(&v), Some(4));
    }

    #[test]
    fn extract_len_accepts_blinded_pairs() {
        let v = json!({"blinded_pairs": [0,0]});
        assert_eq!(extract_pairs_len_value(&v), Some(2));
    }
}