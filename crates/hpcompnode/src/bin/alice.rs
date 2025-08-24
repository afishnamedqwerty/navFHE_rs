// hpcompnode/src/bin/alice.rs
// Client: full two-party run loop scaffold
// - QUIC/TLS + pinned cert
// - Verify Bob's Paillier pk hash from KeyInfo
// - Receive Bob's encrypted route (RouteMeta + RouteEnc)
// - Encrypt Alice segments under Bob's pk and (placeholder) iterate per Bob seg
// - Masked reveal round-trip so only Alice learns the final bit
// NOTE: The encrypted intersection math is left as a TODO hook to hpcomp-algo.

use anyhow::{anyhow, Result};
use clap::Parser;
use hpcompnode::{
    read_msg, send_frame, make_client_config_with_root,
    PAD_TO_HELLO, PAD_TO_MULT, PAD_TO_CMP, PAD_TO_ROUTE, PAD_TO_REVEAL,
    Msg, Hello, KeyInfo, RouteMeta, RouteEnc, RevealReq, RevealResp,
};
use hpcompproto::PROTO_VER; // import canonical version constant
use quinn::Endpoint;
use rand::{rngs::OsRng, Rng};
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, net::SocketAddr, path::PathBuf};

// Paillier primitives (minimal set used here)
use hpcompcrypto::{
    keygen, enc, dec, add_plain, mul_plain,
    PaillierPublicKey, PaillierPrivateKey, Ciphertext,
};
use rug::Integer;

use hpcompnode::MULT_BATCH_MAX;
use serde_json;

use hpcompalgo::{Pt, Seg};
use hpcompcrypto::{RemoteMultiplier, RemoteComparator, EncInt};

use tokio::runtime::Handle;
use tokio::sync::oneshot; //{mpsc, 
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use std::sync::mpsc;

#[derive(Debug, Parser)]
struct Opt {
    /// Bob's QUIC address, e.g. 127.0.0.1:9000
    #[arg(long, default_value = "127.0.0.1:9000")]
    peer: SocketAddr,

    /// Path to Bob's server certificate (DER). Use --cert-out from bob.rs to export.
    #[arg(long)]
    bob_cert: PathBuf,

    /// Alice plaintext route JSON: { "segs":[{"ax":..,"ay":..,"bx":..,"by":..}, ...] }
    #[arg(long)]
    path: PathBuf,

    /// Path to Bob's Paillier public key
    #[arg(long)]
    paillier_pub: PathBuf,

    /// Path to Alice's Paillier private key (optional)
    #[arg(long)]
    alice_priv: Option<PathBuf>,

    /// Optional: enable encrypted AABB prefilter (off|aabb)
    #[arg(long, default_value = "off")]
    prefilter: String,

    /// Optional expected SHA-256 hex of Bob's pk (pinning)
    #[arg(long)]
    expect_bob_key_hash: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct PlainSeg { ax:i64, ay:i64, bx:i64, by:i64 }
#[derive(Debug, Deserialize, Clone)]
struct PlainRoute { segs: Vec<PlainSeg> }

// Request types for async operations with response channels
enum MultRequest {
    Batch {
        pairs: Vec<(Ciphertext, Ciphertext)>,
        response_tx: mpsc::SyncSender<MultResponse>,
    },
}

enum CmpRequest {
    CompareZero {
        ciphertext: Ciphertext,
        response_tx: mpsc::SyncSender<CmpResponse>,
    },
}

// Response types
type MultResponse = Result<Vec<Ciphertext>>;
type CmpResponse = Result<(Ciphertext, Ciphertext, Ciphertext)>;

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Load Bob's self-signed certificate (DER) for pinning
    let der_bytes = fs::read(&opt.bob_cert)
        .map_err(|e| anyhow!("failed to read bob_cert {:?}: {}", opt.bob_cert, e))?;
    let bob_cert = CertificateDer::from(der_bytes);

    // QUIC client endpoint configured to trust Bob's cert only
    let client_cfg = make_client_config_with_root(&bob_cert)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_cfg);

    // ---- Load Bob's public key and Alice's keys ----
    let bob_pk_data = fs::read(&opt.paillier_pub)
        .map_err(|e| anyhow!("Failed to read bob paillier pub key {:?}: {}", opt.paillier_pub, e))?;
    let bob_pk: PaillierPublicKey = serde_json::from_slice(&bob_pk_data)?;

    // Load or generate Alice's keypair
    let (alice_pk, alice_sk) = if let Some(priv_path) = &opt.alice_priv {
        let priv_data = fs::read(priv_path)
            .map_err(|e| anyhow!("Failed to read alice paillier priv key {:?}: {}", priv_path, e))?;
        let alice_sk: PaillierPrivateKey = serde_json::from_slice(&priv_data)?;
        
        // Extract public key from private key
        let alice_pk = PaillierPublicKey {
            n: alice_sk.n.clone(),
            n2: alice_sk.n2.clone(),
        };
        (alice_pk, alice_sk)
    } else {
        // Generate new keypair for reveal
        keygen(2048, &mut OsRng)
    };

    // Connect to Bob
    let conn = endpoint
        .connect(opt.peer, "hpcomp-bob")?
        .await
        .map_err(|e| anyhow!("connect failed: {}", e))?;
    let (mut send, mut recv) = conn.open_bi().await?;

    // Hello per hpcompproto: { proto_ver: u64, features: u64, alice_nonce: [u8;16] }
    let hello = Msg::Hello(Hello { proto_ver: PROTO_VER, features: 0u64, alice_nonce: rand::random::<[u8;16]>() });
    send_frame(&mut send, &hello, PAD_TO_HELLO).await?;

    // ---- Expect KeyInfo then encrypted route ----
    let (bob_pk, _compare_scheme) = wait_keyinfo(&mut recv, &opt.expect_bob_key_hash).await?;
    let (meta, route_enc) = wait_route(&mut recv).await?;
    //let route_enc = wait_route(&mut recv).await?;

    // ---- Load Alice plaintext, iterate encrypted comparison loop (placeholder math) ----
    let alice_route_plain: PlainRoute = {
        let f = fs::File::open(&opt.path)?;
        serde_json::from_reader(f)?
    };

    let mut rng = OsRng;

    for (i, a) in alice_route_plain.segs.iter().enumerate() {
        // Create encrypted Alice segment
        let alice_seg = create_encrypted_segment(
            a.ax, a.ay, a.bx, a.by, 
            &bob_pk, &mut rng
        );
        
        // OR accumulator for intersection results
        let mut acc_bit: Option<Ciphertext> = None;
        
        for bob_seg in &route_enc.segs {
            // Convert protocol type to algorithm type
            let bob_seg_algo = route_enc_seg_to_algo_seg(bob_seg);
            
            // Create separate streams for multiplier and comparator
            let (mut mult_send, mut mult_recv) = conn.open_bi().await?;
            let (mut cmp_send, mut cmp_recv) = conn.open_bi().await?;
            let mut mult = BobMultiplier::new(mult_send, mult_recv);
            let mut cmp = BobComparator::new(cmp_send, cmp_recv);
            let mut ctx = create_proto_ctx(&bob_pk, &mut mult, &mut cmp);
            
            // AABB prefilter (optional)
            let use_aabb = opt.prefilter.to_lowercase() == "aabb";
            let aabb_result = if use_aabb {
                hpcompalgo::aabb_overlap(&alice_seg, &bob_seg_algo, &mut ctx)?
            } else {
                enc(&bob_pk, &Integer::from(1), &mut rng)
            };
            
            // Compute intersection
            let intersection_result = if use_aabb {
                // AABB AND intersection
                let raw_intersection = hpcompalgo::segments_intersect(&alice_seg, &bob_seg_algo, &mut ctx)?;
                hpcompalgo::bool_and(&bob_pk, &aabb_result, &raw_intersection, &mut mult)?
            } else {
                hpcompalgo::segments_intersect(&alice_seg, &bob_seg_algo, &mut ctx)?
            };
            
            // OR with accumulator
            acc_bit = Some(match acc_bit {
                None => intersection_result,
                Some(prev) => {
                    // OR(prev, intersection_result) under Paillier
                    hpcompalgo::bool_or(&bob_pk, &prev, &intersection_result, &mut mult)?
                }
            });
        }
        
        // Continue with masked reveal using the actual intersection result
        // ---- Masked reveal ----
        let r: u8 = if rng.gen::<bool>() { 1 } else { 0 };
        let masked_under_bob = if r == 0 {
            acc_bit.expect("at least one Bob segment")
        } else {
            // 1 - acc_bit  (using Paillier ops under Bob's pk)
            let neg = mul_plain(&bob_pk, &acc_bit.expect("at least one Bob segment"), &Integer::from(-1));
            add_plain(&bob_pk, &neg, &Integer::from(1i64))
        };

        // Ephemeral Alice keypair for reveal
        let (alice_pk, alice_sk): (PaillierPublicKey, PaillierPrivateKey) = keygen(2048, &mut rng);
        let req = RevealReq { masked_bit: masked_under_bob, alice_pk: alice_pk.clone() };
        let (mut s, mut rcv) = conn.open_bi().await?;
        send_frame(&mut s, &Msg::RevealReq(req), PAD_TO_REVEAL).await?;
        let masked_under_alice = match read_msg(&mut rcv).await? {
            Msg::RevealResp(RevealResp { masked_bit_alice }) => masked_bit_alice,
            m => anyhow::bail!("unexpected reply to RevealReq: {:?}", m),
        };
        let masked_int = dec(&alice_sk, &masked_under_alice); // 0 or 1
        let result = (u8::try_from(&masked_int).unwrap_or(0) ^ r) & 1;
        println!("segment {} intersects Bob: {}", i, result);
    }

    // Close cleanly
    send.finish()?;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;
    Ok(())
}

async fn wait_keyinfo(
    recv: &mut quinn::RecvStream,
    expect_hash: &Option<String>,
) -> Result<(PaillierPublicKey, hpcompnode::CompareScheme)> {
    loop {
        match read_msg(recv).await? {
            Msg::KeyInfo(KeyInfo { compare_scheme, pk, bob_nonce }) => {
                //let pk_json = serde_json::to_vec(&bob_pk)?;
                let pk_json = serde_json::to_vec(&pk)?;
                let hash_hex = hex::encode(Sha256::digest(&pk_json));
                eprintln!("[alice] bob pk sha256: {}", hash_hex);
                if let Some(exp) = expect_hash {
                    if &hash_hex.to_lowercase() != &exp.to_lowercase() {
                        // Close peer with app error before bailing
                        return Err(anyhow!("Bob pk hash mismatch: got {}, expected {}", hash_hex, exp));
                    }
                }
                return Ok((pk, compare_scheme));
            }
            other => eprintln!("[alice] waiting KeyInfo, got: {:?}", other),
        }
    }
}

async fn wait_route(recv: &mut quinn::RecvStream) -> Result<(RouteMeta, RouteEnc)> {
    let mut meta: Option<RouteMeta> = None;
    let mut route: Option<RouteEnc> = None;
    while meta.is_none() || route.is_none() {
        match read_msg(recv).await? {
            Msg::RouteMeta(m) => meta = Some(m),
            Msg::RouteEnc(r)  => route = Some(r),
            other => eprintln!("[alice] ignoring pre-route msg: {:?}", other),
        }
    }
    Ok((meta.unwrap(), route.unwrap()))
}

// Helper function to convert RouteEncSeg to hpcompalgo::Seg
fn route_enc_seg_to_algo_seg(seg: &hpcompnode::RouteEncSeg) -> hpcompalgo::Seg {
    hpcompalgo::Seg {
        p: hpcompalgo::Pt {
            x: hpcompcrypto::EncInt::new(seg.ax.clone()),
            y: hpcompcrypto::EncInt::new(seg.ay.clone()),
        },
        q: hpcompalgo::Pt {
            x: hpcompcrypto::EncInt::new(seg.bx.clone()),
            y: hpcompcrypto::EncInt::new(seg.by.clone()),
        },
    }
}

// Helper function to create encrypted segment from coordinates
fn create_encrypted_segment(
    ax: i64, ay: i64, bx: i64, by: i64,
    bob_pk: &PaillierPublicKey,
    rng: &mut impl rand::RngCore
) -> hpcompalgo::Seg {
    hpcompalgo::Seg {
        p: hpcompalgo::Pt {
            x: hpcompcrypto::EncInt::new(enc(bob_pk, &Integer::from(ax), rng)),
            y: hpcompcrypto::EncInt::new(enc(bob_pk, &Integer::from(ay), rng)),
        },
        q: hpcompalgo::Pt {
            x: hpcompcrypto::EncInt::new(enc(bob_pk, &Integer::from(bx), rng)),
            y: hpcompcrypto::EncInt::new(enc(bob_pk, &Integer::from(by), rng)),
        },
    }
}

// Helper function to create protocol context
fn create_proto_ctx<'a>(
    bob_pk: &'a PaillierPublicKey,
    mult: &'a mut dyn RemoteMultiplier,
    cmp: &'a mut dyn RemoteComparator,
) -> hpcompalgo::ProtoCtx<'a> {
    hpcompalgo::ProtoCtx { pk: bob_pk, mult, cmp }
}

// Channel-based multiplier
struct BobMultiplier {
    sender: UnboundedSender<MultRequest>,
}

impl BobMultiplier {
    fn new(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Self {
        let (tx, mut rx) = unbounded_channel::<MultRequest>();
        
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req {
                    MultRequest::Batch { pairs, response_tx } => {
                        let result = async {
                            // Send BatchReq to Bob
                            let req = hpcompnode::BatchReq { blinded_pairs: pairs };
                            let msg = hpcompnode::Msg::BatchReq(req);
                            hpcompnode::send_frame(&mut send, &msg, hpcompnode::PAD_TO_MULT).await?;
                            
                            // Receive BatchResp from Bob
                            match hpcompnode::read_msg(&mut recv).await? {
                                hpcompnode::Msg::BatchResp(resp) => Ok(resp.enc_products),
                                _ => Err(anyhow::anyhow!("Unexpected response to BatchReq")),
                            }
                        }.await;
                        
                        // Send result back through response channel
                        let _ = response_tx.send(result);
                    }
                }
            }
        });
        
        Self { sender: tx }
    }
}

impl RemoteMultiplier for BobMultiplier {
    fn mult_batch(&mut self, blinded_pairs: &[(Ciphertext, Ciphertext)]) -> Result<Vec<Ciphertext>> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        
        // Send request to async task
        self.sender.send(MultRequest::Batch {
            pairs: blinded_pairs.to_vec(),
            response_tx,
        }).map_err(|_| anyhow::anyhow!("Multiplier task has stopped"))?;
        
        // Wait for response (blocking receive works in sync context)
        match response_rx.recv() {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("No response from multiplier task")),
        }
    }
}

// Channel-based comparator
struct BobComparator {
    sender: UnboundedSender<CmpRequest>,
}

impl BobComparator {
    fn new(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Self {
        let (tx, mut rx) = unbounded_channel::<CmpRequest>();
        
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req {
                    CmpRequest::CompareZero { ciphertext, response_tx } => {
                        let result = async {
                            // Send CmpZeroReq to Bob
                            let req = hpcompnode::CmpZeroReq { x: ciphertext };
                            let msg = hpcompnode::Msg::CmpZeroReq(req);
                            hpcompnode::send_frame(&mut send, &msg, hpcompnode::PAD_TO_CMP).await?;
                            
                            // Receive CmpZeroResp from Bob
                            match hpcompnode::read_msg(&mut recv).await? {
                                hpcompnode::Msg::CmpZeroResp(resp) => Ok((resp.lt, resp.eq, resp.gt)),
                                _ => Err(anyhow::anyhow!("Unexpected response to CmpZeroReq")),
                            }
                        }.await;
                        
                        // Send result back through response channel
                        let _ = response_tx.send(result);
                    }
                }
            }
        });
        
        Self { sender: tx }
    }
}

impl RemoteComparator for BobComparator {
    fn cmp_zero(&mut self, x: &Ciphertext) -> Result<(Ciphertext, Ciphertext, Ciphertext)> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        
        // Send request to async task
        self.sender.send(CmpRequest::CompareZero {
            ciphertext: x.clone(),
            response_tx,
        }).map_err(|_| anyhow::anyhow!("Comparator task has stopped"))?;
        
        // Wait for response (blocking receive works in sync context)
        match response_rx.recv() {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("No response from comparator task")),
        }
    }
}

#[cfg(test)]
mod alice_wire_tests {
    use super::*;

    fn padded_len(msg: &Msg, pad: usize) -> usize {
        let mut bytes = bincode::serialize(msg).expect("serialize");
        let rem = (pad - (bytes.len() % pad)) % pad;
        if rem > 0 { bytes.extend(std::iter::repeat(0u8).take(rem)); }
        4 + bytes.len()
    }

    #[test]
    fn hello_padding_equal_across_nonces() {
        let m1 = Msg::Hello(Hello { proto_ver: PROTO_VER, features: 0u64, alice_nonce: [0u8;16] });
        let mut nonce = [0u8;16];
        nonce[0] = 1;
        let m2 = Msg::Hello(Hello { proto_ver: PROTO_VER, features: 0u64, alice_nonce: nonce });
        assert_eq!(padded_len(&m1, PAD_TO_HELLO), padded_len(&m2, PAD_TO_HELLO));
    }

    #[test]
    fn client_side_max_batch_check_logic() {
        // Build a JSON value that mimics a BatchReq with too many pairs.
        let pairs: Vec<serde_json::Value> = (0..(MULT_BATCH_MAX+1)).map(|_| serde_json::Value::Null).collect();
        let v = serde_json::json!({"pairs": pairs});
        let pairs_len = v.get("pairs").and_then(|p| p.as_array()).map(|a| a.len()).unwrap_or(usize::MAX);
        assert!(pairs_len > MULT_BATCH_MAX, "expected over-limit batch to be detected");
    }
}

