// hpcompnode/src/lib.rs
//! Shared networking utilities for hpcompnode (Alice/Bob):
//! - QUIC/TLS setup (self-signed for dev; root-pinned client)
//! - Length-prefixed, padded frames
//! - Shared `Msg` envelope for RPC between Alice and Bob

use anyhow::{anyhow, Result};
use quinn::{ClientConfig, ServerConfig};
//use rcgen::{Certificate, CertificateParams, DnType};
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// On-wire padding targets (bytes). Keep constant to avoid size side-channels.
pub const PAD_TO_MULT: usize = 4096;
pub const PAD_TO_CMP: usize = 4096;
pub const PAD_TO_HELLO: usize = 1024;
/// Max number of pairs in a `BatchReq` accepted by server and client.
pub const MULT_BATCH_MAX: usize = 256;

// ------- Wire messages (serde) -------
// Reuse protocol types from hpcompproto; wrap them in a single Msg envelope.
pub use hpcompproto::{
    BatchReq, BatchResp, CmpZeroReq, CmpZeroResp, CompareScheme, Hello, KeyInfo, PROTO_VER, RouteMeta, RouteEnc, RouteEncSeg, RevealReq, RevealResp,
};

#[derive(Debug, Serialize, Deserialize)]
pub enum Msg {
    Hello(Hello),
    KeyInfo(KeyInfo),
    BatchReq(BatchReq),
    BatchResp(BatchResp),
    CmpZeroReq(CmpZeroReq),
    CmpZeroResp(CmpZeroResp),
    RouteMeta(RouteMeta),
    RouteEnc(RouteEnc),
    RevealReq(RevealReq),
    RevealResp(RevealResp),
}

pub const PAD_TO_ROUTE: usize  = 4096;
pub const PAD_TO_REVEAL: usize = 1024;

// ------- Framing (length-prefixed + padded) -------

fn pad_len(len: usize, pad_to: usize) -> usize {
    (pad_to - (len % pad_to)) % pad_to
}

/// Send a single framed message: [u32 LE: byte_len] [payload + zero padding]
pub async fn send_frame(send: &mut quinn::SendStream, msg: &Msg, pad_to: usize) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut bytes = bincode::serialize(msg)?;
    let rem = pad_len(bytes.len(), pad_to);
    if rem > 0 {
        bytes.extend(std::iter::repeat(0u8).take(rem));
    }
    let len_le = (bytes.len() as u32).to_le_bytes();
    send.write_all(&len_le).await?;
    send.write_all(&bytes).await?;
    send.flush().await?;
    Ok(())
}

/// Read a single framed message.
pub async fn read_msg(recv: &mut quinn::RecvStream) -> Result<Msg> {
    use tokio::io::AsyncReadExt;

    let mut len_le = [0u8; 4];
    recv.read_exact(&mut len_le).await?;
    let n = u32::from_le_bytes(len_le) as usize;

    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf).await?;

    // Trailing padding is zeros; try decode, fall back to trimming zeros.
    match bincode::deserialize::<Msg>(&buf) {
        Ok(m) => Ok(m),
        Err(_) => {
            while let Some(true) = buf.last().map(|b| *b == 0) {
                buf.pop();
            }
            Ok(bincode::deserialize::<Msg>(&buf)?)
        }
    }
}

// ------- QUIC / TLS helpers -------

/// Generate a self-signed certificate for the server (dev).
/// Returns (ServerConfig, server_cert_der) so clients can pin the root.
pub fn make_server_config_self_signed(
    common_name: &str,
) -> Result<(ServerConfig, CertificateDer<'static>)> {
    /*let mut params = CertificateParams::new(vec![common_name.to_string()]);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_string());*/
    let rcgen::CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![common_name.to_string()])?;
    //let cert = rcgen::generate_simple_self_signed(vec![common_name.to_string()])?;
    // cert.der() -> &CertificateDer<'static>; clone to own it
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_pkcs8 = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let key = PrivateKeyDer::Pkcs8(key_pkcs8);
    //let cert_der = CertificateDer::from(cert.serialize_der()?);
    let server_config = quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key)?;
    Ok((server_config, cert_der))
}

/// Build a QUIC client config that trusts only the provided server certificate.
pub fn make_client_config_with_root(server_cert: &CertificateDer<'static>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(server_cert.clone())
        .map_err(|_| anyhow!("failed to add root cert"))?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    let mut client_config = quinn::ClientConfig::with_root_certificates(roots.into())?;
    client_config.transport_config(transport.into());
    Ok(client_config)
}
