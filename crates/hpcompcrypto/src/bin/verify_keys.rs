use clap::Parser;
use hpcompcrypto::{hash_key, load_json, PaillierPrivateKey, PaillierPublicKey};

#[derive(Parser, Debug)]
struct Opt {
    #[arg(long)]
    paillier_pub: String,
    #[arg(long)]
    paillier_priv: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let pk: PaillierPublicKey = load_json(&opt().paillier_pub)?;
    println!("Public key hash: {}", hash_key(&pk));
    if let Some(sk_path) = opt().paillier_priv {
        let _sk: PaillierPrivateKey = load_json(&sk_path)?;
        println!("Private key file looks well-formed.");
    }
    Ok(())
}

fn opt() -> Opt {
    Opt::parse()
}
