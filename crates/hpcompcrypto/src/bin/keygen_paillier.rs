use clap::Parser;
use hpcompcrypto::{keygen, save_json};

#[derive(Parser, Debug)]
struct Opt {
    /// Output directory
    #[arg(long, default_value = "./keys")]
    out: String,
    /// Key size in bits
    #[arg(long, default_value_t = 2048)]
    bits: u32,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    std::fs::create_dir_all(&opt.out)?;
    let (pk, sk) = keygen(opt.bits, &mut rand::thread_rng());
    save_json(&format!("{}/paillier_pub.json", opt.out), &pk)?;
    save_json(&format!("{}/paillier_priv.json", opt.out), &sk)?;
    println!("Wrote Paillier keys to {}", opt.out);
    Ok(())
}
