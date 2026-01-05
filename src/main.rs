mod circuit;
mod prove;
mod verify;
mod poseidon_params;

use std::str::FromStr;
use clap::{Parser, Subcommand};
use ark_bn254::Fr;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::prove::generate_proof;
use crate::verify::verify_proof;
use crate::circuit::HashCircuit;
use crate::poseidon_params::poseidon_params;

#[derive(Parser)]
#[command(name = "zk-login-aidp")]
#[command(about = "Zero-knowledge login CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a proof for a secret value
    Prove {
        #[arg(long)]
        secret: u64,

        #[arg(long, default_value = "proof.json")]
        out: String,
    },

    /// Verify a proof JSON file
    Verify {
        #[arg(long)]
        proof: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove { secret, out } => {
            let secret_fr = Fr::from(secret);
            let params = poseidon_params();

            let (proof_bytes, public_hash) = generate_proof(secret_fr, params.clone());

            let obj = serde_json::json!({
                "proof": BASE64.encode(&proof_bytes),
                "public_hash": public_hash.to_string()
            });

            std::fs::write(out.clone(), serde_json::to_string_pretty(&obj).unwrap()).unwrap();

            println!("Proof written to {}", out);
        }

        Commands::Verify { proof } => {
            let data: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(proof).unwrap()).unwrap();

            let proof_bytes = BASE64.decode(data["proof"].as_str().unwrap()).unwrap();
            let public_hash = Fr::from_str(data["public_hash"].as_str().unwrap()).unwrap();

            let params = poseidon_params();

            let circuit = HashCircuit {
                secret: None,
                public_hash: Some(public_hash),
                params: Some(params.clone()),
            };

            let ok = verify_proof(proof_bytes, public_hash, circuit);

            println!("Proof valid? {}", ok);
        }
    }
}
