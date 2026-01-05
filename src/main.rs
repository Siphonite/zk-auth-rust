mod circuit;
mod prove;
mod verify;
mod setup;
mod poseidon_params;
mod proof_format;

use clap::{Parser, Subcommand};
use ark_bn254::Fr;

use crate::prove::generate_proof;
use crate::verify::verify_proof;
use crate::setup::run_setup;
use crate::proof_format::ZkProof;

#[derive(Parser)]
#[command(name = "zk-login-aidp")]
#[command(about = "ZK Login CLI powered by Poseidon + Groth16")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run trusted setup (one-time)
    Setup,

    /// Generate a proof
    Prove {
        #[arg(long)]
        secret: u64,

        #[arg(long, default_value = "proof.json")]
        out: String,
    },

    /// Verify a proof
    Verify {
        #[arg(long)]
        proof: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => {
            run_setup();
        }

        Commands::Prove { secret, out } => {
            let secret_fr = Fr::from(secret);
            let proof = generate_proof(secret_fr);

            std::fs::write(
                &out,
                serde_json::to_string_pretty(&proof).unwrap(),
            )
            .unwrap();

            println!("Proof written to {}", out);
        }

        Commands::Verify { proof } => {
            let contents = std::fs::read_to_string(proof).unwrap();
            let proof: ZkProof = serde_json::from_str(&contents).unwrap();

            let ok = verify_proof(proof);
            println!("Proof valid? {}", ok);
        }
    }
}
