mod circuit;
mod prove;
mod verify;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use crate::prove::generate_proof;
use crate::verify::verify_proof;
use crate::circuit::HashCircuit;

/// Create Poseidon parameters for BN254 scalar field
fn poseidon_params() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        254,  // prime field bits
        2,    // rate
        8,    // full rounds
        57,   // partial rounds
        0,    // skip matrices
    );

    PoseidonConfig {
        full_rounds: 8,
        partial_rounds: 57,
        alpha: 5,
        ark,
        mds,
        rate: 2,
        capacity: 1,
    }
}

fn main() {
    let secret = Fr::from(42u64);

    let params = poseidon_params();

    let (proof_bytes, public_hash) = generate_proof(secret, params.clone());

    let circuit = HashCircuit {
        secret: None,
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    let verified = verify_proof(proof_bytes, public_hash, circuit);

    println!("Proof verified? {}", verified);
}
