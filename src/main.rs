mod circuit;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_groth16::{prepare_verifying_key, Groth16};
use rand::thread_rng;

use circuit::HashCircuit;

/// Create Poseidon parameters for BN254 scalar field
fn poseidon_params() -> PoseidonConfig<Fr> {
    // Poseidon parameters for BN254
    // rate = 2, full_rounds = 8, partial_rounds = 57, alpha = 5
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
    let mut rng = thread_rng();

    // ------------------------------
    // 1️. Choose a secret identity value
    // (in real life: derived from email/wallet/etc.)
    // ------------------------------
    let secret = Fr::from(42u64);

    // ------------------------------
    // 2️. Generate Poseidon parameters (shared config)
    // ------------------------------
    let params = poseidon_params();

    // ------------------------------
    // 3️. Compute public hash = Poseidon(secret)
    // ------------------------------
    let public_hash = CRH::<Fr>::evaluate(&params, [secret]).unwrap();

    // ------------------------------
    // 4️. Trusted setup (circuit definition)
    // ------------------------------
    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    let params_pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params_pk.vk);

    // ------------------------------
    // 5. Create proof
    // ------------------------------
    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &params_pk, &mut rng).unwrap();

    // ------------------------------
    // 6. Verify proof
    // ------------------------------
    let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_hash]).unwrap();

    println!("Proof verified? {}", verified);
}
