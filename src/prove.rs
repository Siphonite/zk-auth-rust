use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;

use crate::circuit::HashCircuit;
use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

/// Generates a proof given a secret and poseidon params.
/// Returns (proof_bytes, public_hash)
pub fn generate_proof(secret: Fr, params: PoseidonConfig<Fr>) -> (Vec<u8>, Fr) {
    let mut rng = thread_rng();

    // public hash
    let public_hash = CRH::<Fr>::evaluate(&params, [secret]).unwrap();

    // circuit for setup
    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    // trusted setup
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();

    // prover circuit
    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng).unwrap();

    // serialize proof
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    (proof_bytes, public_hash)
}
