use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose, Engine as _};
use rand::thread_rng;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::circuit::HashCircuit;
use crate::poseidon_params::{poseidon_params, poseidon_params_hash};
use crate::proof_format::ZkProof;

/// Generate a portable ZK proof
pub fn generate_proof(secret: Fr) -> ZkProof {
    let mut rng = thread_rng();
    let params = poseidon_params();

    // Public hash
    let public_hash = CRH::<Fr>::evaluate(&params, [secret]).unwrap();

    // Circuit for setup
    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    let pk =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(
            circuit,
            &mut rng,
        )
        .unwrap();

    // Circuit for proving
    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit,
            &pk,
            &mut rng,
        )
        .unwrap();

    // Serialize proof
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    ZkProof {
        version: "v1".to_string(),
        curve: "bn254".to_string(),
        circuit: "zk-login-poseidon".to_string(),
        public_hash: public_hash.to_string(),
        proof: general_purpose::STANDARD.encode(proof_bytes),
        poseidon_params_hash: poseidon_params_hash(&params),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}
