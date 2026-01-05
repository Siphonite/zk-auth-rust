use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::CanonicalDeserialize;
use base64::{engine::general_purpose, Engine as _};
use std::fs::File;
use std::str::FromStr;

use crate::poseidon_params::{poseidon_params, poseidon_params_hash};
use crate::proof_format::ZkProof;

/// Verify a ZK proof using a persisted verifying key
pub fn verify_proof(proof: ZkProof) -> bool {
    let params = poseidon_params();

    // Ensure Poseidon parameters match
    if poseidon_params_hash(&params) != proof.poseidon_params_hash {
        return false;
    }

    let public_hash = Fr::from_str(&proof.public_hash).unwrap();
    let proof_bytes = general_purpose::STANDARD.decode(proof.proof).unwrap();

    // Load verifying key
    let mut vk_file = File::open("keys/verifying_key.bin")
        .expect("Verifying key not found. Run `setup` first.");

    let vk =
        ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&mut vk_file)
            .unwrap();

    let pvk = prepare_verifying_key(&vk);

    let proof =
        ark_groth16::Proof::<Bn254>::deserialize_compressed(&*proof_bytes)
            .unwrap();

    Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_hash]).unwrap()
}
