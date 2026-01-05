use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::CanonicalDeserialize;

use crate::circuit::HashCircuit;
use crate::poseidon_params::{poseidon_params, poseidon_params_hash};
use crate::proof_format::ZkProof;
use std::str::FromStr;
use base64::{engine::general_purpose, Engine as _};

pub fn verify_proof(proof: ZkProof) -> bool {
    let params = poseidon_params();

    // Check Poseidon parameters integrity
    if poseidon_params_hash(&params) != proof.poseidon_params_hash {
        return false;
    }

    let public_hash = Fr::from_str(&proof.public_hash).unwrap();
    let proof_bytes = general_purpose::STANDARD.decode(proof.proof).unwrap();

    let circuit = HashCircuit {
        secret: None,
        public_hash: Some(public_hash),
        params: Some(params.clone()),
    };

    let mut rng = rand::thread_rng();
    let vk_params =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(
            circuit,
            &mut rng,
        )
        .unwrap();

    let pvk = prepare_verifying_key(&vk_params.vk);

    let proof =
        ark_groth16::Proof::<Bn254>::deserialize_compressed(
            &*proof_bytes,
        )
        .unwrap();

    Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_hash]).unwrap()
}
