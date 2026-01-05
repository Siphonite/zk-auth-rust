use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::CanonicalDeserialize;

use crate::circuit::HashCircuit;

/// Verifies a serialized proof against a public hash
pub fn verify_proof(proof_bytes: Vec<u8>, public_hash: Fr, circuit: HashCircuit) -> bool {
    // recreate verifying key from circuit setup
    let mut rng = rand::thread_rng();
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);

    // deserialize proof
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(&*proof_bytes).unwrap();

    Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_hash]).unwrap()
}
