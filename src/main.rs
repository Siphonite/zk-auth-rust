mod circuit;

use ark_bn254::Bn254;
use ark_groth16::{Groth16, prepare_verifying_key};
use rand::thread_rng;

use circuit::HashCircuit;
use ark_bn254::Fr;

fn main() {
    let mut rng = thread_rng();

    // secret and public are equal (for now)
    let secret = Fr::from(42u64);
    let public_hash = secret;

    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
    };

    // Trusted setup
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);

    // Recreate circuit for proving
    let circuit = HashCircuit {
        secret: Some(secret),
        public_hash: Some(public_hash),
    };

    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &params, &mut rng).unwrap();

    let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_hash]).unwrap();

    println!("Proof verified? {}", verified);
}
