use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;
use std::fs::{create_dir_all, File};

use crate::circuit::HashCircuit;
use crate::poseidon_params::poseidon_params;

pub fn run_setup() {
    let mut rng = thread_rng();
    let params = poseidon_params();

    // Dummy circuit for setup (no witness values needed)
    let circuit = HashCircuit {
        secret: None,
        public_hash: None,
        params: Some(params),
    };

    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        circuit,
        &mut rng,
    )
    .unwrap();

    create_dir_all("keys").unwrap();

    let mut pk_file = File::create("keys/proving_key.bin").unwrap();
    let mut vk_file = File::create("keys/verifying_key.bin").unwrap();

    pk.serialize_compressed(&mut pk_file).unwrap();
    pk.vk.serialize_compressed(&mut vk_file).unwrap();

    println!("Setup complete. Keys saved in ./keys/");
}
