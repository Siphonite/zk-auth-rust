use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};

/// Returns stable, pre-computed Poseidon parameters for BN254.
/// These settings are standard for BN254 Poseidon and never change.
pub fn poseidon_params() -> PoseidonConfig<Fr> {
    // BN254 standard Poseidon settings
    let full_rounds: usize = 8;
    let partial_rounds: usize = 57;
    let alpha: u64 = 5;
    let rate: usize = 2;
    let capacity: usize = 1;

    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        254,            // prime bits for BN254
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,              // skip matrices
    );

    PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        ark,
        rate,
        capacity,
    )
}
