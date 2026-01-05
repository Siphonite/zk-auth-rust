use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_ff::{PrimeField, BigInteger};
use sha2::{Sha256, Digest};

/// Deterministic Poseidon parameters for BN254
pub fn poseidon_params() -> PoseidonConfig<Fr> {
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

/// Hash Poseidon parameters so verifier can ensure consistency
pub fn poseidon_params_hash<F: PrimeField>(
    params: &PoseidonConfig<F>,
) -> String {
    let mut hasher = Sha256::new();

    for row in &params.mds {
        for el in row {
            hasher.update(el.into_bigint().to_bytes_le());
        }
    }

    for round in &params.ark {
        for el in round {
            hasher.update(el.into_bigint().to_bytes_le());
        }
    }

    format!("0x{:x}", hasher.finalize())
}
