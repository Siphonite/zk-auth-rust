use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ZkProof {
    pub version: String,
    pub curve: String,
    pub circuit: String,
    pub public_hash: String,
    pub proof: String,
    pub poseidon_params_hash: String,
    pub created_at: u64,
}
