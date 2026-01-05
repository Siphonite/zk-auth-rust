use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bn254::Fr;

pub struct HashCircuit {
    pub secret: Option<Fr>,      // private input
    pub public_hash: Option<Fr>, // public input
}

impl ConstraintSynthesizer<Fr> for HashCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let secret_var = FpVar::new_witness(cs.clone(), || self.secret.ok_or(SynthesisError::AssignmentMissing))?;
        let hash_var =
            FpVar::new_input(cs.clone(), || self.public_hash.ok_or(SynthesisError::AssignmentMissing))?;

        // For now, we use a *dummy* constraint just to test wiring:
        // secret must equal hash (we'll replace with real hashing next)
        secret_var.enforce_equal(&hash_var)?;

        Ok(())
    }
}
