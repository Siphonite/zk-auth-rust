use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_crypto_primitives::crh::{
    CRHScheme, CRHSchemeGadget,
    poseidon::{constraints::{CRHGadget, CRHParametersVar}, CRH},
};

/// Circuit:
/// Prove you know a secret such that Poseidon(secret) = public_hash
pub struct HashCircuit {
    pub secret: Option<Fr>,                                  // private input
    pub public_hash: Option<Fr>,                             // public input
    pub params: Option<<CRH<Fr> as CRHScheme>::Parameters>,  // Poseidon parameters
}

impl ConstraintSynthesizer<Fr> for HashCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Private witness
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public input
        let public_hash_var = FpVar::new_input(cs.clone(), || {
            self.public_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Poseidon parameters (must be supplied externally)
        let params = self
            .params
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Convert parameters to circuit variable
        let params_var = CRHParametersVar::new_constant(cs.clone(), &params)?;

        // Compute Poseidon(secret) inside the circuit
        let computed_hash =
            CRHGadget::<Fr>::evaluate(&params_var, &[secret_var.clone()])?;

        // Enforce equality: hash(secret) == public_hash
        computed_hash.enforce_equal(&public_hash_var)?;

        Ok(())
    }
}
