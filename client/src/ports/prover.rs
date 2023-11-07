use ark_ec::{pairing::Pairing, CurveConfig, CurveGroup};
use ark_ff::FftField;

use crate::domain::{CircuitInputs, CircuitType, Proof};

pub enum ProofInput<E: CurveGroup> {
    Point(E::Affine),
    Scalar(<E::Config as CurveConfig>::ScalarField),
}

pub trait Prover<E>
where
    E: Pairing,
{
    // Returns Proofs and Public Inputs
    fn prove<I: Pairing>(
        circuit_type: CircuitType,
        circuit_inputs: CircuitInputs<I>,
    ) -> Result<(Proof<E>, Vec<E::ScalarField>), &'static str>;
    fn verify<F: FftField>(circuit_type: CircuitType, public_inputs: Option<Vec<F>>) -> bool;
}
