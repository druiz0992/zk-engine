use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{Proof, VerifyingKey};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam};
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;

use crate::domain::{CircuitInputs, CircuitType};

pub trait Prover<V, P, VSW>
where
    P: SWCurveConfig<BaseField = V::ScalarField>,
    V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>>,
    <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
{
    // Returns Proofs and Public Inputs
    fn prove(
        circuit_type: CircuitType,
        circuit_inputs: CircuitInputs<P>,
    ) -> Result<
        (
            Proof<V>,
            Vec<V::ScalarField>,
            DensePolynomial<V::ScalarField>,
        ),
        CircuitError,
    >
    where
        P: SWCurveConfig<BaseField = V::ScalarField>,
        <P as CurveConfig>::BaseField: PrimeField + KemDemParams<Field = V::ScalarField>,
        <P as CurveConfig>::BaseField: PrimeField;

    fn verify(vk: VerifyingKey<V>, public_inputs: Vec<V::ScalarField>, proof: Proof<V>) -> bool;

    fn get_vk(&self, circuit_type: CircuitType) -> Option<&VerifyingKey<V>>;
    fn store_vk(&mut self, circuit_type: CircuitType, vk: VerifyingKey<V>);
}
