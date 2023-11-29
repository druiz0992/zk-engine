use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{Proof, ProvingKey, VerifyingKey};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam};
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;

use crate::domain::{CircuitInputs, CircuitType};

pub trait Prover<V, VSW>
where
    V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>>,
    <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
{
    // Returns Proofs and Public Inputs
    fn prove<P>(
        circuit_type: CircuitType,
        circuit_inputs: CircuitInputs<P>,
        proving_key: Option<&ProvingKey<V>>,
    ) -> Result<
        (
            Proof<V>,
            Vec<V::ScalarField>,
            DensePolynomial<V::ScalarField>,
            ProvingKey<V>,
        ),
        CircuitError,
    >
    where
        P: SWCurveConfig<BaseField = V::ScalarField>,
        <P as CurveConfig>::BaseField: PrimeField + KemDemParams<Field = V::ScalarField>;

    fn verify(vk: VerifyingKey<V>, public_inputs: Vec<V::ScalarField>, proof: Proof<V>) -> bool;

    fn get_pk(&self, circuit_type: CircuitType) -> Option<&ProvingKey<V>>;
    fn store_pk(&mut self, circuit_type: CircuitType, pk: ProvingKey<V>);
}
