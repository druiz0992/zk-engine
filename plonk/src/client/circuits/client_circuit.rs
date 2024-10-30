use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use jf_plonk::nightfall::ipa_structs::{ProvingKey, VerifyingKey};
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;

use super::circuit_inputs::CircuitInputs;
use crate::primitives::circuits::kem_dem::KemDemParams;
use common::crypto::poseidon::constants::PoseidonParams;
use macros::client_circuit;

// P: SWCurveConfig,
// <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,

// V: Pairing<ScalarField = P::BaseField>,
// V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = P::BaseField>,
// <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,
// <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,

// VSW: SWCurveConfig<
// BaseField = <V as Pairing>::BaseField,
// ScalarField = <V as Pairing>::ScalarField,
// >,
#[client_circuit]
pub struct ClientCircuit<P, V, VSW, const C: usize, const N: usize, const D: usize> {
    pub circuit_inputs: CircuitInputs<P, C, N, D>,
    pub proving_key: ProvingKey<V>,
    pub verifying_key: VerifyingKey<V>,
}

#[client_circuit]
impl<P, V, VSW, const C: usize, const N: usize, const D: usize> ClientCircuit<P, V, VSW, C, N, D> {
    pub fn new(
        circuit_inputs: CircuitInputs<P, C, N, D>,
        proving_key: ProvingKey<V>,
        verifying_key: VerifyingKey<V>,
    ) -> Self {
        Self {
            circuit_inputs,
            proving_key,
            verifying_key,
        }
    }
    pub fn set_inputs(&mut self, circuit_inputs: CircuitInputs<P, C, N, D>) {
        self.circuit_inputs = circuit_inputs;
    }
}
