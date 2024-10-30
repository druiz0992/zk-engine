use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use circuits::circuit_inputs::CircuitInputs;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::{nightfall::ipa_structs::ProvingKey, nightfall::ipa_structs::VerifyingKey};
use jf_relation::constraint_system::PlonkCircuit;
use jf_relation::errors::CircuitError;

pub mod circuits;
pub mod structs;

pub trait ClientPlonkCircuit<P, V, const C: usize, const N: usize, const D: usize> {
    fn generate_keys(&self) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError>
    where
        V: Pairing,
        <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig;

    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P, C, N, D>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>
    where
        P: SWCurveConfig,
        <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
        V: Pairing<ScalarField = P::BaseField>;
}
