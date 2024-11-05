use crate::primitives::circuits::kem_dem::KemDemParams;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use circuits::circuit_inputs::CircuitInputs;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::{nightfall::ipa_structs::ProvingKey, nightfall::ipa_structs::VerifyingKey};
use jf_plonk::{nightfall::PlonkIpaSnark, proof_system::UniversalSNARK};
use jf_primitives::rescue::RescueParameter;
use jf_relation::constraint_system::PlonkCircuit;
use jf_relation::errors::CircuitError;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_relation::Arithmetization;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use zk_macros::client_circuit;

pub mod circuits;
pub mod client_macros;
pub mod structs;

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
pub trait ClientPlonkCircuit<P, V, VSW> {
    fn generate_keys(
        &self,
        circuit_inputs: CircuitInputs<P>,
    ) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
        let mut circuit = self.to_plonk_circuit(circuit_inputs)?;
        generate_keys_from_plonk::<P, V, VSW>(&mut circuit)
    }

    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>;

    fn generate_inputs(&self) -> Result<CircuitInputs<P>, CircuitError>;
}

#[client_circuit]
pub fn build<P, V, VSW>(circuit_type: &str) -> Box<dyn ClientPlonkCircuit<P, V, VSW>> {
    match circuit_type {
        "mint" => Box::new(circuits::mint::MintCircuit::<1>::new()),
        "transfer" => Box::new(circuits::transfer::TransferCircuit::<2, 2, 2>::new()),
        _ => panic!("Not"),
    }
}

#[client_circuit]
pub fn generate_keys<P, V, VSW, T: ClientPlonkCircuit<P, V, VSW>>(
    circuit: &T,
) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
    let circuit_inputs = circuit.generate_inputs()?;
    circuit.generate_keys(circuit_inputs)
}

#[client_circuit]
pub fn generate_keys_from_plonk<P, V, VSW>(
    circuit: &mut PlonkCircuit<V::ScalarField>,
) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
    let srs_size = circuit.srs_size()?;
    let mut rng = ChaChaRng::from_entropy();
    let srs =
        <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(srs_size, &mut rng)?;

    let (pk, vk) = PlonkIpaSnark::<V>::preprocess(&srs, circuit)?;
    Ok((pk, vk))
}
#[client_circuit]
pub fn build_plonk_circuit_from_inputs<P, V, VSW, T: ClientPlonkCircuit<P, V, VSW>>(
    circuit: &T,
    circuit_inputs: CircuitInputs<P>,
) -> Result<PlonkCircuit<V::ScalarField>, CircuitError> {
    circuit.to_plonk_circuit(circuit_inputs)
}
