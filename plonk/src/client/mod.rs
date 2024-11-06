use crate::primitives::circuits::kem_dem::KemDemParams;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use circuits::circuit_inputs::CircuitInputs;
use circuits::structs::CircuitId;
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
pub trait ClientPlonkCircuit<P, V, VSW>: Send + Sync + 'static {
    fn generate_keys(&self) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
        let inputs = self.generate_random_inputs()?;
        let mut circuit = self.to_plonk_circuit(inputs)?;
        generate_keys_from_plonk::<P, V, VSW>(&mut circuit)
    }

    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>;

    fn generate_random_inputs(&self) -> Result<CircuitInputs<P>, CircuitError>;
    fn get_circuit_id(&self) -> CircuitId;
    fn get_commitment_and_nullifier_count(&self) -> (usize, usize);
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
