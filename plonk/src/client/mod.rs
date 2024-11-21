use crate::client::structs::ClientPubInputs;
use crate::primitives::circuits::kem_dem::KemDemParams;
use crate::rollup::circuits::client_input::ClientInput;
use crate::rollup::circuits::client_input::LowNullifierInfo;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use circuits::circuit_inputs::CircuitInputs;
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::CircuitType;
use jf_plonk::nightfall::ipa_structs::Proof;
use jf_plonk::{nightfall::ipa_structs::ProvingKey, nightfall::ipa_structs::VerifyingKey};
use jf_plonk::{nightfall::PlonkIpaSnark, proof_system::UniversalSNARK};
use jf_primitives::rescue::RescueParameter;
use jf_relation::constraint_system::PlonkCircuit;
use jf_relation::errors::CircuitError;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_relation::Arithmetization;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use trees::IndexedMerkleTree;
use zk_macros::client_bounds;

pub mod circuits;
pub mod structs;

pub struct PlonkCircuitParams<F: PrimeField> {
    pub circuit: PlonkCircuit<F>,
    pub public_inputs: ClientPubInputs<F>,
}
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

#[client_bounds]
pub trait ClientPlonkCircuit<P, V, VSW>: Send + Sync + 'static + std::fmt::Debug {
    fn generate_keys(&self) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
        let inputs = self.generate_random_inputs(None)?;
        let mut circuit = self.to_plonk_circuit(inputs)?;
        generate_keys_from_plonk::<P, V, VSW>(&mut circuit)
    }

    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>;

    fn generate_random_inputs(
        &self,
        token_id: Option<V::ScalarField>,
    ) -> Result<CircuitInputs<P>, CircuitError>;
    fn get_circuit_type(&self) -> CircuitType;
    fn get_commitment_and_nullifier_count(&self) -> (usize, usize);
    fn generate_sequencer_inputs(
        &self,
        proof: Proof<V>,
        vk: VerifyingKey<V>,
        public_inputs: &ClientPubInputs<V::ScalarField>,
        low_nullifier_info: &Option<LowNullifierInfo<V, 32>>,
    ) -> ClientInput<V>;
}

#[client_bounds]
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
