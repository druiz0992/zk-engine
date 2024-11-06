use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use jf_plonk::nightfall::ipa_structs::{Proof, ProvingKey, VerifyingKey};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam};
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;

use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
use plonk_prover::client::circuits::structs::CircuitId;
use plonk_prover::client::ClientPlonkCircuit;

use common::crypto::poseidon::constants::PoseidonParams;
use zk_macros::client_circuit;

#[client_circuit]
pub trait Prover<P, V, VSW> {
    // Returns Proofs and Public Inputs
    #[allow(clippy::type_complexity)]
    fn prove(
        circuit: &dyn ClientPlonkCircuit<P, V, VSW>,
        circuit_inputs: CircuitInputs<P>,
        proving_key: &ProvingKey<V>,
    ) -> Result<
        (
            Proof<V>,
            Vec<V::ScalarField>,
            DensePolynomial<V::ScalarField>,
        ),
        CircuitError,
    >;

    fn verify(vk: VerifyingKey<V>, public_inputs: Vec<V::ScalarField>, proof: Proof<V>) -> bool;

    fn get_pk(&self, circuit_id: CircuitId) -> Option<&ProvingKey<V>>;
    fn store_pk(&mut self, circuit_id: CircuitId, pk: ProvingKey<V>);
}
