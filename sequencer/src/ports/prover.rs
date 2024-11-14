use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{Proof, VerifyingKey};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam};
use plonk_prover::rollup::circuits::client_input::ClientInput;
use zk_macros::sequencer_circuit;

use crate::domain::{RollupCommitKeys, RollupProvingKeys};
use plonk_prover::client::circuits::structs::CircuitId;

#[sequencer_circuit]
pub trait SequencerProver<V, VSW, P, SW> {
    #[allow(clippy::too_many_arguments)]
    fn rollup_proof(
        client_inputs: [ClientInput<V, 1, 1, 8>; 2],
        global_vk_root: P::ScalarField,
        global_nullifier_root: P::ScalarField,
        global_nullifier_leaf_count: P::ScalarField,
        global_commitment_root: P::ScalarField,
        g_polys: [DensePolynomial<P::BaseField>; 2],
        commit_keys: RollupCommitKeys<V, VSW, P, SW>,
        proving_keys: Option<RollupProvingKeys<V, VSW, P, SW>>,
    ) -> Result<Proof<P>, CircuitError>;

    fn store_pks(&mut self, pks: RollupProvingKeys<V, VSW, P, SW>);
    fn get_pks(&self) -> Option<RollupProvingKeys<V, VSW, P, SW>>;

    fn store_vk(&mut self, circuit_id: CircuitId, vk: VerifyingKey<V>);
    fn get_vk(&self, circuit_id: CircuitId) -> Option<VerifyingKey<V>>;

    fn store_cks(&mut self, cks: RollupCommitKeys<V, VSW, P, SW>);
    fn get_cks(&self) -> Option<RollupCommitKeys<V, VSW, P, SW>>;
}
