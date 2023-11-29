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
use plonk_prover::rollup::circuits::base::ClientInput;

use crate::domain::{CircuitType, RollupCommitKeys, RollupProvingKeys};

pub trait SequencerProver<V, P, SW>
where
    V: Pairing<G1Affine = Affine<<<V as Pairing>::G1 as CurveGroup>::Config>>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
    <V as Pairing>::BaseField:
        PrimeField + PoseidonParams<Field = P::ScalarField> + RescueParameter + SWToTEConParam,

    <V as Pairing>::ScalarField:
        PrimeField + PoseidonParams<Field = P::BaseField> + RescueParameter + SWToTEConParam,
    P: Pairing<BaseField = V::ScalarField, ScalarField = V::BaseField>,

    P: Pairing<G1Affine = Affine<SW>, G1 = Projective<SW>>,
    V: Pairing,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
    SW: SWCurveConfig<BaseField = V::ScalarField, ScalarField = V::BaseField>,
{
    #[allow(clippy::too_many_arguments)]
    fn rollup_proof(
        client_inputs: [ClientInput<V, 1, 1>; 2],
        global_vk_root: P::ScalarField,
        global_nullifier_root: P::ScalarField,
        global_nullifier_leaf_count: P::ScalarField,
        global_commitment_root: P::ScalarField,
        g_polys: [DensePolynomial<P::BaseField>; 2],
        commit_keys: RollupCommitKeys,
        proving_keys: Option<RollupProvingKeys>,
    ) -> Result<Proof<P>, CircuitError>;

    fn store_pks(&mut self, pks: RollupProvingKeys);

    fn get_pks(&self) -> Option<RollupProvingKeys>;

    fn store_vk(&mut self, circuit_type: CircuitType, vk: VerifyingKey<V>);
    fn get_vk(&self, circuit_type: CircuitType) -> Option<VerifyingKey<V>>;

    fn store_cks(&mut self, cks: RollupCommitKeys);
    fn get_cks(&self) -> Option<RollupCommitKeys>;
}
