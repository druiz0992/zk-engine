use crate::{domain::Preimage, ports::prover::Prover};

use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use common::crypto::poseidon::constants::PoseidonParams;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;

use crate::domain::{CircuitInputs, CircuitType::Mint, PublicKey, Transaction};

pub fn transfer_tokens<P, V, VSW, Proof>(
    // Token information
    old_preimages: Vec<Preimage<P>>,
    new_token_values: Vec<V::ScalarField>,
    recipients: Vec<PublicKey<P>>,
    // Tree information
    sibling_paths: Vec<P::ScalarField>,
    commitment_roots: Vec<P::ScalarField>,
) -> Result<Transaction<V>, &'static str>
where
    P: SWCurveConfig<BaseField = V::ScalarField>,
    V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>>,
    <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,
    <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
    Proof: Prover<V, P, VSW>,
{
    let mut circuit_inputs_builder = CircuitInputs::<P>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_ids(token_ids)
        .add_token_salts(salts)
        .add_token_values(token_values)
        .add_recipients(owners)
        .build();

    let (proof, pub_inputs, g_polys) = Proof::prove(Mint, circuit_inputs).unwrap();
    let commitments = pub_inputs.into_iter().map(|x| x.into()).collect();

    let transaction = Transaction::new(commitments, Default::default(), proof, g_polys);
    Ok(transaction)
}
