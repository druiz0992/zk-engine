use crate::ports::prover::Prover;

use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use common::structs::Transaction;
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::{client::structs::ClientPubInputs, primitives::circuits::kem_dem::KemDemParams};

use crate::domain::{CircuitType::Mint, PublicKey};
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;

pub fn mint_tokens<P, V, VSW, Proof>(
    token_values: Vec<V::ScalarField>,
    token_ids: Vec<V::ScalarField>,
    salts: Vec<V::ScalarField>,
    owners: Vec<PublicKey<P>>,
    proving_key: Option<&ProvingKey<V>>,
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
    Proof: Prover<V, VSW>,
{
    const C: usize = 1;
    const N: usize = 0;
    const D: usize = 0;
    let mut circuit_inputs_builder = CircuitInputs::<P, C, N, D>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_ids(token_ids)
        .add_token_salts(salts)
        .add_token_values(token_values)
        .add_recipients(owners)
        .build();

    let (proof, pub_inputs, g_polys, _pk) =
        Proof::prove::<P, C, N, D>(Mint, circuit_inputs, proving_key).unwrap();

    let client_pub_inputs: ClientPubInputs<_, 0, 1> = pub_inputs.try_into()?;

    let transaction = Transaction::new(
        client_pub_inputs
            .commitments
            .into_iter()
            .map(Into::into)
            .collect(),
        client_pub_inputs
            .nullifiers
            .into_iter()
            .map(Into::into)
            .collect(),
        client_pub_inputs.ciphertexts,
        proof,
        g_polys,
        client_pub_inputs.ephemeral_public_key,
        client_pub_inputs.swap_field,
    );
    Ok(transaction)
}
