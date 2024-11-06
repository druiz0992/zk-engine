use crate::ports::prover::Prover;

use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use common::structs::Transaction;
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::{
    client::{structs::ClientPubInputs, ClientPlonkCircuit},
    primitives::circuits::kem_dem::KemDemParams,
};

use crate::domain::Preimage;
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;

pub fn mint_tokens<P, V, VSW, Proof>(
    mint_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    preimage: Preimage<P>,
    proving_key: &ProvingKey<V>,
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
    Proof: Prover<P, V, VSW>,
{
    let Preimage {
        value,
        token_id,
        salt,
        public_key,
    } = preimage;
    let mut circuit_inputs_builder = CircuitInputs::<P>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_ids(vec![token_id])
        .add_token_salts(vec![salt])
        .add_token_values(vec![value])
        .add_recipients(vec![public_key])
        .build();

    let (proof, pub_inputs, g_polys) =
        Proof::prove(&*mint_circuit, circuit_inputs, proving_key).unwrap();

    let client_pub_inputs = ClientPubInputs::new(
        pub_inputs,
        mint_circuit.get_commitment_and_nullifier_count(),
    )?;

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
