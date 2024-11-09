use crate::domain::Preimage;
use crate::ports::prover::Prover;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::Transaction;
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::{circuits::circuit_inputs::CircuitInputs, ClientPlonkCircuit};
use plonk_prover::{client::structs::ClientPubInputs, primitives::circuits::kem_dem::KemDemParams};
use zk_macros::client_circuit;

#[client_circuit]
pub(crate) fn mint_tokens<P, V, VSW, Proof: Prover<P, V, VSW>>(
    mint_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    preimage: &[Preimage<P>],
    proving_key: &ProvingKey<V>,
) -> Result<Transaction<V>, &'static str> {
    let values: Vec<_> = preimage.iter().map(|s| s.value).collect();
    let token_ids: Vec<_> = preimage.iter().map(|s| s.token_id).collect();
    let salts: Vec<_> = preimage.iter().map(|s| s.salt).collect();
    let public_keys: Vec<_> = preimage.iter().map(|s| s.public_key).collect();

    let mut circuit_inputs_builder = CircuitInputs::<P>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_ids(token_ids)
        .add_token_salts(salts)
        .add_token_values(values)
        .add_recipients(public_keys)
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
