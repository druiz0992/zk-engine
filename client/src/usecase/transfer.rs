use crate::{domain::Preimage, ports::prover::Prover};

use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use common::structs::Transaction;
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::{client::structs::ClientPubInputs, primitives::circuits::kem_dem::KemDemParams};
use trees::MembershipPath;

use common::keypair::PublicKey;
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
use plonk_prover::client::ClientPlonkCircuit;

#[allow(clippy::too_many_arguments)]
pub fn transfer_tokens<P, V, VSW, Proof>(
    transfer_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    // Token information
    old_preimages: Vec<Preimage<P>>,
    new_token_values: Vec<V::ScalarField>,
    recipients: Vec<PublicKey<P>>,
    // Tree information
    sibling_paths: Vec<MembershipPath<V::ScalarField>>,
    commitment_roots: Vec<V::ScalarField>,
    membership_path_index: Vec<V::ScalarField>,
    // Key Information
    root_key: V::ScalarField,
    ephemeral_key: V::ScalarField,
    // Prover
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
    // Assert all token ids are the same
    let token_id = old_preimages[0].token_id;
    old_preimages.iter().skip(1).for_each(|x| {
        assert_eq!(x.token_id, token_id);
    });
    // Start the builder
    let mut circuit_inputs_builder = CircuitInputs::<P>::new();
    //let mut circuit_inputs_builder = CircuitInputs::<P>::new();
    // Add vector inputs
    let mut old_token_values = Vec::with_capacity(old_preimages.len());
    let mut old_token_salts = Vec::with_capacity(old_preimages.len());

    old_preimages.iter().for_each(|x| {
        old_token_values.push(x.value);
        old_token_salts.push(x.salt);
    });

    let circuit_inputs = circuit_inputs_builder
        .add_token_values(new_token_values)
        .add_token_ids(vec![token_id])
        .add_recipients(recipients)
        .add_old_token_values(old_token_values)
        .add_old_token_salts(old_token_salts)
        .add_membership_path(sibling_paths)
        .add_commitment_tree_root(commitment_roots)
        .add_membership_path_index(membership_path_index.clone())
        .add_root_key(root_key)
        .add_ephemeral_key(ephemeral_key)
        .add_token_salts(membership_path_index) //only the first salt needs to be the index
        .build();

    let (proof, pub_inputs, g_polys) =
        Proof::prove(&*transfer_circuit, circuit_inputs, proving_key).unwrap();

    let client_pub_inputs = ClientPubInputs::new(
        pub_inputs,
        transfer_circuit.get_commitment_and_nullifier_count(),
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
