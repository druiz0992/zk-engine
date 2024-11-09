use crate::ports::prover::Prover;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use common::structs::Transaction;
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::{client::structs::ClientPubInputs, primitives::circuits::kem_dem::KemDemParams};

#[allow(clippy::too_many_arguments)]
pub fn transfer_tokens<P, V, VSW, Proof>(
    transfer_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    // Token information
    circuit_inputs: &CircuitInputs<P>,
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
    let (proof, pub_inputs, g_polys) =
        Proof::prove(&*transfer_circuit, circuit_inputs.clone(), proving_key).unwrap();

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
