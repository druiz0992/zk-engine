use crate::ports::prover::Prover;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::CircuitType;
use common::structs::Transaction;
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::{circuits::circuit_inputs::CircuitInputs, ClientPlonkCircuit};
use plonk_prover::{client::structs::ClientPubInput, primitives::circuits::kem_dem::KemDemParams};
use zk_macros::client_bounds;

#[client_bounds]
pub(crate) fn mint_tokens<P, V, VSW, Proof: Prover<P, V, VSW>>(
    mint_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    circuit_inputs: CircuitInputs<P>,
    proving_key: &ProvingKey<V>,
) -> Result<Transaction<V>, &'static str> {
    let (proof, pub_inputs, g_polys) = Proof::prove(&*mint_circuit, circuit_inputs, proving_key)
        .map_err(|_| "Error running Mint proof")?;

    let commitments_nullifiers_count = mint_circuit.get_commitment_and_nullifier_count();
    let client_pub_inputs: ClientPubInput<<V as Pairing>::ScalarField> =
        ClientPubInput::new(pub_inputs, commitments_nullifiers_count)?;

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
        CircuitType::Mint(commitments_nullifiers_count.0),
    );
    Ok(transaction)
}
