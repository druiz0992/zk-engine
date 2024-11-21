use crate::adapters::rest_api::structs::TransferInput;
use crate::ports::prover::Prover;
use crate::ports::storage::{KeyDB, PreimageDB, TreeDB};
use crate::services::user_keys::UserKeys;
use crate::utils;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::ports::notifier::Notifier;
use common::structs::Transaction;
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use std::sync::Arc;
use tokio::sync::Mutex;
use zk_macros::client_bounds;

mod inputs;
pub mod transfer_tokens;

use transfer_tokens::*;

use inputs::*;

#[client_bounds]
pub async fn transfer_process<
    P,
    V,
    VSW,
    Proof: Prover<P, V, VSW>,
    Storage: PreimageDB<E = P> + TreeDB<F = <P as CurveConfig>::BaseField> + KeyDB<E = P, Key = UserKeys<P>>,
    Comms: Notifier<Info = Transaction<V>>,
>(
    db: Arc<Mutex<Storage>>,
    prover: Arc<Mutex<Proof>>,
    notifier: Arc<Mutex<Comms>>,
    transfer_details: TransferInput<P>,
) -> anyhow::Result<Transaction<V>> {
    let transfer_inputs = build_transfer_inputs::<P, V, VSW, Storage>(db, transfer_details).await?;
    let (proving_key, circuit) = get_circuit_and_pk(prover, &transfer_inputs).await?;

    // transfer tokens
    let transaction =
        spawn_transfer::<P, V, _, Proof>(circuit, transfer_inputs, proving_key).await?;

    let notifier = notifier.lock().await;
    notifier.send_info(transaction.clone()).await?;

    Ok(transaction)
}

#[client_bounds]
async fn get_circuit_and_pk<P, V, VSW, Proof: Prover<P, V, VSW>>(
    prover: Arc<Mutex<Proof>>,
    transfer_details: &CircuitInputs<P>,
) -> anyhow::Result<(ProvingKey<V>, Box<dyn ClientPlonkCircuit<P, V, VSW>>)> {
    let prover_guard = prover.lock().await;
    let circuit = utils::circuits::get_transfer_circuit_from_params::<P, V, _>(
        transfer_details.token_values.len(),
        transfer_details.old_token_values.len(),
    )?;
    let pk = prover_guard
        .get_pk(circuit.get_circuit_type())
        .ok_or(anyhow::anyhow!(
            "Error in minting process. Circuit Id {:?} not registered",
            circuit.get_circuit_type()
        ))?
        .clone();
    Ok((pk, circuit))
}

#[client_bounds]
async fn spawn_transfer<P, V, VSW, Proof: Prover<P, V, VSW>>(
    transfer_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    transfer_inputs: CircuitInputs<P>,
    proving_key: ProvingKey<V>,
) -> anyhow::Result<Transaction<V>> {
    let transaction = tokio::task::spawn_blocking(move || -> anyhow::Result<Transaction<V>> {
        let transaction =
            transfer_tokens::<P, V, _, Proof>(transfer_circuit, &transfer_inputs, &proving_key)
                .map_err(|_| anyhow::anyhow!("Error transfer tokens",))?;

        Ok(transaction)
    })
    .await??;
    Ok(transaction)
}
