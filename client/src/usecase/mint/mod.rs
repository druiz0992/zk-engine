use crate::domain::Preimage;
use crate::ports::storage::StoredPreimageInfo;
use crate::ports::{prover::Prover, storage::PreimageDB};
use crate::utils;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::ports::notifier::Notifier;
use common::structs::{Commitment, Transaction};
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use std::sync::Arc;
use tokio::sync::Mutex;
use zk_macros::client_circuit;

mod inputs;
mod mint_tokens;

use inputs::*;
use mint_tokens::*;

struct MintPreimage<P>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField: PrimeField,
{
    key: Commitment<P::BaseField>,
    preimage: StoredPreimageInfo<P>,
}

#[client_circuit]
pub async fn mint_process<
    P,
    V,
    VSW,
    Proof: Prover<P, V, VSW>,
    Storage: PreimageDB<E = P>,
    Comms: Notifier<Info = Transaction<V>>,
>(
    db: Arc<Mutex<Storage>>,
    prover: Arc<Mutex<Proof>>,
    notifier: Arc<Mutex<Comms>>,
    mint_details: Vec<Preimage<P>>,
) -> anyhow::Result<Transaction<V>> {
    let (proving_key, circuit) = get_circuit_and_pk(prover, &mint_details).await?;
    let (transaction, preimages) =
        spawn_mint::<_, _, _, Proof>(circuit, mint_details, proving_key).await?;
    let mut db = db.lock().await;

    for mint_preimage in preimages {
        db.insert_preimage(mint_preimage.key.0, mint_preimage.preimage)
            .ok_or(anyhow::anyhow!("Error inserting mint preimage"))?;
    }

    // This is to simulate the mint being added to the tree
    // Replace with something better
    // let cloned_tx = transaction.clone();
    // let tx = Tx {
    //     ct: transaction.commitments,
    //     nullifiers: transaction.nullifiers,
    //     ciphertexts: transaction.ciphertexts,
    //     proof: transaction.proof,
    //     g_polys: transaction.g_polys,
    //     phantom: std::marker::PhantomData,
    // };
    // let writer_str = serde_json::to_string(&tx).unwrap();
    // ark_std::println!("Got writer str {}", writer_str);
    // ark_std::println!(
    //     "unwrapped: {:?}",
    //     serde_json::from_str::<Tx<VestaConfig>>(&writer_str).unwrap()
    // );

    // ark_std::println!("Posted res");
    let notifier = notifier.lock().await;
    notifier.send_info(transaction.clone()).await?;

    Ok(transaction)
}

#[client_circuit]
async fn get_circuit_and_pk<P, V, VSW, Proof: Prover<P, V, VSW>>(
    prover: Arc<Mutex<Proof>>,
    mint_details: &[Preimage<P>],
) -> anyhow::Result<(ProvingKey<V>, Box<dyn ClientPlonkCircuit<P, V, VSW>>)> {
    let prover_guard = prover.lock().await;
    let n_commitments = mint_details.len();
    let circuit = utils::circuits::get_mint_circuit_from_params::<P, V, _>(n_commitments)?;
    let pk = prover_guard
        .get_pk(circuit.get_circuit_id())
        .ok_or(anyhow::anyhow!(
            "Error in minting process. Circuit Id {:?} not registered",
            circuit.get_circuit_id()
        ))?
        .clone();
    Ok((pk, circuit))
}

#[client_circuit]
async fn spawn_mint<P, V, VSW, Proof: Prover<P, V, VSW>>(
    mint_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    mint_details: Vec<Preimage<P>>,
    proving_key: ProvingKey<V>,
) -> anyhow::Result<(Transaction<V>, Vec<MintPreimage<P>>)> {
    let (transaction, preimages) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(_, _)> {
            let inputs = build_mint_inputs::<P, V, VSW>(mint_details.clone())?;
            let transaction = mint_tokens::<P, V, _, Proof>(mint_circuit, inputs, &proving_key)
                .map_err(|_| anyhow::anyhow!("Error minting tokens",))?;
            let preimages = compute_mint_preimages(mint_details, &transaction)?;

            Ok((transaction, preimages))
        })
        .await??;
    Ok((transaction, preimages))
}
