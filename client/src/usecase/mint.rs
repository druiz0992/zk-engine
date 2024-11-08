use crate::domain::Preimage;
use crate::ports::committable::Committable;
use crate::ports::storage::StoredPreimageInfo;
use crate::ports::{prover::Prover, storage::PreimageDB};
use crate::services::prover::in_memory_prover::InMemProver;
use crate::utils;
use anyhow::Context;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::{Commitment, Transaction};
use jf_plonk::nightfall::ipa_structs::ProvingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::{circuits::circuit_inputs::CircuitInputs, ClientPlonkCircuit};
use plonk_prover::{client::structs::ClientPubInputs, primitives::circuits::kem_dem::KemDemParams};
use std::sync::Arc;
use tokio::sync::Mutex;
use zk_macros::client_circuit;

#[client_circuit]
pub async fn mint_process<P, V, VSW, Proof: Prover<P, V, VSW>, Storage: PreimageDB<E = P>>(
    db: Arc<Mutex<Storage>>,
    prover: Arc<Mutex<Proof>>,
    mint_details: Vec<Preimage<P>>,
) -> anyhow::Result<Transaction<V>> {
    let (pk, circuit) = {
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
        (pk, circuit)
    };

    let (transaction, preimages) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(_, _)> {
            let transaction =
                mint_tokens::<P, V, _, InMemProver<P, V, _>>(circuit, &mint_details, &pk)
                    .map_err(|_| anyhow::anyhow!("Error minting tokens",))?;
            let preimages = compute_mint_preimages(mint_details, &transaction)?;

            Ok((transaction, preimages))
        })
        .await??;

    tokio::spawn(send_transaction_to_sequencer(transaction.clone()));
    store_mint_preimages::<P, V, _, _>(db, preimages).await?;

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
    Ok(transaction)
}

async fn send_transaction_to_sequencer<V>(transaction: Transaction<V>)
where
    V: Pairing,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    let client = reqwest::Client::new();
    let res = client
        .post("http://127.0.0.1:4000/transactions")
        .json(&transaction)
        .send()
        .await;
    ark_std::println!("Got response {:?}", res);
}

struct MintPreimage<P>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField: PrimeField,
{
    key: Commitment<P::BaseField>,
    preimage: StoredPreimageInfo<P>,
}

#[client_circuit]
fn compute_mint_preimages<P, V, VSW>(
    mint_details: Vec<Preimage<P>>,
    transaction: &Transaction<V>,
) -> anyhow::Result<Vec<MintPreimage<P>>> {
    let mut stored_preimages = Vec::new();
    for mint_detail in mint_details {
        let preimage_key = mint_detail
            .commitment_hash()
            .context("Failed to compute commitment hash")?;

        let new_preimage = StoredPreimageInfo {
            preimage: mint_detail,
            nullifier: transaction.nullifiers[0].0,
            block_number: None,
            leaf_index: None,
            spent: false,
        };

        let mint_preimage = MintPreimage {
            key: preimage_key,
            preimage: new_preimage,
        };
        stored_preimages.push(mint_preimage);
    }
    Ok(stored_preimages)
}

#[client_circuit]
async fn store_mint_preimages<P, V, VSW, Storage: PreimageDB<E = P>>(
    db: Arc<Mutex<Storage>>,
    mint_preimages: Vec<MintPreimage<P>>,
) -> anyhow::Result<()> {
    let mut db = db.lock().await;

    for mint_preimage in mint_preimages {
        db.insert_preimage(mint_preimage.key.0, mint_preimage.preimage)
            .ok_or(anyhow::anyhow!("Error inserting mint preimage"))?;
    }
    Ok(())
}

#[client_circuit]
fn mint_tokens<P, V, VSW, Proof: Prover<P, V, VSW>>(
    mint_circuit: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    preimage: &Vec<Preimage<P>>,
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
