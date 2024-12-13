use crate::adapters::rest_api::structs::TransferInput;
use crate::domain::{Preimage, StoredPreimageInfoVector};
use crate::ports::committable::Committable;
use crate::ports::keys::FullKey;
use crate::ports::storage::{KeyDB, PreimageDB, TreeDB};
use crate::services::user_keys::UserKeys;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use common::crypto::poseidon::constants::PoseidonParams;
use common::keypair::PublicKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
use plonk_prover::client::circuits::transfer::check_inputs;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::sync::Arc;
use tokio::sync::Mutex;
use trees::MembershipPath;
use zk_macros::client_bounds;

#[client_bounds]
pub async fn build_transfer_inputs<
    P,
    V,
    VSW,
    Storage: PreimageDB<E = P> + TreeDB<F = <P as CurveConfig>::BaseField> + KeyDB<E = P, Key = UserKeys<P>>,
>(
    db: Arc<Mutex<Storage>>,
    transfer_details: TransferInput<P>,
) -> anyhow::Result<CircuitInputs<P>> {
    let mut circuit_inputs = CircuitInputs::<P>::new();

    let db_locked = db.lock().await;
    // find commitments
    let stored_preimages: StoredPreimageInfoVector<P> = transfer_details
        .commitments_to_use
        .iter()
        .map(|key| db_locked.get_preimage(*key))
        .collect::<Option<_>>()
        .ok_or(anyhow::anyhow!(
            "Preimage not found during transfer request"
        ))?;

    // retrieve commitment preimages
    let old_preimages: Vec<Preimage<P>> = stored_preimages.iter().map(|x| x.preimage).collect();
    ark_std::println!(
        "Got commitment hash {}",
        old_preimages[0].commitment_hash().unwrap().0
    );

    // retrieve sibling paths
    let sibling_path_indices: Vec<<P as CurveConfig>::BaseField> = stored_preimages
        .iter()
        .map(|x| {
            x.leaf_index
                .map(|x| <P as CurveConfig>::BaseField::from(x as u64))
        })
        .collect::<Option<_>>()
        .ok_or(anyhow::anyhow!("Error building path indices"))?;
    circuit_inputs.add_membership_path_index(sibling_path_indices.clone());
    circuit_inputs.add_token_salts(sibling_path_indices);

    let sibling_paths: Vec<MembershipPath<<P as CurveConfig>::BaseField>> = stored_preimages
        .iter()
        .map(|x| db_locked.get_sibling_path(&x.block_number?, x.leaf_index?))
        .collect::<Option<Vec<_>>>()
        .ok_or(anyhow::anyhow!("Error retrieving sibling path"))?;
    circuit_inputs.add_membership_path(sibling_paths);

    // get commitment roots
    let commitment_roots: Vec<<P as CurveConfig>::BaseField> = stored_preimages
        .iter()
        .map(|x| db_locked.get_root(&x.block_number?))
        .collect::<Option<_>>()
        .ok_or(anyhow::anyhow!("Error retrieving commitment roots"))?;
    ark_std::println!("Got root {}", commitment_roots[0]);
    circuit_inputs.add_commitment_tree_root(commitment_roots);

    let root_key: <P as CurveConfig>::BaseField = db_locked
        .get_key(transfer_details.sender)
        .ok_or(anyhow::anyhow!("Error retrieving key"))?
        .get_private_key();
    circuit_inputs.add_root_key(root_key);

    let eph_key = transfer_details.eph_key.unwrap_or_else(|| {
        let mut rng = ChaChaRng::from_entropy();
        <P as CurveConfig>::BaseField::rand(&mut rng)
    });
    circuit_inputs.add_ephemeral_key(eph_key);

    circuit_inputs.add_recipients(vec![PublicKey(transfer_details.recipient)]);

    let token_id = old_preimages[0].token_id;
    if !old_preimages.iter().all(|x| x.token_id == token_id) {
        return Err(anyhow::anyhow!("Token Ids must be equal"));
    }
    //let mut circuit_inputs_builder = CircuitInputs::<P>::new();
    // Add vector inputs
    let mut old_token_values = Vec::with_capacity(old_preimages.len());
    let mut old_token_salts = Vec::with_capacity(old_preimages.len());

    old_preimages.iter().for_each(|x| {
        old_token_values.push(x.value);
        old_token_salts.push(x.salt);
    });

    circuit_inputs
        .add_token_ids(vec![token_id])
        .add_old_token_values(old_token_values)
        .add_old_token_salts(old_token_salts)
        .add_token_values(vec![transfer_details.transfer_amount])
        .build();
    check_inputs::<P, V>(
        &circuit_inputs,
        circuit_inputs.token_values.len(),
        circuit_inputs.old_token_values.len(),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(circuit_inputs)
}
