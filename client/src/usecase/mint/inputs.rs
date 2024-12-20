use super::MintPreimage;
use crate::domain::Preimage;
use crate::domain::{PreimageStatus, StoredPreimageInfo};
use crate::ports::committable::Committable;
use anyhow::Context;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::Transaction;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use zk_macros::client_bounds;

#[client_bounds]
pub(crate) fn compute_mint_preimages<P, V, VSW>(
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
            status: PreimageStatus::Unspent,
        };

        let mint_preimage = MintPreimage {
            key: preimage_key,
            preimage: new_preimage,
        };
        stored_preimages.push(mint_preimage);
    }
    Ok(stored_preimages)
}

#[client_bounds]
pub fn build_mint_inputs<P, V, VSW>(
    preimage: Vec<Preimage<P>>,
) -> anyhow::Result<CircuitInputs<P>> {
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

    Ok(circuit_inputs)
}
