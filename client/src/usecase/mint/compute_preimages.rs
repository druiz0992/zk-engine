use super::MintPreimage;
use crate::domain::Preimage;
use crate::ports::committable::Committable;
use crate::ports::storage::StoredPreimageInfo;
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
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use zk_macros::client_circuit;

#[client_circuit]
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
