use super::MintPreimage;
use crate::ports::storage::PreimageDB;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use std::sync::Arc;
use tokio::sync::Mutex;
use zk_macros::client_circuit;

#[client_circuit]
pub(crate) async fn store_mint_preimages<P, V, VSW, Storage: PreimageDB<E = P>>(
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
