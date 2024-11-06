use crate::ports::prover::Prover;
use anyhow::{anyhow, Result};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::{
    circuits::{mint::MintCircuit, transfer::TransferCircuit},
    ClientPlonkCircuit,
};
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use std::sync::Arc;
use tokio::sync::Mutex;
use zk_macros::client_circuit;

const DEPTH: usize = 8;
#[client_circuit]
pub fn init_client_circuits<P, V, VSW, PR: Prover<P, V, VSW>>(prover: &mut PR) -> Result<()> {
    let circuit_info: Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>> = vec![
        Box::new(MintCircuit::<1>::new()),
        Box::new(MintCircuit::<2>::new()),
        Box::new(TransferCircuit::<1, 1, DEPTH>::new()),
        Box::new(TransferCircuit::<1, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 3, DEPTH>::new()),
    ];

    for c in circuit_info {
        let keys = c
            .generate_keys()
            .map_err(|e| anyhow!("Failed to generate keys: {:?}", e))?;
        prover.store_pk(c.get_circuit_id(), keys.0);
    }
    Ok(())
}

#[client_circuit]
pub async fn add_client_circuits<P, V, VSW, PR: Prover<P, V, VSW> + Send>(
    prover: &Arc<Mutex<PR>>,
    circuit_info: Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>>,
) -> anyhow::Result<()> {
    let mut prover = prover.lock().await;
    for c in circuit_info {
        let keys = c
            .generate_keys()
            .map_err(|e| anyhow!("Failed to generate keys: {:?}", e))?;
        prover.store_pk(c.get_circuit_id(), keys.0);
    }
    Ok(())
}
