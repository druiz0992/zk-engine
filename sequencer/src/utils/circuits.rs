use crate::usecase::block::TransactionProcessor;
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
use zk_macros::client_bounds;

const DEPTH: usize = 8;

#[client_bounds]
pub fn select_client_circuits_sequencer<P, V, VSW>() -> Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>>
{
    let circuit_info: Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>> = vec![
        Box::new(MintCircuit::<1>::new()),
        Box::new(MintCircuit::<2>::new()),
        Box::new(TransferCircuit::<1, 1, DEPTH>::new()),
        Box::new(TransferCircuit::<1, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 3, DEPTH>::new()),
    ];
    circuit_info
}

#[client_bounds]
pub fn register_circuits<P, V, VSW>(
    processor: &mut TransactionProcessor<P, V, VSW>,
    circuits: Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>>,
) {
    circuits.into_iter().for_each(|c| {
        let circuit_type = c.get_circuit_type();
        processor.register(circuit_type, c);
    });
}
