use std::sync::Arc;

use crate::{
    adapters::rest_api::rest_api_entry::run_api,
    services::{prover::in_memory_prover::InMemProver, storage::in_mem_storage::InMemStorage},
};
use curves::{
    pallas::{Fq, PallasConfig},
    vesta::VestaConfig,
};
use plonk_prover::client::{
    circuits::{mint::MintCircuit, transfer::TransferCircuit},
    ClientPlonkCircuit,
};
use ports::prover::Prover;

pub mod adapters;
pub mod domain;
pub mod ports;
pub mod services;
pub mod usecase;

fn main() {
    let db: InMemStorage<PallasConfig, Fq> = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let mut prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::new();

    const DEPTH: usize = 8;
    let circuit_info: Vec<Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>> = vec![
        Box::new(MintCircuit::<1>::new()),
        Box::new(MintCircuit::<2>::new()),
        Box::new(TransferCircuit::<1, 1, DEPTH>::new()),
        Box::new(TransferCircuit::<1, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 3, DEPTH>::new()),
    ];

    circuit_info.into_iter().for_each(|c| {
        let keys = c.generate_keys().unwrap();
        prover.store_pk(c.get_circuit_id(), keys.0);
    });

    let thread_safe_prover = Arc::new(tokio::sync::Mutex::new(prover));
    let _test_mnemonic = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";
    let async_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    async_rt.block_on(async {
        let _ = run_api(thread_safe_db, thread_safe_prover).await;
    });
    // let rng = &mut rand::thread_rng();
    // let transfer_input: TransferInput<PallasConfig> = TransferInput {
    //     sender: Affine::rand(rng),
    //     recipient: Affine::rand(rng),
    //     transfer_amount: Fr::rand(rng),
    //     commitments_to_use: [Fr::rand(rng); 2].to_vec(),
    // };
    // let s_string = serde_json::to_string(&transfer_input).unwrap();
    // ark_std::println!("transfer_input: {:?}", s_string);
    // let d_string = serde_json::from_str::<TransferInput<PallasConfig>>(&s_string);
    //
    // ark_std::println!("transfer_input: {:?}", d_string);

    println!("Hello, world!");
}
