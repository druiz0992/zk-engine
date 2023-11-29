use std::sync::Arc;

use crate::{
    adapters::rest_api::rest_api_entry::run_api,
    domain::{CircuitType, Fr},
    ports::prover::Prover,
    services::{prover::in_memory_prover::InMemProver, storage::in_mem_storage::InMemStorage},
};
use ark_ec::short_weierstrass::Affine;
use ark_std::UniformRand;
use curves::{
    pallas::{Fq, PallasConfig},
    vesta::VestaConfig,
};
use plonk_prover::utils::key_gen::generate_client_pks_and_vks;

pub mod adapters;
pub mod domain;
pub mod ports;
pub mod services;
pub mod usecase;

fn main() {
    let db: InMemStorage<PallasConfig, Fq> = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let mut prover: InMemProver<VestaConfig> = InMemProver::new();
    ark_std::println!("generating keys");
    let pks = generate_client_pks_and_vks::<PallasConfig, VestaConfig, VestaConfig>().unwrap();
    pks.into_iter()
        .zip([CircuitType::Mint, CircuitType::Transfer].into_iter())
        .for_each(|(pk, circuit_type)| prover.store_pk(circuit_type, pk));

    ark_std::println!("keys generated");
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
