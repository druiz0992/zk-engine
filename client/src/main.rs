use crate::{
    adapters::rest_api::rest_api_entry::run_api, services::storage::in_mem_storage::InMemStorage,
};
use curves::pallas::PallasConfig;

pub mod adapters;
pub mod domain;
pub mod ports;
pub mod services;
pub mod usecase;

fn main() {
    let db: InMemStorage<PallasConfig> = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));

    let _test_mnemonic = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";

    let async_rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    async_rt.block_on(async {
        let _ = run_api(thread_safe_db).await;
    });
    println!("Hello, world!");
}
