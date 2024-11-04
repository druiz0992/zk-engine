pub mod adapters;
pub mod domain;
pub mod ports;
pub mod services;
pub mod usecase;

use common::crypto::poseidon::Poseidon;
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_plonk::{
    nightfall::PlonkIpaSnark,
    proof_system::{structs::VK, UniversalSNARK},
};
use jf_primitives::pcs::StructuredReferenceString;
use plonk_prover::{
    client::circuits::{mint::MintCircuit, transfer::TransferCircuit},
    utils::key_gen::generate_client_pks_and_vks,
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use trees::{membership_tree::Tree, tree::AppendTree};

use crate::{
    adapters::rest_api::sequencer_api::run_sequencer_api,
    domain::RollupCommitKeys,
    ports::{prover::SequencerProver, storage::GlobalStateStorage},
    services::{
        prover::in_mem_sequencer_prover::InMemProver,
        storage::in_mem_sequencer_storage::InMemStorage,
    },
};

fn main() {
    let mut db: InMemStorage = InMemStorage::new();
    let mut prover: InMemProver = InMemProver::new();
    const C: usize = 1;
    const N: usize = 1;
    const D: usize = 8;

    // Setup Preamble
    ark_std::println!("Generating Keys");
    let pks =
        generate_client_pks_and_vks::<PallasConfig, VestaConfig, VestaConfig, C, N, D>().unwrap();
    let vks = pks
        .into_iter()
        .zip([MintCircuit::circuit_id(), TransferCircuit::circuit_id()])
        .map(|(pk, circuit_type)| {
            prover.store_vk(circuit_type, pk.1.clone());
            pk.1
        })
        .collect::<Vec<_>>();

    let poseidon: Poseidon<curves::vesta::Fq> = Poseidon::new();
    let vk_hashes = vks
        .iter()
        .map(|vk| {
            let vk_sigmas = vk.sigma_comms();
            let vk_selectors = vk.selector_comms();
            let vk_sigma_hashes = vk_sigmas
                .iter()
                .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
            let vk_selector_hashes = vk_selectors
                .iter()
                .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
            let vk_hashes = vk_sigma_hashes
                .chain(vk_selector_hashes)
                .collect::<Vec<_>>();
            let outlier_pair = vk_hashes[0..2].to_vec();
            let mut total_leaves = vk_hashes[2..].to_vec();
            for _ in 0..4 {
                let lefts = total_leaves.iter().step_by(2);
                let rights = total_leaves.iter().skip(1).step_by(2);
                let pairs = lefts.zip(rights);
                total_leaves = pairs
                    .map(|(&x, &y)| poseidon.hash_unchecked(vec![x, y]))
                    .collect::<Vec<_>>();
            }
            poseidon.hash_unchecked(vec![outlier_pair[0], outlier_pair[1], total_leaves[0]])
        })
        .collect::<Vec<_>>();

    let vk_tree: Tree<_, 2> = Tree::from_leaves(vk_hashes);
    db.store_vk_tree(vk_tree);

    let mut rng = ChaChaRng::from_entropy();
    ark_std::println!("Generating srs_1");
    let vesta_srs =
        <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(20),
            &mut rng,
        )
        .unwrap();
    let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(20)).unwrap();

    let pallas_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            2usize.pow(20),
            &mut rng,
        )
        .unwrap();
    let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(20)).unwrap();
    ark_std::println!("Ck ready");
    let rollup_commit_keys = RollupCommitKeys {
        pallas_commit_key,
        vesta_commit_key,
    };
    prover.store_cks(rollup_commit_keys);

    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let thread_safe_prover = std::sync::Arc::new(tokio::sync::Mutex::new(prover));

    let _test_mnemonic = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";

    let async_rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    async_rt.block_on(async {
        let _ = run_sequencer_api(thread_safe_db, thread_safe_prover).await;
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
