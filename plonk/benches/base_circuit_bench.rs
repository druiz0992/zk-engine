use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use curves::{
    pallas::{Fq, Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_relation::Circuit;
use plonk_prover::client::circuits::mint::MintCircuit;
use plonk_prover::client::circuits::transfer::TransferCircuit;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::rollup::circuits::base::base_rollup_circuit;
use plonk_prover::utils::bench;
use plonk_prover::utils::bench::base::*;
use plonk_prover::utils::bench::tree::tree_generator_from_client_inputs;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use trees::{non_membership_tree::IndexedMerkleTree, tree::AppendTree};

pub fn benchmark_client_transactions<const D: usize>(c: &mut Criterion) {
    let client_circuits: [[Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>; 2];
        2] = [
        [
            Box::new(MintCircuit::<1>::new()),
            Box::new(MintCircuit::<2>::new()),
        ],
        [
            Box::new(TransferCircuit::<1, 1, 8>::new()),
            Box::new(TransferCircuit::<2, 2, 8>::new()),
        ],
    ];
    for client_circuit in client_circuits.iter() {
        // Prepare transfer preamble (i.e. create fake mints)
        let mut rng = ChaChaRng::from_entropy();
        let mut client_inputs = vec![];
        let mut global_comm_roots: Vec<Fr> = vec![];
        let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
        let init_nullifier_root = nullifier_tree.root();
        let mut g_polys = vec![];
        let initial_nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();

        let token_id = Some(Fq::rand(&mut rng));

        for i in 0..client_circuit.len() {
            build_client_inputs(
                &mut client_inputs,
                &mut nullifier_tree,
                &mut global_comm_roots,
                &mut g_polys,
                &client_circuit[i],
                token_id,
            )
            .unwrap();
        }

        /* ----------------------------------------------------------------------------------
         * ---------------------------  Base Rollup Circuit ----------------------------------
         * ----------------------------------------------------------------------------------
         */

        let zk_trees =
            tree_generator_from_client_inputs::<D>(&mut client_inputs, global_comm_roots).unwrap();

        let (vesta_commit_key, _pallas_commit_key) = build_commit_keys().unwrap();

        let (base_rollup_circuit, _pi_star) = base_rollup_circuit::<VestaConfig, PallasConfig, D>(
            client_inputs.try_into().unwrap(),
            zk_trees.vk_tree.root(),
            // initial_nullifier_tree.root,
            init_nullifier_root,
            (initial_nullifier_tree.leaf_count() as u64).into(),
            zk_trees.global_root_tree.root(),
            g_polys.try_into().unwrap(),
            vesta_commit_key.clone(),
        )
        .unwrap();

        ark_std::println!(
            "Base rollup circuit constraints: {:?}",
            base_rollup_circuit.num_gates()
        );

        c.bench_function(
            &format!("Base with {:?} - Output: Proof Generation", client_circuit),
            |b| {
                b.iter(|| {
                    bench::generate_rollup_circuit_artifacts_and_verify::<
                        PallasConfig,
                        VestaConfig,
                        _,
                        _,
                    >(&base_rollup_circuit, false)
                    .unwrap();
                })
            },
        );
    }
}

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1).sample_size(10);targets = benchmark_client_transactions::<8>}
criterion_main!(benches);
