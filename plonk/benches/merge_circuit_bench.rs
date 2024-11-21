use criterion::{criterion_group, criterion_main, Criterion};
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use plonk_prover::client::circuits::transfer::TransferCircuit;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::utils::bench;
use plonk_prover::utils::bench::base::TransactionType;
use plonk_prover::{
    rollup::circuits::merge::merge_circuit, utils::bench::bounce::bounce_circuit_helper_generator,
};

pub fn benchmark_merge<const D: usize>(c: &mut Criterion) {
    // Below taken from merge_test_helper
    let client_circuits: [Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>; 2] = [
        Box::new(TransferCircuit::<1, 1, 8>::new()),
        Box::new(TransferCircuit::<2, 2, 8>::new()),
    ];
    let stored_bounce = bounce_circuit_helper_generator::<D>(&client_circuits);
    let stored_bounce_2 = stored_bounce.clone();
    let (global_public_inputs, subtree_pi_1, passthrough_instance_1, instance_1) =
        stored_bounce.pub_inputs;
    let (_, subtree_pi_2, passthrough_instance_2, instance_2) = stored_bounce_2.pub_inputs;

    let (merge_circuit, _) = merge_circuit::<VestaConfig, PallasConfig>(
        stored_bounce.vk,
        global_public_inputs.clone(),
        [subtree_pi_1, subtree_pi_2],
        [stored_bounce.proof, stored_bounce_2.proof],
        [stored_bounce.g_poly, stored_bounce_2.g_poly],
        [
            passthrough_instance_1.clone(),
            passthrough_instance_2.clone(),
        ],
        stored_bounce.commit_key.1.clone(),
        [instance_1[0].clone(), instance_2[0].clone()],
        [stored_bounce.pi_stars.1, stored_bounce_2.pi_stars.1],
    )
    .unwrap();

    let (merge_ipa_pk, merge_ipa_vk) =
        bench::generate_rollup_circuit_pks::<PallasConfig, VestaConfig, _, _>(&merge_circuit)
            .unwrap();
    c.bench_function(
        &format!("Merge {:?}- Output: Proof Generation", client_circuits),
        |b| {
            b.iter(|| {
                bench::rollup_circuit_proof_and_verify::<PallasConfig, VestaConfig, _, _>(
                    &merge_circuit,
                    &merge_ipa_pk,
                    &merge_ipa_vk,
                    false,
                )
                .unwrap();
            })
        },
    );
}

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1).sample_size(10);targets = benchmark_merge::<8>,}
criterion_main!(benches);
