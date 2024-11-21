use criterion::{criterion_group, criterion_main, Criterion};
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use plonk_prover::client::circuits::transfer::TransferCircuit;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::utils::bench;
use plonk_prover::utils::bench::base::TransactionType;
use plonk_prover::{
    rollup::circuits::bounce_merge::bounce_merge_circuit,
    utils::bench::merge::merge_circuit_helper_generator,
};

pub fn benchmark_bounce_merge<const D: usize>(c: &mut Criterion) {
    // Below taken from bounce_merge_test_helper
    let client_circuits: [Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>; 2] = [
        Box::new(TransferCircuit::<1, 1, 8>::new()),
        Box::new(TransferCircuit::<2, 2, 8>::new()),
    ];
    let stored_proof_merge = merge_circuit_helper_generator::<D>(&client_circuits);
    let (global_public_inputs, subtree_public_inputs, passthrough_instance, bounce_accs) =
        stored_proof_merge.pub_inputs;
    let (bounce_circuit, _) = bounce_merge_circuit::<PallasConfig, VestaConfig>(
        stored_proof_merge.vk,
        global_public_inputs.clone(),
        subtree_public_inputs.clone(),
        stored_proof_merge.proof,
        stored_proof_merge.g_poly,
        passthrough_instance,
        stored_proof_merge.commit_key.0.clone(),
        [bounce_accs[0].clone(), bounce_accs[1].clone()],
        [
            stored_proof_merge.pi_stars.0[0].clone(),
            stored_proof_merge.pi_stars.0[1].clone(),
        ],
    )
    .unwrap();

    let (bounce_ipa_pk, bounce_ipa_vk) =
        bench::generate_rollup_circuit_pks::<VestaConfig, PallasConfig, _, _>(&bounce_circuit)
            .unwrap();

    c.bench_function(
        &format!(
            "Bounce Merge {:?}- Output: Proof Generation",
            client_circuits,
        ),
        |b| {
            b.iter(|| {
                bench::rollup_circuit_proof_and_verify::<VestaConfig, PallasConfig, _, _>(
                    &bounce_circuit,
                    &bounce_ipa_pk,
                    &bounce_ipa_vk,
                    false,
                )
                .unwrap();
            })
        },
    );
}

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1).sample_size(10);targets = benchmark_bounce_merge::<8>,}
criterion_main!(benches);
