use criterion::{criterion_group, criterion_main, Criterion};
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use plonk_prover::utils::bench;
use plonk_prover::{
    rollup::circuits::bounce::bounce_circuit,
    utils::bench::base::{self, TransactionType},
};

pub fn benchmark_bounce<const D: usize>(c: &mut Criterion) {
    // Below taken from bounce_test_helper
    let transaction_sequence = [TransactionType::Transfer, TransactionType::Transfer];
    let stored_proof_base = base::base_circuit_helper_generator::<D>(&transaction_sequence);
    let (global_public_inputs, subtree_public_inputs, passthrough_instance, _) =
        stored_proof_base.pub_inputs;
    let (bounce_circuit, _) = bounce_circuit::<PallasConfig, VestaConfig>(
        stored_proof_base.vk,
        global_public_inputs.clone(),
        subtree_public_inputs.clone(),
        stored_proof_base.proof,
        passthrough_instance,
    )
    .unwrap();

    let (bounce_ipa_pk, bounce_ipa_vk) =
        bench::generate_rollup_circuit_pks::<VestaConfig, PallasConfig, _, _>(&bounce_circuit)
            .unwrap();

    c.bench_function(
        &format!(
            "Bounce {:?}- Output: Proof Generation",
            transaction_sequence,
        ),
        |b| {
            b.iter(|| {
                let _ = bench::rollup_circuit_proof_and_verify::<VestaConfig, PallasConfig, _, _>(
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

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1).sample_size(10);targets = benchmark_bounce::<8>,}
criterion_main!(benches);
