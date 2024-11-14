use ark_ec::pairing::Pairing;
use criterion::{criterion_group, criterion_main, Criterion};
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_plonk::{
    nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
};
use jf_relation::{Arithmetization, Circuit};
use jf_utils::test_rng;
use plonk_prover::{
    rollup::circuits::merge::merge_circuit, utils::bench::bounce::bounce_circuit_helper_generator,
};

pub fn benchmark_merge<const I: usize, const N: usize, const C: usize, const D: usize>(
    c: &mut Criterion,
) {
    // Below taken from merge_test_helper
    let mut rng = test_rng();
    let stored_bounce = bounce_circuit_helper_generator::<I, C, N, D>();
    let stored_bounce_2 = stored_bounce.clone();
    let (global_public_inputs, subtree_pi_1, passthrough_instance_1, instance_1) =
        stored_bounce.pub_inputs;
    let (_, subtree_pi_2, passthrough_instance_2, instance_2) = stored_bounce_2.pub_inputs;

    let (mut merge_circuit, _) = merge_circuit::<VestaConfig, PallasConfig>(
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
    merge_circuit
        .check_circuit_satisfiability(&merge_circuit.public_input().unwrap())
        .unwrap();
    merge_circuit.finalize_for_arithmetization().unwrap();
    let merge_ipa_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            merge_circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();
    let (merge_ipa_pk, _) =
        PlonkIpaSnark::<PallasConfig>::preprocess(&merge_ipa_srs, &merge_circuit).unwrap();
    c.bench_function("Merge - Output: Proof Generation", |b| {
        b.iter(|| {
            let _ = PlonkIpaSnark::<PallasConfig>::prove::<
                _,
                _,
                RescueTranscript<<PallasConfig as Pairing>::BaseField>,
            >(&mut rng, &merge_circuit, &merge_ipa_pk, None)
            .unwrap();
        })
    });
}

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1).sample_size(10);targets = benchmark_merge::<2, 2, 2, 8>,}
criterion_main!(benches);
