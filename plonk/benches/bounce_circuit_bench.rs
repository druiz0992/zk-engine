use ark_ec::pairing::Pairing;
use criterion::{criterion_group, criterion_main, Criterion};
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_plonk::{
    nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
};
use jf_relation::{Arithmetization, Circuit};
use jf_utils::test_rng;
use plonk_prover::{
    rollup::circuits::bounce::bounce_circuit, utils::bench_utils::base_circuit_helper_generator,
};

pub fn benchmark_bounce<const I: usize, const N: usize, const C: usize, const D: usize>(
    c: &mut Criterion,
) {
    // Below taken from bounce_test_helper
    let mut rng = test_rng();
    let stored_proof_base = base_circuit_helper_generator::<I, C, N, D>();
    let (global_public_inputs, subtree_public_inputs, passthrough_instance, _) =
        stored_proof_base.pub_inputs;
    let (mut bounce_circuit, _) = bounce_circuit::<PallasConfig, VestaConfig>(
        stored_proof_base.vk,
        global_public_inputs.clone(),
        subtree_public_inputs.clone(),
        stored_proof_base.proof,
        passthrough_instance,
    )
    .unwrap();
    bounce_circuit
        .check_circuit_satisfiability(&bounce_circuit.public_input().unwrap())
        .unwrap();
    bounce_circuit.finalize_for_arithmetization().unwrap();
    let bounce_ipa_srs =
        <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            bounce_circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();
    let (bounce_ipa_pk, _) =
        PlonkIpaSnark::<VestaConfig>::preprocess(&bounce_ipa_srs, &bounce_circuit).unwrap();
    c.bench_function("Bounce - Output: Proof Generation", |b| {
        b.iter(|| {
            let _ = PlonkIpaSnark::<VestaConfig>::prove::<
                _,
                _,
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(&mut rng, &bounce_circuit, &bounce_ipa_pk, None)
            .unwrap();
        })
    });
}

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1).sample_size(10);targets = benchmark_bounce::<2, 2, 2, 8>,}
criterion_main!(benches);
