use ark_ec::{short_weierstrass::SWCurveConfig, CurveGroup};
use ark_std::UniformRand;
use common::crypto::poseidon::Poseidon;
use common::derived_keys::DerivedKeys;
use common::keypair::PublicKey;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curves::{
    pallas::{Fq, Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_plonk::{
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
};
use jf_relation::{Arithmetization, Circuit};
use jf_utils::test_rng;
use plonk_prover::client::circuits::{
    circuit_inputs::CircuitInputs, mint::mint_circuit, transfer::transfer_circuit,
};
use std::str::FromStr;
use trees::MembershipPath;

pub fn benchmark_mint(c: &mut Criterion) {
    const N: usize = 0;
    const D: usize = 0;
    c.bench_function("Mint Circuit - 1 Output: Witness Generation", |b| {
        const C: usize = 1;
        b.iter(|| {
            let value = Fq::from_str("1").unwrap();
            let token_id = Fq::from_str("2").unwrap();
            let token_nonce = Fq::from_str("3").unwrap();
            let token_owner = (PallasConfig::GENERATOR * Fr::from_str("4").unwrap()).into_affine();

            let mut circuit_inputs_builder = CircuitInputs::<PallasConfig, C, N, D>::new();
            let circuit_inputs = circuit_inputs_builder
                .add_token_values(vec![value; C])
                .add_token_ids(vec![token_id; C])
                .add_token_salts(vec![token_nonce; C])
                .add_recipients(vec![PublicKey::from_affine(token_owner); C])
                .build();
            let mut circuit =
                mint_circuit::<PallasConfig, VestaConfig, _, C, N, D>(circuit_inputs).unwrap();
            circuit.finalize_for_arithmetization().unwrap();
        })
    });
    c.bench_function("Mint Circuit - 1 Output: Proof Generation", |b| {
        const C: usize = 1;
        let value = Fq::from_str("1").unwrap();
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from_str("3").unwrap();
        let token_owner =
            (PallasConfig::GENERATOR * Fr::from_str("4").unwrap()).into_affine();

        let mut circuit_inputs_builder = CircuitInputs::<PallasConfig, C, N, D>::new();
        let circuit_inputs = circuit_inputs_builder
            .add_token_values(vec![value; C])
            .add_token_ids(vec![token_id; C])
            .add_token_salts(vec![token_nonce; C])
            .add_recipients(vec![PublicKey::from_affine(token_owner); C])
            .build();

        let mut circuit = mint_circuit::<PallasConfig, VestaConfig,_, C, N, D>(circuit_inputs).unwrap();
        circuit.finalize_for_arithmetization().unwrap();

        let srs_size = circuit.srs_size().unwrap();
        let srs =
            <PlonkKzgSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
                srs_size, &mut test_rng(),
            ).unwrap();

        let (pk, _) = PlonkKzgSnark::<VestaConfig>::preprocess(&srs, &circuit).unwrap();



        b.iter(|| {
            let _ = PlonkKzgSnark::<VestaConfig>::prove::<_, _, StandardTranscript>(
                &mut test_rng(), &circuit, &pk, None,
            ).unwrap();
        })
    });
    c.bench_function("Mint Circuit - 2 Output: Witness Generation", |b| {
        const C: usize = 2;
        b.iter(|| {
            let value = Fq::from_str("1").unwrap();
            let token_id = Fq::from_str("2").unwrap();
            let token_nonce = Fq::from_str("3").unwrap();
            let token_owner = (PallasConfig::GENERATOR * Fr::from_str("4").unwrap()).into_affine();

            let mut circuit_inputs_builder = CircuitInputs::<PallasConfig, C, N, D>::new();
            let circuit_inputs = circuit_inputs_builder
                .add_token_values(vec![value; C])
                .add_token_ids(vec![token_id; C])
                .add_token_salts(vec![token_nonce; C])
                .add_recipients(vec![PublicKey::from_affine(token_owner); C])
                .build();

            let mut circuit =
                mint_circuit::<PallasConfig, VestaConfig, _, C, N, D>(circuit_inputs).unwrap();
            circuit.finalize_for_arithmetization().unwrap();
        })
    });
    c.bench_function("Mint Circuit - 2 Output: Proof Generation", |b| {
        const C: usize = 2;
        let value = Fq::from_str("1").unwrap();
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from_str("3").unwrap();
        let token_owner =
            (PallasConfig::GENERATOR * Fr::from_str("4").unwrap()).into_affine();


        let mut circuit_inputs_builder = CircuitInputs::<PallasConfig, C, N, D>::new();
        let circuit_inputs = circuit_inputs_builder
            .add_token_values(vec![value; C])
            .add_token_ids(vec![token_id; C])
            .add_token_salts(vec![token_nonce; C])
            .add_recipients(vec![PublicKey::from_affine(token_owner); C])
            .build();

        let mut circuit = mint_circuit::<PallasConfig, VestaConfig,_, C, N, D>(circuit_inputs).unwrap();
        circuit.finalize_for_arithmetization().unwrap();
        let srs_size = circuit.srs_size().unwrap();
        let srs =
            <PlonkKzgSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
                srs_size, &mut test_rng(),
            ).unwrap();

        let (pk, _) = PlonkKzgSnark::<VestaConfig>::preprocess(&srs, &circuit).unwrap();

        b.iter(|| {
            let _ = PlonkKzgSnark::<VestaConfig>::prove::<_, _, StandardTranscript>(
                &mut test_rng(), &circuit, &pk, None,
            ).unwrap();
        })
    });
}

pub fn benchmark_transfer(c: &mut Criterion) {
    const C: usize = 1;
    const N: usize = 1;
    const D: usize = 1;

    let root_key = Fq::rand(&mut test_rng());
    let derived_keys = DerivedKeys::<PallasConfig>::new(root_key).unwrap();
    let token_owner = derived_keys.public_key;
    let old_commitment_leaf_index = 0u64; //u32::rand(&mut test_rng());

    let value = Fq::from_str("1").unwrap();
    let token_id = Fq::from_str("2").unwrap();
    let token_nonce = Fq::from(3u32);
    let old_commitment_hash = Poseidon::<Fq>::new()
        .hash(vec![
            value,
            token_id,
            token_nonce,
            token_owner.x,
            token_owner.y,
        ])
        .unwrap();

    let mut old_commitment_sibling_path = MembershipPath::new();
    (0..D).for_each(|_| old_commitment_sibling_path.append(Fq::rand(&mut test_rng())));

    let root = old_commitment_sibling_path
        .clone()
        .into_iter()
        .enumerate()
        .fold(old_commitment_hash, |a, (i, b)| {
            let poseidon: Poseidon<Fq> = Poseidon::new();
            let bit_dir = old_commitment_leaf_index >> i & 1;
            if bit_dir == 0 {
                poseidon.hash(vec![a, b]).unwrap()
            } else {
                poseidon.hash(vec![b, a]).unwrap()
            }
        });

    //let t = old_commitment_sibling_path.clone();

    c.bench_function(
        "Transfer Circuit - 1 Input, 1 Output: Witness Generation",
        |b| {
            b.iter(|| {
                let circuit_inputs = CircuitInputs::new()
                    .add_old_token_values(black_box(vec![value]))
                    .add_old_token_salts(black_box(vec![token_nonce]))
                    .add_membership_path(black_box(vec![old_commitment_sibling_path.clone()]))
                    .add_membership_path_index(black_box(vec![Fq::from(old_commitment_leaf_index)]))
                    .add_commitment_tree_root(black_box(vec![root]))
                    .add_token_values(black_box(vec![value]))
                    .add_token_salts(black_box(vec![Fq::from(old_commitment_leaf_index)]))
                    .add_token_ids(black_box(vec![token_id]))
                    .add_recipients(black_box(vec![PublicKey::from_affine(token_owner)]))
                    .add_root_key(black_box(root_key))
                    .add_ephemeral_key(black_box(Fq::rand(&mut test_rng())))
                    .build();
                let mut circuit =
                    transfer_circuit::<PallasConfig, VestaConfig, C, N, D>(circuit_inputs).unwrap();

                let public_inputs = circuit.public_input().unwrap();
                assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());

                circuit.finalize_for_arithmetization().unwrap();
            });
        },
    );

    let circuit_inputs = CircuitInputs::new()
        .add_old_token_values(black_box(vec![value]))
        .add_old_token_salts(black_box(vec![token_nonce]))
        .add_membership_path(black_box(vec![old_commitment_sibling_path.clone()]))
        .add_membership_path_index(black_box(vec![Fq::from(old_commitment_leaf_index)]))
        .add_commitment_tree_root(black_box(vec![root]))
        .add_token_values(black_box(vec![value]))
        .add_token_salts(black_box(vec![Fq::from(old_commitment_leaf_index)]))
        .add_token_ids(black_box(vec![token_id]))
        .add_recipients(black_box(vec![PublicKey::from_affine(token_owner)]))
        .add_root_key(black_box(root_key))
        .add_ephemeral_key(black_box(Fq::rand(&mut test_rng())))
        .build();
    let mut circuit =
        transfer_circuit::<PallasConfig, VestaConfig, C, N, D>(circuit_inputs).unwrap();

    let public_inputs = circuit.public_input().unwrap();
    assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());

    circuit.finalize_for_arithmetization().unwrap();
    let srs_size = circuit.srs_size().unwrap();
    let srs =
        <PlonkKzgSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            srs_size,
            &mut test_rng(),
        )
        .unwrap();

    let (pk, _) = PlonkKzgSnark::<VestaConfig>::preprocess(&srs, &circuit).unwrap();
    c.bench_function(
        "Transfer Circuit - 1 Input, 1 Output: Proof Generation",
        |b| {
            b.iter(|| {
                let _ = PlonkKzgSnark::<VestaConfig>::prove::<_, _, StandardTranscript>(
                    &mut test_rng(),
                    &circuit,
                    &pk,
                    None,
                )
                .unwrap();
            });
        },
    );
}

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1);targets = benchmark_mint,benchmark_transfer}
criterion_main!(benches);
