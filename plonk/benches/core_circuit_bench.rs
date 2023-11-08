use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, Fq, Fr};
use ark_std::UniformRand;
use common::crypto::poseidon::Poseidon;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jf_plonk::{
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
};
use jf_relation::{Arithmetization, Circuit};
use jf_utils::{fq_to_fr_with_mask, test_rng};
use plonk_prover::client::circuits::{mint::mint_circuit, transfer::transfer_circuit};
use std::str::FromStr;

pub fn benchmark_mint(c: &mut Criterion) {
    c.bench_function("Mint Circuit - 1 Output: Witness Generation", |b| {
        b.iter(|| {
            let value = Fq::from_str("1").unwrap();
            let token_id = Fq::from_str("2").unwrap();
            let token_nonce = Fq::from_str("3").unwrap();
            let token_owner =
                (EdwardsAffine::generator() * Fr::from_str("4").unwrap()).into_affine();
            let mut circuit = mint_circuit::<ark_ed_on_bn254::EdwardsConfig, ark_bn254::Bn254, 1>(
                [value],
                [token_id],
                [token_nonce],
                [token_owner],
            )
            .unwrap();
            circuit.finalize_for_arithmetization().unwrap();
        })
    });
    c.bench_function("Mint Circuit - 1 Output: Proof Generation", |b| {
        let value = Fq::from_str("1").unwrap();
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from_str("3").unwrap();
        let token_owner =
            (EdwardsAffine::generator() * Fr::from_str("4").unwrap()).into_affine();
        let mut circuit = mint_circuit::<ark_ed_on_bn254::EdwardsConfig, ark_bn254::Bn254, 1>(
            [value],
            [token_id],
            [token_nonce],
            [token_owner],
        )
            .unwrap();
        circuit.finalize_for_arithmetization().unwrap();

        let srs_size = circuit.srs_size().unwrap();
        let srs =
            <PlonkKzgSnark<ark_bn254::Bn254> as UniversalSNARK<ark_bn254::Bn254>>::universal_setup_for_testing(
                srs_size, &mut test_rng(),
            ).unwrap();

        let (pk, _) = PlonkKzgSnark::<ark_bn254::Bn254>::preprocess(&srs, &circuit).unwrap();



        b.iter(|| {
            let _ = PlonkKzgSnark::<ark_bn254::Bn254>::prove::<_, _, StandardTranscript>(
                &mut test_rng(), &circuit, &pk, None,
            ).unwrap();
        })
    });
    c.bench_function("Mint Circuit - 2 Output: Witness Generation", |b| {
        b.iter(|| {
            let value = Fq::from_str("1").unwrap();
            let token_id = Fq::from_str("2").unwrap();
            let token_nonce = Fq::from_str("3").unwrap();
            let token_owner =
                (EdwardsAffine::generator() * Fr::from_str("4").unwrap()).into_affine();
            let mut circuit = mint_circuit::<ark_ed_on_bn254::EdwardsConfig, ark_bn254::Bn254, 2>(
                [value, value],
                [token_id, token_id],
                [token_nonce, token_nonce],
                [token_owner, token_owner],
            )
            .unwrap();
            circuit.finalize_for_arithmetization().unwrap();
        })
    });
    c.bench_function("Mint Circuit - 2 Output: Proof Generation", |b| {
        let value = Fq::from_str("1").unwrap();
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from_str("3").unwrap();
        let token_owner =
            (EdwardsAffine::generator() * Fr::from_str("4").unwrap()).into_affine();
        let mut circuit = mint_circuit::<ark_ed_on_bn254::EdwardsConfig, ark_bn254::Bn254, 2>(
            [value, value],
            [token_id, token_id],
            [token_nonce, token_nonce],
            [token_owner, token_owner],
        )
            .unwrap();
        circuit.finalize_for_arithmetization().unwrap();
        let srs_size = circuit.srs_size().unwrap();
        let srs =
            <PlonkKzgSnark<ark_bn254::Bn254> as UniversalSNARK<ark_bn254::Bn254>>::universal_setup_for_testing(
                srs_size, &mut test_rng(),
            ).unwrap();

        let (pk, _) = PlonkKzgSnark::<ark_bn254::Bn254>::preprocess(&srs, &circuit).unwrap();

        b.iter(|| {
            let _ = PlonkKzgSnark::<ark_bn254::Bn254>::prove::<_, _, StandardTranscript>(
                &mut test_rng(), &circuit, &pk, None,
            ).unwrap();
        })
    });
}

pub fn benchmark_transfer(c: &mut Criterion) {
    let root_key = Fq::rand(&mut test_rng());
    let private_key_domain = Fq::from_str("1").unwrap();
    let nullifier_key_domain = Fq::from_str("2").unwrap();
    let private_key = Poseidon::<Fq>::new()
        .hash(vec![root_key, private_key_domain])
        .unwrap();
    let private_key_trunc: Fr = fq_to_fr_with_mask(&private_key);
    let old_commitment_leaf_index = 0u64; //u32::rand(&mut test_rng());

    let value = Fq::from_str("1").unwrap();
    let token_id = Fq::from_str("2").unwrap();
    let token_nonce = Fq::from(3u32);
    let token_owner = (EdwardsAffine::generator() * private_key_trunc).into_affine();
    let old_commitment_hash = Poseidon::<Fq>::new()
        .hash(vec![
            value,
            token_id,
            token_nonce,
            token_owner.x,
            token_owner.y,
        ])
        .unwrap();

    let old_commitment_sibling_path: [Fq; 48] = (0..48)
        .map(|_| Fq::rand(&mut test_rng()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let root = old_commitment_sibling_path.into_iter().enumerate().fold(
        old_commitment_hash,
        |a, (i, b)| {
            let poseidon: Poseidon<Fq> = Poseidon::new();
            let bit_dir = old_commitment_leaf_index >> i & 1;
            if bit_dir == 0 {
                poseidon.hash(vec![a, b]).unwrap()
            } else {
                poseidon.hash(vec![b, a]).unwrap()
            }
        },
    );

    let recipient_public_key = EdwardsAffine::rand(&mut test_rng());
    let ephemeral_key = Fq::rand(&mut test_rng());

    c.bench_function(
        "Transfer Circuit - 1 Input, 1 Output: Witness Generation",
        |b| {
            b.iter(|| {
                let mut circuit =
                    transfer_circuit::<ark_ed_on_bn254::EdwardsConfig, ark_bn254::Bn254, 1, 1, 48>(
                        black_box([value]),
                        black_box([token_nonce]),
                        black_box([old_commitment_sibling_path]),
                        black_box([Fq::from(old_commitment_leaf_index)]),
                        black_box(root),
                        black_box([value]),
                        black_box([Fq::from(old_commitment_leaf_index)]),
                        black_box(token_id),
                        black_box(recipient_public_key),
                        black_box(root_key),
                        black_box(ephemeral_key),
                        black_box(private_key_domain),
                        black_box(nullifier_key_domain),
                    )
                    .unwrap();

                let public_inputs = circuit.public_input().unwrap();
                assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());

                circuit.finalize_for_arithmetization().unwrap();
            });
        },
    );

    let mut circuit =
        transfer_circuit::<ark_ed_on_bn254::EdwardsConfig, ark_bn254::Bn254, 1, 1, 48>(
            black_box([value]),
            black_box([token_nonce]),
            black_box([old_commitment_sibling_path]),
            black_box([Fq::from(old_commitment_leaf_index)]),
            black_box(root),
            black_box([value]),
            black_box([Fq::from(old_commitment_leaf_index)]),
            black_box(token_id),
            black_box(recipient_public_key),
            black_box(root_key),
            black_box(ephemeral_key),
            black_box(private_key_domain),
            black_box(nullifier_key_domain),
        )
        .unwrap();

    let public_inputs = circuit.public_input().unwrap();
    assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());

    circuit.finalize_for_arithmetization().unwrap();
    let srs_size = circuit.srs_size().unwrap();
    let srs =
        <PlonkKzgSnark<ark_bn254::Bn254> as UniversalSNARK<ark_bn254::Bn254>>::universal_setup_for_testing(
            srs_size, &mut test_rng(),
        ).unwrap();

    let (pk, _) = PlonkKzgSnark::<ark_bn254::Bn254>::preprocess(&srs, &circuit).unwrap();
    c.bench_function(
        "Transfer Circuit - 1 Input, 1 Output: Proof Generation",
        |b| {
            b.iter(|| {
                let _ = PlonkKzgSnark::<ark_bn254::Bn254>::prove::<_, _, StandardTranscript>(
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
