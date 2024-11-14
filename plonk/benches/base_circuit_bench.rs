use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};
use curves::{
    pallas::{Fq, Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_plonk::{
    nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
};
use jf_primitives::pcs::StructuredReferenceString;
use jf_relation::{Arithmetization, Circuit};
use jf_utils::field_switching;
use plonk_prover::client::PlonkCircuitParams;
use plonk_prover::rollup::circuits::client_input::ClientInputBuilder;
use plonk_prover::utils::bench::tree::tree_generator;
use plonk_prover::{
    client::circuits::mint, rollup::circuits::base::base_rollup_circuit,
    rollup::circuits::client_input::ClientInput,
};
use plonk_prover::{client::circuits::transfer, rollup::circuits::client_input::LowNullifierInfo};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use trees::{
    membership_tree::MembershipTree, non_membership_tree::IndexedMerkleTree, tree::AppendTree,
};

pub fn benchmark_mints<const I: usize, const C: usize, const N: usize, const D: usize>(
    c: &mut Criterion,
) {
    // Below taken from test_base_rollup_helper_mint
    let mut rng = ChaChaRng::from_entropy();
    let mut client_inputs = vec![];
    let mut g_polys = vec![];
    let mut mint_ipa_srs = Default::default(); // avoid re-generating
                                               // Can't do the below as no default exists
                                               // let mut mint_ipa_vk= VerifyingKey::dummy(1, 2^10);
                                               // let mut mint_ipa_pk= ProvingKey { sigmas: Default::default()};
    ark_std::println!("Creating {} Mint Circuits", I);
    let token_id = Some(Fq::rand(&mut rng));
    for i in 0..I {
        let PlonkCircuitParams {
            circuit: mint_circuit,
            public_inputs: mint_inputs,
        } = mint::utils::mint_with_random_inputs::<PallasConfig, VestaConfig, _, C>(token_id)
            .unwrap();
        if i == 0 {
            mint_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
                mint_circuit.srs_size().unwrap(),
                &mut rng,
            ).unwrap();
        }
        let (mint_ipa_pk, mint_ipa_vk) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&mint_ipa_srs, &mint_circuit).unwrap();
        let (mint_ipa_proof, g_poly, _) = PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
            _,
            _,
            RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        >(&mut rng, &mint_circuit, &mint_ipa_pk, None)
        .unwrap();

        let input_builder = ClientInputBuilder::<VestaConfig, C, 1, D>::new();
        let mut client_input =
            ClientInput::<VestaConfig, C, 1, D>::new(mint_ipa_proof, mint_ipa_vk.clone());
        client_input.set_commitments(
            input_builder
                .to_commitments_array(mint_inputs.commitments)
                .unwrap(),
        );

        client_inputs.push(client_input);
        g_polys.push(g_poly);
    }
    ark_std::println!("Created {} Mint Proofs", I);
    let (vk_tree, _, nullifier_tree, global_comm_tree) =
        tree_generator(vec![client_inputs[0].vk.clone()], vec![], vec![], vec![]);
    let vesta_srs =
        <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        )
        .unwrap();
    let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(21)).unwrap();

    // BELOW - if we want to bench witness gen, uncomment
    // ==================================================
    // let mut base_circuit = Default::default();
    // let mut base_ipa_srs = Default::default();
    // c.bench_function("Base with I Mints - Output: Witness Generation", |b| {
    //     b.iter(|| {
    //         let (mut base_rollup_circuit, _) =
    //         base_rollup_circuit::<VestaConfig, PallasConfig, I, C, 1>(
    //             client_inputs.clone().try_into().unwrap(),
    //             vk_tree.root(),
    //             nullifier_tree.root,
    //             nullifier_tree.leaf_count.into(),
    //             global_comm_tree.root(),
    //             g_polys.clone().try_into().unwrap(),
    //             vesta_commit_key.clone(),
    //         )
    //         .unwrap();
    //         base_rollup_circuit.finalize_for_arithmetization().unwrap();
    //         base_ipa_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
    //             base_rollup_circuit.srs_size().unwrap(),
    //             &mut rng,
    //         ).unwrap();
    //         base_circuit = base_rollup_circuit;
    //     })
    // });
    // ==================================================

    // BELOW - if we DON'T want to bench witness gen, comment
    // ==================================================
    let (mut base_circuit, _) = base_rollup_circuit::<VestaConfig, PallasConfig, I, C, 1, D>(
        client_inputs.clone().try_into().unwrap(),
        vk_tree.root(),
        nullifier_tree.root(),
        (nullifier_tree.leaf_count() as u64).into(),
        global_comm_tree.root(),
        g_polys.clone().try_into().unwrap(),
        vesta_commit_key.clone(),
    )
    .unwrap();
    base_circuit
        .check_circuit_satisfiability(&base_circuit.public_input().unwrap())
        .unwrap();
    base_circuit.finalize_for_arithmetization().unwrap();
    let base_ipa_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            base_circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();
    // ==================================================
    // we must preprocess here because there is no pk default to init
    let (base_ipa_pk, _) =
        PlonkIpaSnark::<PallasConfig>::preprocess(&base_ipa_srs, &base_circuit).unwrap();
    c.bench_function("Base with I Mints - Output: Proof Generation", |b| {
        let mut n = 0;
        b.iter(|| {
            ark_std::println!("Iteration {n}");
            n += 1;
            let _ = PlonkIpaSnark::<PallasConfig>::prove::<
                _,
                _,
                RescueTranscript<<PallasConfig as Pairing>::BaseField>,
            >(&mut rng, &base_circuit, &base_ipa_pk, None)
            .unwrap();
        })
    });
}

pub fn benchmark_transfers<const I: usize, const C: usize, const N: usize, const D: usize>(
    c: &mut Criterion,
) {
    let mut rng = ChaChaRng::from_entropy();
    let mut client_inputs = vec![];
    let mut global_comm_roots: Vec<Fr> = vec![];
    let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
    let init_nullifier_root = nullifier_tree.root();
    let mut g_polys = vec![];
    let mut transfer_ipa_srs = Default::default(); // avoid re-generating

    ark_std::println!("Creating {} Transfer Circuits", I);
    let token_id = Some(Fq::rand(&mut rng));

    for i in 0..I {
        let PlonkCircuitParams {
            circuit: transfer_circuit,
            public_inputs: transfer_inputs,
        } = transfer::utils::transfer_with_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
            token_id,
        )
        .unwrap();
        if i == 0 {
            transfer_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
                transfer_circuit.srs_size().unwrap(),
                &mut rng,
            ).unwrap();
        }

        let (transfer_ipa_pk, transfer_ipa_vk) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&transfer_ipa_srs, &transfer_circuit).unwrap();

        let (transfer_ipa_proof, g_poly, _) =
            PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(&mut rng, &transfer_circuit, &transfer_ipa_pk, None)
            .unwrap();
        g_polys.push(g_poly);

        let input_builder = ClientInputBuilder::<VestaConfig, C, N, D>::new();
        let mut client_input =
            ClientInput::<VestaConfig, C, N, D>::new(transfer_ipa_proof, transfer_ipa_vk.clone());

        let switched_root: <VestaConfig as Pairing>::BaseField =
            field_switching(&transfer_inputs.commitment_root[0]);
        let nullifiers = input_builder
            .to_nullifiers_array(transfer_inputs.nullifiers)
            .unwrap();
        let LowNullifierInfo {
            nullifiers: low_nullifier,
            indices: low_nullifier_indices,
            paths: low_nullifier_mem_path,
        } = input_builder.update_nullifier_tree(&mut nullifier_tree, nullifiers);

        client_input
            .set_nullifiers(nullifiers)
            .set_commitments(
                input_builder
                    .to_commitments_array(transfer_inputs.commitments)
                    .unwrap(),
            )
            .set_commitment_tree_root(
                input_builder
                    .to_commitments_tree_root_array(transfer_inputs.commitment_root)
                    .unwrap(),
            )
            .set_low_nullifier_info(low_nullifier, low_nullifier_indices, low_nullifier_mem_path)
            .set_eph_pub_key(
                input_builder
                    .to_eph_key_array(transfer_inputs.ephemeral_public_key)
                    .unwrap(),
            )
            .set_ciphertext(
                input_builder
                    .to_ciphertext_array(transfer_inputs.ciphertexts)
                    .unwrap(),
            );

        client_inputs.push(client_input);
        global_comm_roots.push(switched_root);
    }
    ark_std::println!("Created {} Transfer Proofs", I);
    // all have the same vk
    let vks = vec![client_inputs[0].vk.clone()];
    let comms: Vec<Fq> = vec![];

    let (vk_tree, _, _, global_comm_tree) = tree_generator(vks, comms, vec![], global_comm_roots);

    for (i, ci) in client_inputs.iter_mut().enumerate() {
        let global_root_path = global_comm_tree
            .membership_witness(i)
            .unwrap()
            .try_into()
            .unwrap();
        ci.path_comm_tree_root_to_global_tree_root = [global_root_path; N];
        ci.path_comm_tree_index = [Fr::from(i as u32); N];
        ci.vk_paths = vk_tree.membership_witness(0).unwrap().try_into().unwrap();
        // vk index is already (correctly) zero
    }

    let vesta_srs =
        <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        )
        .unwrap();
    let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(21)).unwrap();

    let initial_nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();

    // BELOW - if we want to bench witness gen, uncomment
    // ==================================================
    // let mut base_circuit = Default::default();
    // let mut base_ipa_srs = Default::default();
    // c.bench_function("Base with I Tranfers - Output: Witness Generation", |b| {
    //     b.iter(|| {
    //         let (mut base_rollup_circuit, _) =
    //         base_rollup_circuit::<VestaConfig, PallasConfig, I, C, N>(
    //             client_inputs.clone().try_into().unwrap(),
    //             vk_tree.root(),
    //             init_nullifier_root,
    //             initial_nullifier_tree.leaf_count.into(),
    //             global_comm_tree.root(),
    //             g_polys.clone().try_into().unwrap(),
    //             vesta_commit_key.clone(),
    //         )
    //         .unwrap();
    //         base_rollup_circuit.finalize_for_arithmetization().unwrap();
    //         base_ipa_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
    //             base_rollup_circuit.srs_size().unwrap(),
    //             &mut rng,
    //         ).unwrap();
    //         base_circuit = base_rollup_circuit;
    //     })
    // });
    // ==================================================

    // BELOW - if we DON'T want to bench witness gen, comment
    // ==================================================
    let (mut base_circuit, _) = base_rollup_circuit::<VestaConfig, PallasConfig, I, C, N, D>(
        client_inputs.try_into().unwrap(),
        vk_tree.root(),
        init_nullifier_root,
        (initial_nullifier_tree.leaf_count() as u64).into(),
        global_comm_tree.root(),
        g_polys.try_into().unwrap(),
        vesta_commit_key.clone(),
    )
    .unwrap();
    base_circuit
        .check_circuit_satisfiability(&base_circuit.public_input().unwrap())
        .unwrap();
    base_circuit.finalize_for_arithmetization().unwrap();
    let base_ipa_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            base_circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();
    // ==================================================
    // we must preprocess here because there is no pk default to init
    let (base_ipa_pk, _) =
        PlonkIpaSnark::<PallasConfig>::preprocess(&base_ipa_srs, &base_circuit).unwrap();
    c.bench_function("Base with I Transfers - Output: Proof Generation", |b| {
        let mut n = 0;
        b.iter(|| {
            ark_std::println!("Iteration {n}");
            n += 1;
            let _ = PlonkIpaSnark::<PallasConfig>::prove::<
                _,
                _,
                RescueTranscript<<PallasConfig as Pairing>::BaseField>,
            >(&mut rng, &base_circuit, &base_ipa_pk, None)
            .unwrap();
        })
    });
}

criterion_group! {name = benches; config = Criterion::default().significance_level(0.1).sample_size(10);targets = benchmark_mints::<2, 2,1,8>, benchmark_transfers::<2, 1, 2, 8>}
criterion_main!(benches);
