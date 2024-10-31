use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use common::crypto::poseidon::Poseidon;
use common::derived_keys::DerivedKeys;
use common::keypair::PublicKey;
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
use jf_utils::{field_switching, test_rng};
use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
use plonk_prover::utils::bench_utils::{transfer_circuit_helper_generator, tree_generator};
use plonk_prover::{
    client::circuits::mint::mint_circuit,
    rollup::circuits::base::{base_rollup_circuit, ClientInput},
};
use std::str::FromStr;
use trees::{
    membership_tree::{MembershipTree, Tree},
    non_membership_tree::{IndexedMerkleTree, IndexedNode, NonMembershipTree},
    tree::AppendTree,
};

pub fn benchmark_mints<const I: usize, const C: usize, const N: usize, const D: usize>(
    c: &mut Criterion,
) {
    const D: usize = 0;
    const N: usize = 0;

    // Below taken from test_base_rollup_helper_mint
    let mut rng = test_rng();
    let mut client_inputs = vec![];
    let mut g_polys = vec![];
    let mut mint_ipa_srs = Default::default(); // avoid re-generating
                                               // Can't do the below as no default exists
                                               // let mut mint_ipa_vk= VerifyingKey::dummy(1, 2^10);
                                               // let mut mint_ipa_pk= ProvingKey { sigmas: Default::default()};
    ark_std::println!("Creating {} Mint Circuits", I);
    for i in 0..I {
        let value = ark_std::array::from_fn::<_, C, _>(|j| Fq::from((j + i) as u32));
        let token_id = [Fq::from(12 as u64); C];
        let token_nonce = [Fq::from(13 as u64); C];
        let secret_key = Fq::from_str("4").unwrap();
        let secret_key_fr = field_switching::<Fq, Fr>(&secret_key);
        let token_owner = (PallasConfig::GENERATOR * secret_key_fr).into_affine();

        let mut circuit_inputs_builder = CircuitInputs::<PallasConfig, C, N, D>::new();
        let circuit_inputs = circuit_inputs_builder
            .add_token_values(value.to_vec())
            .add_token_ids(token_id.to_vec())
            .add_token_salts(token_nonce.to_vec())
            .add_recipients(vec![PublicKey::from_affine(token_owner); C])
            .build();

        let mut mint_circuit =
            mint_circuit::<PallasConfig, VestaConfig, C, N, D>(circuit_inputs).unwrap();

        mint_circuit.finalize_for_arithmetization().unwrap();
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

        let client_input: ClientInput<VestaConfig, C, 1> = ClientInput {
            proof: mint_ipa_proof,
            swap_field: false,
            nullifiers: [Fq::zero()],
            commitments: mint_circuit.public_input().unwrap()[3..3 + C]
                .try_into()
                .unwrap(),
            commitment_tree_root: [Fq::zero()],
            path_comm_tree_root_to_global_tree_root: [[Fr::zero(); 8]; 1],
            path_comm_tree_index: [Fr::zero()],
            low_nullifier: [Default::default()],
            low_nullifier_indices: [Fr::one()],
            low_nullifier_mem_path: [[Fr::zero(); 32]],
            vk_paths: [Fr::zero(); 2], // filled later
            vk_path_index: Fr::from(0u64),
            vk: mint_ipa_vk.clone(),
            eph_pub_key: [Fr::zero(); 2],
            ciphertext: [Fq::zero(); 3],
        };

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
    let (mut base_circuit, _) = base_rollup_circuit::<VestaConfig, PallasConfig, I, C, 1>(
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
    // Below taken from test_base_rollup_helper_transfer
    let poseidon = Poseidon::<Fq>::new();
    let root_key = Fq::rand(&mut test_rng());
    let derived_keys = DerivedKeys::<PallasConfig>::new(root_key).unwrap();
    let token_owner = derived_keys.public_key;

    let mut rng = test_rng();
    let mut client_inputs = vec![];
    let mut global_comm_roots: Vec<Fr> = vec![];
    let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
    let mut init_nullifier_root = Fr::zero();
    let mut g_polys = vec![];
    let mut transfer_ipa_srs = Default::default(); // avoid re-generating

    ark_std::println!("Creating {} Transfer Circuits", I);

    for i in 0..I {
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from(3u32);

        let mint_values: [Fq; N] =
            ark_std::array::from_fn(|index| Fq::from((index + i * N + 1) as u32));
        let mint_commitments = mint_values
            .into_iter()
            .map(|v| {
                poseidon.hash_unchecked(vec![
                    v,
                    token_id,
                    token_nonce,
                    token_owner.x,
                    token_owner.y,
                ])
            })
            .collect::<Vec<_>>();
        let prev_commitment_tree = Tree::<Fq, D>::from_leaves(mint_commitments.clone());
        let mut old_sib_paths: [[Fq; 8]; N] = [[Fq::zero(); 8]; N];

        for j in 0..N {
            old_sib_paths[j] = prev_commitment_tree
                .membership_witness(j)
                .unwrap()
                .try_into()
                .unwrap();
        }
        let (mut transfer_circuit, transfer_inputs) = transfer_circuit_helper_generator::<C, N, D>(
            mint_values,
            old_sib_paths,
            [prev_commitment_tree.root(); N],
            ark_std::array::from_fn(|i| i as u64),
        );
        transfer_circuit.finalize_for_arithmetization().unwrap();
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

        let nullifiers = transfer_inputs.0;
        let lifted_nullifiers = nullifiers
            .iter()
            .map(field_switching::<Fq, Fr>)
            .collect::<Vec<_>>();
        let mut low_nullifiers: [IndexedNode<Fr>; N] =
            [IndexedNode::new(Fr::zero(), 0, Fr::zero()); N];
        let mut low_indices: [Fr; N] = [Fr::zero(); N];
        let mut low_paths: [[Fr; 32]; N] = [[Fr::zero(); 32]; N];
        for (j, null) in lifted_nullifiers.iter().enumerate() {
            let low_null = nullifier_tree.find_predecessor(*null);
            low_nullifiers[j] = low_null.node.clone();
            low_paths[j] = nullifier_tree
                .non_membership_witness(*null)
                .unwrap()
                .try_into()
                .unwrap();
            low_indices[j] = Fr::from(low_null.tree_index as u32);
            // TODO what was this before? Can't we get the root from the tree initially?
            if i == 0 && j == 0 {
                let this_poseidon = Poseidon::<Fr>::new();
                let low_nullifier_hash = this_poseidon.hash_unchecked(vec![
                    low_null.node.value(),
                    Fr::from(low_null.tree_index as u64),
                    low_null.node.next_value(),
                ]);

                init_nullifier_root = nullifier_tree
                    .non_membership_witness(*null)
                    .unwrap()
                    .into_iter()
                    .enumerate()
                    .fold(low_nullifier_hash, |acc, (i, curr)| {
                        if low_null.tree_index >> i & 1 == 0 {
                            this_poseidon.hash_unchecked(vec![acc, curr])
                        } else {
                            this_poseidon.hash(vec![curr, acc]).unwrap()
                        }
                    });
            }
            // nullifier_tree.append_leaf(null);
            nullifier_tree.update_low_nullifier(*null);
        }

        let client_input: ClientInput<VestaConfig, C, N> = ClientInput {
            proof: transfer_ipa_proof,
            swap_field: false,
            nullifiers,
            commitments: transfer_inputs.1,
            commitment_tree_root: [prev_commitment_tree.root(); N],
            path_comm_tree_root_to_global_tree_root: [[Fr::zero(); 8]; N], // filled later
            path_comm_tree_index: [Fr::zero(); N],                         // filled later
            low_nullifier: low_nullifiers,
            low_nullifier_indices: low_indices,
            low_nullifier_mem_path: low_paths,
            vk_paths: [Fr::zero(); 2], // filled later
            vk_path_index: Fr::zero(),
            vk: transfer_ipa_vk.clone(),
            eph_pub_key: [
                field_switching(&transfer_inputs.2[0]),
                field_switching(&transfer_inputs.2[1]),
            ],
            ciphertext: transfer_inputs.3,
        };

        client_inputs.push(client_input);
        global_comm_roots.push(field_switching(&prev_commitment_tree.root()));
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
    let (mut base_circuit, _) = base_rollup_circuit::<VestaConfig, PallasConfig, I, C, N>(
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
