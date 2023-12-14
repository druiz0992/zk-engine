
use crate::{
    client::circuits::transfer::transfer_circuit,
    rollup::circuits::{
        base::{base_rollup_circuit, ClientInput},
        bounce::bounce_circuit,
        merge::merge_circuit,
        structs::{AccInstance, GlobalPublicInputs, SubTrees},
        utils::StoredProof,
    },
};
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::Zero;
use ark_std::UniformRand;
use common::crypto::poseidon::Poseidon;
use curves::{
    pallas::{Affine, Fq, Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_plonk::{
    nightfall::{ipa_structs::VerifyingKey, PlonkIpaSnark},
    proof_system::{structs::VK, UniversalSNARK},
    transcript::RescueTranscript,
};
use jf_primitives::pcs::StructuredReferenceString;
use jf_relation::{
    gadgets::ecc::short_weierstrass::SWPoint, Arithmetization, Circuit, PlonkCircuit,
};
use jf_utils::{field_switching, fq_to_fr_with_mask, test_rng};
use std::str::FromStr;
use trees::{
    membership_tree::{MembershipTree, Tree},
    non_membership_tree::{IndexedMerkleTree, IndexedNode, NonMembershipTree},
    tree::AppendTree,
};

pub fn tree_generator(
    vks: Vec<VerifyingKey<VestaConfig>>,
    comms: Vec<Fq>,
    nullifiers: Vec<Fq>,
    global_comm_roots: Vec<Fr>,
) -> (
    Tree<Fr, 2>,
    Tree<Fq, 8>,
    IndexedMerkleTree<Fr, 32>,
    Tree<Fr, 8>,
) {
    // Vk trees
    let poseidon: Poseidon<Fr> = Poseidon::new();
    let vk_hashes = vks.iter().map(|vk| {
        let vk_sigmas = vk.sigma_comms();
        let vk_selectors = vk.selector_comms();
        let vk_sigma_hashes = vk_sigmas
            .iter()
            .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
        let vk_selector_hashes = vk_selectors
            .iter()
            .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
        let vk_hashes = vk_sigma_hashes
            .chain(vk_selector_hashes)
            .collect::<Vec<_>>();
        let outlier_pair = vk_hashes[0..2].to_vec();
        let mut total_leaves = vk_hashes[2..].to_vec();
        for _ in 0..4 {
            let lefts = total_leaves.iter().step_by(2);
            let rights = total_leaves.iter().skip(1).step_by(2);
            let pairs = lefts.zip(rights);
            total_leaves = pairs
                .map(|(&x, &y)| poseidon.hash_unchecked(vec![x, y]))
                .collect::<Vec<_>>();
        }
        poseidon.hash_unchecked(vec![outlier_pair[0], outlier_pair[1], total_leaves[0]])
    });

    let vk_tree: Tree<Fr, 2> = Tree::from_leaves(vk_hashes.collect::<Vec<_>>());

    // commitment trees
    let commitment_tree: Tree<Fq, 8> = Tree::from_leaves(comms);
    // nullifier trees
    let lifted_nullifiers = nullifiers
        .iter()
        .map(field_switching::<Fq, Fr>)
        .collect::<Vec<_>>();
    let nullifier_tree: IndexedMerkleTree<Fr, 32> =
        IndexedMerkleTree::from_leaves(lifted_nullifiers);
    // global root tree
    let global_root_tree: Tree<Fr, 8> = Tree::from_leaves(global_comm_roots);
    (vk_tree, commitment_tree, nullifier_tree, global_root_tree)
}

pub fn transfer_circuit_helper_generator<const C: usize, const N: usize>(
    value: [Fq; N],
    old_sib_path: [[Fq; 8]; N],
    root: [Fq; N],
    old_leaf_index: [u64; N],
) -> (PlonkCircuit<Fq>, ([Fq; N], [Fq; C], [Fq; 2], [Fq; 3])) {
    let recipient_public_key = Affine::rand(&mut test_rng());
    let ephemeral_key = Fq::rand(&mut test_rng());
    let token_id = Fq::from_str("2").unwrap();
    let root_key = Fq::rand(&mut test_rng());
    let private_key_domain = Fq::from_str("1").unwrap();
    let nullifier_key_domain = Fq::from_str("2").unwrap();

    let token_nonce = Fq::from(3u32);
    let indices = old_leaf_index
        .iter()
        .map(|i| Fq::from(*i))
        .collect::<Vec<_>>();
    let total_value = value.iter().fold(Fq::zero(), |acc, x| acc + x);
    let mut new_values = [Fq::from(0 as u32); C];
    if C > 1 {
        new_values[0] = total_value - Fq::from(1 as u32);
        new_values[1] = Fq::from(1 as u32);
    } else {
        new_values[0] = total_value;
    }

    let circuit = transfer_circuit::<PallasConfig, VestaConfig, N, C, 8>(
        value,
        [token_nonce; N],
        old_sib_path.try_into().unwrap(),
        indices.clone().try_into().unwrap(),
        root,
        new_values,
        indices[0..C].try_into().unwrap(),
        token_id,
        recipient_public_key,
        root_key,
        ephemeral_key,
        private_key_domain,
        nullifier_key_domain,
    )
    .unwrap();

    let public_inputs = circuit.public_input().unwrap();
    let len = public_inputs.len();
    assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());

    let client_input = (
        public_inputs[N + 1..=2 * N].try_into().unwrap(), // nullifiers
        public_inputs[2 * N + 1..=2 * N + C].try_into().unwrap(), // new commitments
        public_inputs[len - 5..len - 3].try_into().unwrap(), // eph pub key
        public_inputs[len - 3..len].try_into().unwrap(),  // ciphertext
    );
    (circuit, client_input)
}

pub fn base_circuit_helper_generator<const I: usize, const C: usize, const N: usize>(
) -> StoredProof<PallasConfig, VestaConfig> {
    // Below taken from test_base_rollup_helper_transfer
    let poseidon = Poseidon::<Fq>::new();
    let root_key = Fq::rand(&mut test_rng());
    let private_key_domain = Fq::from_str("1").unwrap();
    let private_key: Fq = Poseidon::<Fq>::new()
        .hash(vec![root_key, private_key_domain])
        .unwrap();

    let private_key_fr: Fr = fq_to_fr_with_mask(&private_key);

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
        let token_owner = (PallasConfig::GENERATOR * private_key_fr).into_affine();

        let mint_values: [Fq; N] =
            ark_std::array::from_fn(|index| Fq::from((index + i * N) as u32));
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
        let prev_commitment_tree = Tree::<Fq, 8>::from_leaves(mint_commitments.clone());
        let mut old_sib_paths: [[Fq; 8]; N] = [[Fq::zero(); 8]; N];
        for j in 0..N {
            old_sib_paths[j] = prev_commitment_tree
                .membership_witness(j)
                .unwrap()
                .try_into()
                .unwrap();
        }
        let (mut transfer_circuit, transfer_inputs) = transfer_circuit_helper_generator::<C, N>(
            mint_values,
            old_sib_paths,
            [prev_commitment_tree.root.0; N],
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
                    low_null.node.value,
                    Fr::from(low_null.tree_index as u64),
                    low_null.node.next_value,
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
            commitment_tree_root: [prev_commitment_tree.root.0; N],
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
        global_comm_roots.push(field_switching(&prev_commitment_tree.root.0));
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

    let pallas_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        )
        .unwrap();
    let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(21)).unwrap();

    let initial_nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();

    ark_std::println!("Creating Base Circuit");

    let (mut base_circuit, pi_star) = base_rollup_circuit::<VestaConfig, PallasConfig, I, C, N>(
        client_inputs.try_into().unwrap(),
        vk_tree.root.0,
        init_nullifier_root,
        initial_nullifier_tree.leaf_count.into(),
        global_comm_tree.root.0,
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

    let (base_ipa_pk, base_ipa_vk) =
        PlonkIpaSnark::<PallasConfig>::preprocess(&base_ipa_srs, &base_circuit).unwrap();

    let (base_ipa_proof, g_poly, _) = PlonkIpaSnark::<PallasConfig>::prove_for_partial::<
        _,
        _,
        RescueTranscript<<PallasConfig as Pairing>::BaseField>,
    >(&mut rng, &base_circuit, &base_ipa_pk, None)
    .unwrap();

    ark_std::println!("Created Base Proof");

    let public_inputs = base_circuit.public_input().unwrap();
    let global_public_inputs = GlobalPublicInputs::from_vec(public_inputs.clone());
    let subtree_pi = SubTrees::from_vec(public_inputs[5..=6].to_vec());
    let instance: AccInstance<VestaConfig> = AccInstance {
        comm: SWPoint(
            public_inputs[7],
            public_inputs[8],
            public_inputs[7] == Fr::zero(),
        ),
        // values are originally Vesta scalar => safe switch back into 'native'
        eval: field_switching(&public_inputs[9]),
        eval_point: field_switching(&public_inputs[10]),
    };

    StoredProof {
        proof: base_ipa_proof,
        pub_inputs: (global_public_inputs, subtree_pi, instance, vec![]),
        vk: base_ipa_vk,
        commit_key: (pallas_commit_key, vesta_commit_key),
        g_poly,
        pi_stars: (Default::default(), pi_star),
    }
}

pub fn bounce_circuit_helper_generator<const I: usize, const N: usize, const C: usize>(
) -> StoredProof<VestaConfig, PallasConfig> {
    // Below taken from bounce_test_helper
    let mut rng = test_rng();
    ark_std::println!("Creating Bounce Circuit");
    let stored_proof_base = base_circuit_helper_generator::<I, C, N>();
    let (global_public_inputs, subtree_public_inputs, passthrough_instance, _) =
        stored_proof_base.pub_inputs;
    let (mut bounce_circuit, public_outputs) = bounce_circuit::<PallasConfig, VestaConfig>(
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
    let (bounce_ipa_pk, bounce_ipa_vk) =
        PlonkIpaSnark::<VestaConfig>::preprocess(&bounce_ipa_srs, &bounce_circuit).unwrap();
    let (bounce_ipa_proof, g_poly, _) = PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
        _,
        _,
        RescueTranscript<<VestaConfig as Pairing>::BaseField>,
    >(&mut rng, &bounce_circuit, &bounce_ipa_pk, None)
    .unwrap();
    ark_std::println!("Created Bounce Proof");
    // This is the Vesta acc calculated in base
    let passthrough = AccInstance {
        comm: SWPoint(
            public_outputs[7],
            public_outputs[8],
            public_outputs[7] == Fr::zero(),
        ),
        // These are originally Vesta Fr => small => safe conversion
        eval: field_switching(&public_outputs[9]),
        eval_point: field_switching(&public_outputs[10]),
    };

    // This is the Pallas acc we just made by Pv'ing base
    let instance = AccInstance {
        // This is originally a Pallas point => safe conversion
        comm: SWPoint(
            field_switching(&public_outputs[public_outputs.len() - 4]),
            field_switching(&public_outputs[public_outputs.len() - 3]),
            public_outputs[public_outputs.len() - 4] == Fr::zero(),
        ),
        eval: public_outputs[public_outputs.len() - 2], // = 0 because we only PV one base
        eval_point: public_outputs[public_outputs.len() - 1],
    };

    StoredProof::<VestaConfig, PallasConfig> {
        proof: bounce_ipa_proof,
        pub_inputs: (
            global_public_inputs,
            subtree_public_inputs,
            instance,
            vec![passthrough],
        ),
        vk: bounce_ipa_vk,
        commit_key: stored_proof_base.commit_key,
        g_poly,
        pi_stars: (
            [stored_proof_base.g_poly].to_vec(),
            stored_proof_base.pi_stars.1,
        ),
    }
}

pub fn merge_circuit_helper_generator<const I: usize, const N: usize, const C: usize>(
) -> StoredProof<PallasConfig, VestaConfig> {
    // Below taken from merge_test_helper
    let mut rng = test_rng();
    let stored_bounce = bounce_circuit_helper_generator::<I, C, N>();
    let stored_bounce_2 = stored_bounce.clone();
    let (global_public_inputs, subtree_pi_1, passthrough_instance_1, instance_1) =
        stored_bounce.pub_inputs;
    let (_, subtree_pi_2, passthrough_instance_2, instance_2) = stored_bounce_2.pub_inputs;
    ark_std::println!("Creating Merge Circuit");
    let (mut merge_circuit, pi_star_out) = merge_circuit::<VestaConfig, PallasConfig>(
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
    let (merge_ipa_pk, merge_ipa_vk) =
        PlonkIpaSnark::<PallasConfig>::preprocess(&merge_ipa_srs, &merge_circuit).unwrap();

    let (merge_ipa_proof, g_poly, _) = PlonkIpaSnark::<PallasConfig>::prove_for_partial::<
        _,
        _,
        RescueTranscript<<PallasConfig as Pairing>::BaseField>,
    >(&mut rng, &merge_circuit, &merge_ipa_pk, None)
    .unwrap();

    ark_std::println!("Created Merge Proof");

    let all_pi = merge_circuit.public_input().unwrap();
    let st = SubTrees {
        commitment_subtree: all_pi[all_pi.len() - 2],
        nullifier_subtree: all_pi[all_pi.len() - 1],
    };
    let instance = AccInstance {
        comm: SWPoint(
            all_pi[all_pi.len() - 6],
            all_pi[all_pi.len() - 5],
            all_pi[all_pi.len() - 6] == Fr::zero(),
        ),
        eval: field_switching(&all_pi[all_pi.len() - 4]),
        eval_point: field_switching(&all_pi[all_pi.len() - 3]),
    };
    StoredProof::<PallasConfig, VestaConfig> {
        proof: merge_ipa_proof,
        pub_inputs: (
            global_public_inputs,
            st,
            instance,
            vec![passthrough_instance_1, passthrough_instance_2],
        ),
        vk: merge_ipa_vk,
        commit_key: stored_bounce.commit_key.clone(),
        g_poly,
        pi_stars: (
            [
                stored_bounce.pi_stars.0[0].clone(),
                stored_bounce_2.pi_stars.0[0].clone(),
            ]
            .to_vec(),
            pi_star_out,
        ), // TODO do we need 3 here?
    }
}
