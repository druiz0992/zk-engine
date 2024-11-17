#[cfg(test)]
use super::base_rollup_circuit;
use crate::client::circuits::swap::swap_circuit;
use crate::rollup::circuits::client_input::{self, LowNullifierInfo};
use crate::rollup::circuits::utils::StoredProof;
use crate::utils::bench;
use crate::utils::bench::base::{self, TransactionType};
use crate::utils::bench::tree::tree_generator_from_client_inputs;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_std::UniformRand;
use client_input::ClientInput;
use common::crypto::poseidon::Poseidon;
use curves::pallas::Affine as PAffine;
use curves::pallas::{Fq, Fr, PallasConfig};
use curves::vesta::VestaConfig;
use jf_plonk::nightfall::PlonkIpaSnark;
use jf_plonk::proof_system::UniversalSNARK;
use jf_plonk::transcript::RescueTranscript;
use jf_relation::PlonkCircuit;
use jf_relation::{Arithmetization, Circuit};
use jf_utils::{field_switching, fq_to_fr_with_mask, test_rng};
use std::str::FromStr;
use trees::membership_tree::{MembershipTree, Tree};
use trees::non_membership_tree::IndexedMerkleTree;
use trees::non_membership_tree::NonMembershipTree;
use trees::tree::AppendTree;

#[test]
fn test_base_circuit() {
    test_base_rollup_helper::<8>(&[TransactionType::Mint, TransactionType::Mint]);
    //test_base_rollup_helper::<8>(&[
    //    TransactionType::Mint,
    //    TransactionType::Mint,
    //    TransactionType::Mint,
    //    TransactionType::Mint,
    //]);

    test_base_rollup_helper::<8>(&[TransactionType::Transfer, TransactionType::Transfer]);
    //test_base_rollup_helper::<8>(&[
    //TransactionType::Transfer,
    //TransactionType::Transfer,
    //TransactionType::Transfer,
    //TransactionType::Transfer,
    //]);

    //test_base_rollup_helper::<8>(&[TransactionType::Mint, TransactionType::Transfer]);
    test_base_rollup_helper::<8>(&[
        TransactionType::Mint,
        TransactionType::Transfer,
        TransactionType::Transfer,
        TransactionType::Mint,
    ]);

    test_base_rollup_helper_swap::<8>();
}

pub fn test_base_rollup_helper<const D: usize>(
    transaction_sequence: &[TransactionType],
) -> StoredProof<PallasConfig, VestaConfig> {
    base::base_circuit_helper_generator::<D>(transaction_sequence)
}

fn test_base_rollup_helper_swap<const D: usize>() -> StoredProof<PallasConfig, VestaConfig> {
    const I: usize = 2;
    let mut rng = test_rng();
    let private_key_domain = Fq::from_str("1").unwrap();
    let nullifier_key_domain = Fq::from_str("2").unwrap();

    let mut client_inputs = vec![];
    let mut g_polys = vec![];
    let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
    let mut init_nullifier_root = Fr::zero();

    let mut values = vec![];
    let mut token_ids = vec![];
    let mut old_commitments = vec![];
    let mut old_nonces = vec![];
    let mut root_keys = vec![];
    let mut public_keys = vec![];

    // for each swap participant, prepare old commitment details
    for i in 0..I {
        let root_key = Fq::rand(&mut rng);
        let value = Fq::from((i + 1) as u64);
        let token_id = Fq::from((i + 10) as u64);
        let nonce = Fq::from((i + 100) as u64);

        let private_key: Fq = Poseidon::<Fq>::new()
            .hash(vec![root_key, private_key_domain])
            .unwrap();
        let private_key_trunc: Fr = fq_to_fr_with_mask(&private_key);

        let token_owner = (PallasConfig::GENERATOR * private_key_trunc).into_affine();

        let old_commitment_hash = Poseidon::<Fq>::new()
            .hash(vec![value, token_id, nonce, token_owner.x, token_owner.y])
            .unwrap();
        values.push(value);
        token_ids.push(token_id);
        old_commitments.push(old_commitment_hash);
        old_nonces.push(nonce);
        root_keys.push(root_key);
        public_keys.push(token_owner);
    }
    let comm_tree: Tree<Fq, D> = Tree::from_leaves(old_commitments);
    for i in 0..I {
        // other half of swap index
        let j = (i + 1) % 2;
        let old_sib_path = comm_tree.membership_witness(i).unwrap().try_into().unwrap();
        let (mut swap_circuit, (nullifier, commitments, eph_pub_key, ciphertext)) =
            swap_circuit_helper_generator(
                values[i],
                token_ids[i],
                values[j],
                token_ids[j],
                old_sib_path,
                old_nonces[i],
                comm_tree.root(),
                i as u64,
                j as u64,
                root_keys[i],
                private_key_domain,
                nullifier_key_domain,
                public_keys[j],
            );
        swap_circuit.finalize_for_arithmetization().unwrap();
        let swap_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            swap_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();
        let (swap_ipa_pk, swap_ipa_vk) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&swap_ipa_srs, &swap_circuit).unwrap();

        let (swap_ipa_proof, g_poly, _) = PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
            _,
            _,
            RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        >(&mut rng, &swap_circuit, &swap_ipa_pk, None)
        .unwrap();
        PlonkIpaSnark::<VestaConfig>::verify::<
            RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        >(
            &swap_ipa_vk,
            &swap_circuit.public_input().unwrap(),
            &swap_ipa_proof,
            None,
        )
        .unwrap();
        ark_std::println!("Client proof verified");
        let lifted_nullifier = field_switching(&nullifier);
        let low_null = nullifier_tree.find_predecessor(lifted_nullifier);
        let low_path: [Fr; 32] = nullifier_tree
            .non_membership_witness(lifted_nullifier)
            .unwrap()
            .try_into()
            .unwrap();
        let low_index = Fr::from(low_null.tree_index as u32);
        // TODO what was this before? Can't we get the root from the tree initially?
        if i == 0 {
            let this_poseidon = Poseidon::<Fr>::new();
            let low_nullifier_hash = this_poseidon.hash_unchecked(vec![
                low_null.node.value(),
                Fr::from(low_null.tree_index as u64),
                low_null.node.next_value(),
            ]);

            init_nullifier_root =
                low_path
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
        nullifier_tree.update_low_nullifier(lifted_nullifier);
        let low_nullifier_info = LowNullifierInfo {
            nullifiers: vec![low_null.node],
            indices: vec![low_index],
            paths: vec![low_path],
        };

        let mut client_input: ClientInput<VestaConfig, D> =
            ClientInput::new(swap_ipa_proof, swap_ipa_vk.clone(), 2, 1);
        client_input
            .set_swap_field(true)
            .set_nullifiers(&vec![nullifier])
            .set_commitments(&commitments)
            .set_commitment_tree_root(&vec![comm_tree.root()])
            .set_low_nullifier_info(&low_nullifier_info)
            .set_ciphertext(ciphertext)
            .set_eph_pub_key(
                client_input::to_eph_key_array::<VestaConfig>(eph_pub_key.to_vec()).unwrap(),
            );

        client_inputs.push(client_input);
        g_polys.push(g_poly);
    }

    /* ----------------------------------------------------------------------------------
     * ---------------------------  Base Rollup Circuit ----------------------------------
     * ----------------------------------------------------------------------------------
     */

    let zk_trees = tree_generator_from_client_inputs(
        &mut client_inputs,
        vec![field_switching(&comm_tree.root())],
    )
    .unwrap();

    let (vesta_commit_key, pallas_commit_key) = base::build_commit_keys().unwrap();

    // let pallas_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
    //     2usize.pow(21),
    //     &mut rng,
    // ).unwrap();
    // let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(21)).unwrap();

    let (base_rollup_circuit, pi_star) = base_rollup_circuit::<VestaConfig, PallasConfig, D>(
        client_inputs.try_into().unwrap(),
        zk_trees.vk_tree.root(),
        // initial_nullifier_tree.root,
        init_nullifier_root,
        Fr::from(0 as u32),
        zk_trees.global_root_tree.root(),
        g_polys.try_into().unwrap(),
        vesta_commit_key.clone(),
    )
    .unwrap();
    ark_std::println!(
        "Base rollup circuit constraints: {:?}",
        base_rollup_circuit.num_gates()
    );
    let base_artifacts =
        bench::generate_rollup_circuit_artifacts_and_verify::<PallasConfig, VestaConfig, _, _>(
            &base_rollup_circuit,
            true,
        )
        .unwrap();

    StoredProof::new_from_base(
        &base_rollup_circuit,
        base_artifacts.proof,
        base_artifacts.vk,
        pallas_commit_key,
        vesta_commit_key,
        base_artifacts.g_poly,
        pi_star,
        vec![],
    )
    .unwrap()
}

fn swap_circuit_helper_generator(
    old_value: Fq,
    old_token_id: Fq,
    new_value: Fq,
    new_token_id: Fq,
    old_sib_path: [Fq; 8],
    old_nonce: Fq,
    root: Fq,
    old_leaf_index: u64,
    new_leaf_index: u64, // = expected incoming commitment nonce
    root_key: Fq,        // required here as we need to keep keys consistent
    private_key_domain: Fq,
    nullifier_key_domain: Fq,
    recipient_public_key: PAffine,
) -> (PlonkCircuit<Fq>, (Fq, [Fq; 2], [Fq; 2], [Fq; 3])) {
    let ephemeral_key = Fq::rand(&mut test_rng());
    let circuit = swap_circuit::<PallasConfig, VestaConfig, 8>(
        old_value,
        old_nonce,
        old_sib_path.try_into().unwrap(),
        old_leaf_index.try_into().unwrap(),
        root,
        old_token_id,
        new_value,
        new_leaf_index.try_into().unwrap(),
        new_token_id,
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
        public_inputs[2].try_into().unwrap(),     // nullifiers
        public_inputs[3..=4].try_into().unwrap(), // new commitments
        public_inputs[len - 5..len - 3].try_into().unwrap(), // eph pub key
        public_inputs[len - 3..len].try_into().unwrap(), // ciphertext
    );
    (circuit, client_input)
}
