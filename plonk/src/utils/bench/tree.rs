use common::crypto::poseidon::Poseidon;
use curves::{
    pallas::{Fq, Fr},
    vesta::VestaConfig,
};
use jf_plonk::{nightfall::ipa_structs::VerifyingKey, proof_system::structs::VK};
use jf_utils::field_switching;
use trees::{membership_tree::Tree, non_membership_tree::IndexedMerkleTree, tree::AppendTree};

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
