use crate::rollup::circuits::client_input::ClientInput;
use ark_std::Zero;
use common::crypto::poseidon::Poseidon;
use curves::{
    pallas::{Fq, Fr},
    vesta::VestaConfig,
};
use jf_plonk::{nightfall::ipa_structs::VerifyingKey, proof_system::structs::VK};
use jf_utils::field_switching;
use trees::MembershipTree;
use trees::{membership_tree::Tree, non_membership_tree::IndexedMerkleTree, tree::AppendTree};

const VK_PATHS_LEN: usize = 8;

pub struct ZkTrees {
    pub vk_tree: Tree<Fr, VK_PATHS_LEN>,
    pub commitment_tree: Tree<Fq, 8>,
    pub nullifier_tree: IndexedMerkleTree<Fr, 32>,
    pub global_root_tree: Tree<Fr, 8>,
}

pub fn tree_generator_from_client_inputs<const D: usize>(
    inputs: &mut [ClientInput<VestaConfig>],
    global_comm_roots: Vec<Fr>,
) -> Result<ZkTrees, String> {
    let global_comm_roots_empty = global_comm_roots.is_empty();
    let vk_tree = build_vk_tree::<D>(inputs)?;
    let commitment_tree = build_commitments_tree::<D>(inputs);
    let nullifier_tree = build_nullifier_tree::<D>(inputs);
    let global_root_tree = build_global_root_tree::<D>(global_comm_roots);

    update_inputs_vk::<D>(inputs, &vk_tree);
    if !global_comm_roots_empty {
        update_inputs_global_path::<D>(inputs, &global_root_tree);
    }

    Ok(ZkTrees {
        vk_tree,
        commitment_tree,
        nullifier_tree,
        global_root_tree,
    })
}

pub fn build_vk_tree<const D: usize>(
    inputs: &mut [ClientInput<VestaConfig>],
) -> Result<Tree<Fr, VK_PATHS_LEN>, String> {
    if inputs.len() > VK_PATHS_LEN {
        return Err(format!(
            "Too many VKs. Capacity {VK_PATHS_LEN}. Given : {}",
            inputs.len()
        ));
    }
    let vks = inputs
        .iter()
        .map(|i| i.vk.clone())
        .collect::<Vec<VerifyingKey<_>>>();

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

    let vk_tree: Tree<Fr, VK_PATHS_LEN> = Tree::from_leaves(vk_hashes.collect::<Vec<_>>());

    Ok(vk_tree)
}

pub fn build_commitments_tree<const D: usize>(
    inputs: &mut [ClientInput<VestaConfig>],
) -> Tree<Fq, 8> {
    // commitment trees
    let comms = inputs
        .iter()
        .flat_map(|i| i.commitments.clone())
        .collect::<Vec<_>>();

    let commitment_tree: Tree<Fq, 8> = Tree::from_leaves(comms);

    commitment_tree
}

pub fn build_nullifier_tree<const D: usize>(
    inputs: &mut [ClientInput<VestaConfig>],
) -> IndexedMerkleTree<Fr, 32> {
    // nullifier trees
    let nullifiers = inputs
        .iter()
        .flat_map(|i| i.nullifiers.clone())
        .collect::<Vec<_>>();

    let lifted_nullifiers = nullifiers
        .iter()
        .map(field_switching::<Fq, Fr>)
        .collect::<Vec<_>>();
    let nullifier_tree: IndexedMerkleTree<Fr, 32> =
        IndexedMerkleTree::from_leaves(lifted_nullifiers);

    nullifier_tree
}

pub fn build_global_root_tree<const D: usize>(global_comm_roots: Vec<Fr>) -> Tree<Fr, 8> {
    // global root tree
    let global_root_tree: Tree<Fr, 8> = Tree::from_leaves(global_comm_roots);

    global_root_tree
}

#[allow(non_snake_case)]
pub fn update_inputs_global_path<const D: usize>(
    inputs: &mut [ClientInput<VestaConfig>],
    global_comm_tree: &Tree<Fr, 8>,
) {
    let mut commitment_index = 0;
    for ci in inputs.iter_mut() {
        let N = ci.nullifiers.len();
        let null = &ci.nullifiers;
        if !null[0].is_zero() {
            if ci.swap_field {
                commitment_index = 0;
            }
            let global_root_path: [Fr; 8] = global_comm_tree
                .membership_witness(commitment_index)
                .unwrap()
                .try_into()
                .unwrap();
            ci.path_comm_tree_root_to_global_tree_root = vec![global_root_path; N];
            ci.path_comm_tree_index = vec![Fr::from(commitment_index as u32); N];
            commitment_index += 1;
        }
    }
}
pub fn update_inputs_vk<const D: usize>(
    inputs: &mut [ClientInput<VestaConfig>],
    vk_tree: &Tree<Fr, VK_PATHS_LEN>,
) {
    for (idx, ci) in inputs.iter_mut().enumerate() {
        ci.vk_paths = vk_tree.membership_witness(idx).unwrap().as_vec();
        ci.vk_path_index = Fr::from(idx as u32);
    }
}
