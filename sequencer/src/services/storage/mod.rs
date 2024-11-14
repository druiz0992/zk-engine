use crate::ports::storage::GlobalStateStorage;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::CurveGroup;
use common::crypto::poseidon::constants::PoseidonParams;
use common::crypto::poseidon::Poseidon;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_plonk::proof_system::structs::VK;
use trees::MembershipTree;
use trees::{membership_tree::Tree, tree::AppendTree};

pub mod in_mem_sequencer_storage;

pub fn generate_and_store_vk_tree<V, Storage, const H: usize>(
    db: &mut Storage,
    vks: Vec<VerifyingKey<V>>,
) where
    V: Pairing<G1Affine = Affine<<<V as Pairing>::G1 as CurveGroup>::Config>>,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
    Storage: GlobalStateStorage,
    Storage::VkTree: MembershipTree<H> + AppendTree<H> + From<Tree<<V as Pairing>::BaseField, H>>,
{
    let poseidon: Poseidon<<V as Pairing>::BaseField> = Poseidon::new();
    let vk_hashes = vks
        .iter()
        .map(|vk| {
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
        })
        .collect::<Vec<_>>();

    let vk_tree = Tree::<<V as Pairing>::BaseField, H>::from_leaves(vk_hashes).into();
    db.store_vk_tree(vk_tree);
}
