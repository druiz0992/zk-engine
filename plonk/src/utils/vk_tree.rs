use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::CurveGroup;
use common::crypto::poseidon::constants::PoseidonParams;
use common::crypto::poseidon::Poseidon;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_plonk::proof_system::structs::VK;
use trees::{membership_tree::Tree, tree::AppendTree};

const VK_PATHS_LEN: usize = 8;

pub fn build_vk_tree<V>(vks: &[VerifyingKey<V>]) -> Tree<V::BaseField, VK_PATHS_LEN>
where
    V: Pairing<G1Affine = Affine<<<V as Pairing>::G1 as CurveGroup>::Config>>,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
{
    // Vk trees
    let poseidon: Poseidon<V::BaseField> = Poseidon::new();
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

    let vk_tree: Tree<V::BaseField, VK_PATHS_LEN> =
        Tree::from_leaves(vk_hashes.collect::<Vec<_>>());

    vk_tree
}
