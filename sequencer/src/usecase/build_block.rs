use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use common::{
    crypto::poseidon::constants::PoseidonParams,
    structs::{Block, Transaction},
};
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_utils::field_switching;
use plonk_prover::rollup::circuits::client_input::ClientInput;
use trees::{
    membership_tree::{MembershipTree, Tree},
    non_membership_tree::{IndexedMerkleTree, IndexedNode, NonMembershipTree},
    tree::AppendTree,
    MembershipPath,
};
use zk_macros::sequencer_circuit;

use crate::{
    domain::{RollupCommitKeys, RollupProvingKeys},
    ports::{prover::SequencerProver, storage::GlobalStateStorage},
};

// pub struct ClientInput<P, V, const C: usize, const N: usize>
// where
//     P: Pairing,
//     V: Pairing<ScalarField = P::BaseField>,
//     <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
//     <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
// {
//     proof: Proof<V>,
//     nullifiers: [V::ScalarField; N], // List of nullifiers in transaction
//     commitments: [V::ScalarField; C], // List of commitments in transaction
//     commitment_tree_root: [P::ScalarField; N], // Tree root for comm membership
//     path_comm_tree_root_to_global_tree_root: [[P::ScalarField; 8]; N],
//     path_comm_tree_index: [P::ScalarField; N],
//     low_nullifier: [IndexedNode<P::ScalarField>; N],
//     low_nullifier_indices: [P::ScalarField; N],
//     low_nullifier_mem_path: [[P::ScalarField; 32]; N], // Path for nullifier non membership
//     vk_paths: [P::ScalarField; 1],
//     vk_path_index: P::ScalarField,
//     vk: VerifyingKey<V>,
//     ciphertext: [V::ScalarField; 3],
// }
//

#[sequencer_circuit]
pub fn build_block<P, V, T, Prover, SW, VSW>(
    transactions: Vec<Transaction<V>>,
    vks: Vec<VerifyingKey<V>>,
    vks_indices: Vec<usize>,
    global_state_trees: T,
    commit_keys: RollupCommitKeys<V, VSW, P, SW>,
    proving_keys: Option<RollupProvingKeys<V, VSW, P, SW>>,
) -> Result<Block<V::ScalarField>, &'static str>
where
    T: GlobalStateStorage<
        CommitmentTree = Tree<V::BaseField, 8>,
        VkTree = Tree<V::BaseField, 2>,
        NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
    >,
    Prover: SequencerProver<V, VSW, P, SW>,
{
    ark_std::println!("vk_paths");
    let vk_paths: Vec<MembershipPath<V::BaseField>> = vks_indices
        .iter()
        .map(|vk| global_state_trees.get_vk_tree().membership_witness(*vk))
        .collect::<Option<Vec<MembershipPath<_>>>>()
        .ok_or("Invalid vk index")?;

    ark_std::println!("low nullifier path");
    let low_nullifier_path: Vec<MembershipPath<V::BaseField>> = transactions
        .iter()
        .flat_map(|tx| {
            tx.nullifiers
                .iter()
                .filter(|nullifier| !nullifier.0.is_zero())
                .map(|nullifier| {
                    let nullifier_fr = field_switching(&nullifier.0);
                    global_state_trees
                        .get_global_nullifier_tree()
                        .non_membership_witness(nullifier_fr)
                        .ok_or("Invalid nullifier")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    ark_std::println!("low nulliifer");
    let low_nullifier: Vec<IndexedNode<V::BaseField>> = transactions
        .iter()
        .flat_map(|tx| {
            tx.nullifiers
                .iter()
                .filter(|nullifier| !nullifier.0.is_zero())
                .map(|n| {
                    let nullifier_fr = field_switching(&n.0);
                    global_state_trees
                        .get_global_nullifier_tree()
                        .find_predecessor(nullifier_fr)
                        .node
                })
        })
        .collect::<Vec<_>>();
    let nullifiers = transactions
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().map(|n| n.0))
        .collect::<Vec<_>>();
    let commitments = transactions
        .iter()
        .flat_map(|tx| tx.commitments.iter().map(|c| c.0))
        .collect::<Vec<_>>();

    ark_std::println!("commitment tree");
    let local_commitment_tree: Tree<V::ScalarField, 8> = Tree::from_leaves(commitments.clone());
    global_state_trees
        .get_global_commitment_tree()
        .append_leaf(field_switching(&local_commitment_tree.root()));

    ark_std::println!("commitment tree root: {:?}", local_commitment_tree.root());
    let client_inputs: Vec<_> = transactions
        .into_iter()
        .enumerate()
        .map(|(i, t)| ClientInput::<V, 1, 1, 8> {
            proof: t.proof,
            nullifiers: t
                .nullifiers
                .iter()
                .map(|n| n.0)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_or([V::ScalarField::from(0u8); 1]),
            commitments: t
                .commitments
                .iter()
                .map(|c| c.0)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_or([V::ScalarField::from(0u8); 1]),
            commitment_tree_root: [V::ScalarField::from(0u8); 1],
            path_comm_tree_root_to_global_tree_root: [[V::BaseField::from(0u8); 8]],
            //path_comm_tree_index: [F::zero()],
            path_comm_tree_index: [V::BaseField::from(0u32)],
            low_nullifier: low_nullifier
                .clone()
                .try_into()
                .unwrap_or([Default::default(); 1]),
            low_nullifier_indices: [V::BaseField::zero()],
            low_nullifier_mem_path: low_nullifier_path
                .clone()
                .into_iter()
                .map(|p| p.try_into().unwrap_or([V::BaseField::zero(); 32]))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_or([[V::BaseField::from(0u32); 32]; 1]),
            vk_paths: vk_paths[i].clone().try_into().unwrap(),
            vk_path_index: V::BaseField::from(vks_indices[i] as u64),
            vk: vks[i].clone(),
            ciphertext: [V::ScalarField::from(0u8); 3],
            eph_pub_key: [V::BaseField::from(0u8); 2],
            swap_field: t.swap_field,
        })
        .collect::<Vec<_>>();

    println!("build_block");
    // client_inputs: [ClientInput<V, 1, 1>; 2],
    // global_vk_root: P::ScalarField,
    // global_nullifier_root: P::ScalarField,
    // global_nullifier_leaf_count: P::ScalarField,
    // global_commitment_root: P::ScalarField,
    // g_polys: [DensePolynomial<P::BaseField>; 2],
    // commit_key: CommitKey<V>,

    let res = Prover::rollup_proof(
        client_inputs.try_into().unwrap(),
        global_state_trees.get_vk_tree().root(),
        global_state_trees.get_global_nullifier_tree().root(),
        V::BaseField::from(global_state_trees.get_global_nullifier_tree().leaf_count()),
        global_state_trees.get_global_commitment_tree().root(),
        [Default::default(), Default::default()],
        commit_keys,
        proving_keys,
    );

    ark_std::println!("res: {:?}", res);

    Ok(Block {
        block_number: 0,
        commitments,
        nullifiers,
        commitment_root: local_commitment_tree.root(),
    })

    // Given transaction list, produce a block
}
