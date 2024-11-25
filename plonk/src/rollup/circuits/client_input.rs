#![allow(non_snake_case)]

use crate::client::circuits::mint::constants::{CIPHERTEXT_LEN, EPHEMERAL_KEY_LEN};
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{Proof, VerifyingKey};
use jf_utils::field_switching;
use trees::NonMembershipTree;
use trees::{non_membership_tree::IndexedNode, IndexedMerkleTree};

/*
nullifiers: [E::ScalarField; N], // List of nullifiers in transaction
commitments: [E::ScalarField; C], // List of commitments in transaction
commitment_tree_root: [E::ScalarField; N], // Tree root for comm membership
path_comm_tree_root_to_global_tree_root: [[E::BaseField; D]; N],
path_comm_tree_index: [E::BaseField; N],
low_nullifier: [IndexedNode<E::BaseField>; N],
low_nullifier_indices: [E::BaseField; N],
low_nullifier_mem_path: [[E::BaseField; H]; N], // Path for nullifier non membership
vk_paths: [E::BaseField; VK_PATHS_LEN],
*/

const H: usize = 32;
const D: usize = 8;
const VK_PATHS_LEN: usize = 8;
// Fixed constants - I: Number of Input proofs (assume 2)
// C: number of commitments (1) , N: number of nullifiers(1)
// if swap_field, C = 2, N = 1
#[derive(Debug, Clone)]
pub struct ClientInput<E>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
{
    pub proof: Proof<E>,
    pub swap_field: bool,
    pub nullifiers: Vec<E::ScalarField>, // List of nullifiers in transaction
    pub commitments: Vec<E::ScalarField>, // List of commitments in transaction
    pub commitment_tree_root: Vec<E::ScalarField>, // Tree root for comm membership
    pub path_comm_tree_root_to_global_tree_root: Vec<[E::BaseField; D]>,
    pub path_comm_tree_index: Vec<E::BaseField>,
    pub low_nullifier: Vec<IndexedNode<E::BaseField>>,
    pub low_nullifier_indices: Vec<E::BaseField>,
    pub low_nullifier_mem_path: Vec<[E::BaseField; H]>, // Path for nullifier non membership
    pub vk_paths: Vec<E::BaseField>,
    pub vk_path_index: E::BaseField,
    pub vk: VerifyingKey<E>,
    pub eph_pub_key: [E::BaseField; EPHEMERAL_KEY_LEN], // we just set x and y public
    pub ciphertext: [E::ScalarField; CIPHERTEXT_LEN],
}

impl<E> ClientInput<E>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
{
    pub fn new(proof: Proof<E>, vk: VerifyingKey<E>, C: usize, N: usize) -> Self {
        ClientInput {
            proof,
            swap_field: false,
            nullifiers: vec![E::ScalarField::from(0u32); N],
            commitments: vec![E::ScalarField::from(0u32); C],
            commitment_tree_root: vec![E::ScalarField::from(0u32); N],
            path_comm_tree_root_to_global_tree_root: vec![[E::BaseField::from(0u32); D]; N],
            path_comm_tree_index: vec![E::BaseField::from(0u32); N],
            low_nullifier: vec![Default::default(); N],
            low_nullifier_indices: vec![E::BaseField::from(1u32); N],
            low_nullifier_mem_path: vec![[E::BaseField::from(0u32); H]; N],
            vk_paths: vec![E::BaseField::from(0u32); VK_PATHS_LEN],
            vk_path_index: E::BaseField::from(0u64),
            vk,
            eph_pub_key: [E::BaseField::from(0u32); EPHEMERAL_KEY_LEN],
            ciphertext: [E::ScalarField::from(0u32); CIPHERTEXT_LEN],
        }
    }

    pub fn set_swap_field(&mut self, flag: bool) -> &mut Self {
        self.swap_field = flag;
        self
    }

    pub fn set_nullifiers(&mut self, nullifiers: &[E::ScalarField]) -> &mut Self {
        self.nullifiers = nullifiers.to_vec();
        self
    }

    pub fn set_commitments(&mut self, commitments: &[E::ScalarField]) -> &mut Self {
        self.commitments = commitments.to_vec();
        self
    }
    pub fn set_commitment_tree_root(&mut self, root: &[E::ScalarField]) -> &mut Self {
        self.commitment_tree_root = root.to_vec();
        self
    }
    pub fn set_low_nullifier_info(
        &mut self,
        low_nullifier_info: &LowNullifierInfo<E, H>,
    ) -> &mut Self
    where
        E: Pairing,
        <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
        <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
    {
        self.low_nullifier = low_nullifier_info.nullifiers.to_vec();
        self.low_nullifier_indices = low_nullifier_info.indices.to_vec();
        self.low_nullifier_mem_path = low_nullifier_info.paths.to_vec();
        self
    }

    pub fn set_eph_pub_key(&mut self, key: [E::BaseField; EPHEMERAL_KEY_LEN]) -> &mut Self {
        self.eph_pub_key = key;
        self
    }
    pub fn set_ciphertext(&mut self, ciphertext: [E::ScalarField; CIPHERTEXT_LEN]) -> &mut Self {
        self.ciphertext = ciphertext;
        self
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ClientInputError(String);

/*
    pub nullifiers: vec![IndexedNode<E::BaseField>; N],
    pub indices: [E::BaseField; N],
    pub paths: [[E::BaseField; H]; N],
*/
#[derive(Debug, Clone)]
pub struct LowNullifierInfo<E, const H: usize>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    pub nullifiers: Vec<IndexedNode<E::BaseField>>,
    pub indices: Vec<E::BaseField>,
    pub paths: Vec<[E::BaseField; H]>,
}

pub fn to_eph_key_array<E>(
    eph_key: Vec<E::ScalarField>,
) -> Result<[E::BaseField; EPHEMERAL_KEY_LEN], ClientInputError>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    let eph_key: [E::BaseField; EPHEMERAL_KEY_LEN] = eph_key
            .into_iter()
            .map(|key| field_switching(&key))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| {
                ClientInputError(format!("Error converting ephermeral key into ClientInputs. Expected len: {EPHEMERAL_KEY_LEN}"))
            })?;
    Ok(eph_key)
}
pub fn to_ciphertext_array<E>(
    ciphertext: Vec<E::ScalarField>,
) -> Result<[E::ScalarField; CIPHERTEXT_LEN], ClientInputError>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    let ciphertext: [E::ScalarField; CIPHERTEXT_LEN] = ciphertext.try_into().map_err(|_| {
        ClientInputError(format!(
            "Error converting ciphertext into ClientInputs. Expected len {CIPHERTEXT_LEN}"
        ))
    })?;
    Ok(ciphertext)
}

pub fn update_nullifier_tree<E, const H: usize>(
    nullifier_tree: &mut IndexedMerkleTree<E::BaseField, H>,
    nullifiers: &[E::ScalarField],
) -> Option<LowNullifierInfo<E, H>>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    let mut lifted_nullifiers = Vec::new();

    for n in nullifiers {
        if *n == E::ScalarField::from(0u32) {
            return None;
        }
        lifted_nullifiers.push(field_switching::<E::ScalarField, E::BaseField>(n));
    }
    let N = nullifiers.len();
    let mut low_nullifiers: Vec<IndexedNode<E::BaseField>> =
        vec![IndexedNode::new(E::BaseField::from(0u32), 0, E::BaseField::from(0u32)); N];
    let mut low_indices: Vec<E::BaseField> = vec![E::BaseField::from(0u32); N];
    let mut low_paths: Vec<[E::BaseField; H]> = vec![[E::BaseField::from(0u32); H]; N];
    for (j, null) in lifted_nullifiers.iter().enumerate() {
        let low_null = nullifier_tree.find_predecessor(*null);
        low_nullifiers[j] = low_null.node;
        low_paths[j] = nullifier_tree
            .non_membership_witness(*null)
            .unwrap()
            .try_into()
            .unwrap();
        low_indices[j] = E::BaseField::from(low_null.tree_index as u32);
        nullifier_tree.update_low_nullifier(*null);
    }
    Some(LowNullifierInfo {
        nullifiers: low_nullifiers,
        indices: low_indices,
        paths: low_paths,
    })
}
