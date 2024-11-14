use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{Proof, VerifyingKey};
use jf_utils::field_switching;
use trees::NonMembershipTree;
use trees::{non_membership_tree::IndexedNode, IndexedMerkleTree};

use crate::client::circuits::mint::constants::{CIPHERTEXT_LEN, EPHEMERAL_KEY_LEN};

const H: usize = 32;
const VK_PATHS_LEN: usize = 2;
// Fixed constants - I: Number of Input proofs (assume 2)
// C: number of commitments (1) , N: number of nullifiers(1)
// if swap_field, C = 2, N = 1
#[derive(Debug, Clone)]
pub struct ClientInput<E, const C: usize, const N: usize, const D: usize>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
{
    pub proof: Proof<E>,
    pub swap_field: bool,
    pub nullifiers: [E::ScalarField; N], // List of nullifiers in transaction
    pub commitments: [E::ScalarField; C], // List of commitments in transaction
    pub commitment_tree_root: [E::ScalarField; N], // Tree root for comm membership
    pub path_comm_tree_root_to_global_tree_root: [[E::BaseField; D]; N],
    pub path_comm_tree_index: [E::BaseField; N],
    pub low_nullifier: [IndexedNode<E::BaseField>; N],
    pub low_nullifier_indices: [E::BaseField; N],
    pub low_nullifier_mem_path: [[E::BaseField; H]; N], // Path for nullifier non membership
    pub vk_paths: [E::BaseField; VK_PATHS_LEN],
    pub vk_path_index: E::BaseField,
    pub vk: VerifyingKey<E>,
    pub eph_pub_key: [E::BaseField; EPHEMERAL_KEY_LEN], // we just set x and y public
    pub ciphertext: [E::ScalarField; CIPHERTEXT_LEN],
}

impl<E, const C: usize, const N: usize, const D: usize> ClientInput<E, C, N, D>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
{
    pub fn new(proof: Proof<E>, vk: VerifyingKey<E>) -> Self {
        ClientInput {
            proof,
            swap_field: false,
            nullifiers: [E::ScalarField::from(0u32); N],
            commitments: [E::ScalarField::from(0u32); C],
            commitment_tree_root: [E::ScalarField::from(0u32); N],
            path_comm_tree_root_to_global_tree_root: [[E::BaseField::from(0u32); D]; N],
            path_comm_tree_index: [E::BaseField::from(0u32); N],
            low_nullifier: [Default::default(); N],
            low_nullifier_indices: [E::BaseField::from(1u32); N],
            low_nullifier_mem_path: [[E::BaseField::from(0u32); H]; N],
            vk_paths: [E::BaseField::from(0u32); 2], // filled later
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

    pub fn set_nullifiers(&mut self, nullifiers: [E::ScalarField; N]) -> &mut Self {
        self.nullifiers = nullifiers;
        self
    }

    pub fn set_commitments(&mut self, commitments: [E::ScalarField; C]) -> &mut Self {
        self.commitments = commitments;
        self
    }
    pub fn set_commitment_tree_root(&mut self, root: [E::ScalarField; N]) -> &mut Self {
        self.commitment_tree_root = root;
        self
    }
    pub fn set_low_nullifier_info(
        &mut self,
        low_nullifier: [IndexedNode<E::BaseField>; N],
        low_nullifier_indices: [E::BaseField; N],
        low_nullifier_mem_path: [[E::BaseField; H]; N],
    ) -> &mut Self {
        self.low_nullifier = low_nullifier;
        self.low_nullifier_indices = low_nullifier_indices;
        self.low_nullifier_mem_path = low_nullifier_mem_path;
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

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClientInputError(String);

pub struct ClientInputBuilder<E, const C: usize, const N: usize, const D: usize>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    _phantom: std::marker::PhantomData<E>,
}
pub struct LowNullifierInfo<E, const N: usize, const H: usize>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    pub nullifiers: [IndexedNode<E::BaseField>; N],
    pub indices: [E::BaseField; N],
    pub paths: [[E::BaseField; H]; N],
}

impl<E, const C: usize, const N: usize, const D: usize> Default for ClientInputBuilder<E, C, N, D>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<E, const C: usize, const N: usize, const D: usize> ClientInputBuilder<E, C, N, D>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: PrimeField + PoseidonParams<Field = E::BaseField>,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
    pub fn to_commitments_array(
        &self,
        commitments: Vec<E::ScalarField>,
    ) -> Result<[E::ScalarField; C], ClientInputError> {
        let commitments: [E::ScalarField; C] = commitments.try_into().map_err(|_| {
            ClientInputError(format!(
                "Error converting commitments into ClientInputs. Expected: {C}",
            ))
        })?;
        Ok(commitments)
    }

    pub fn to_commitments_tree_root_array(
        &self,
        root: Vec<E::ScalarField>,
    ) -> Result<[E::ScalarField; N], ClientInputError> {
        let root: [E::ScalarField; N] = root.try_into().map_err(|_| {
            ClientInputError(format!(
                "Error converting commitments roots into ClientInputs. Expected: {N}"
            ))
        })?;
        Ok(root)
    }

    pub fn to_eph_key_array(
        &self,
        eph_key: Vec<E::ScalarField>,
    ) -> Result<[E::BaseField; EPHEMERAL_KEY_LEN], ClientInputError> {
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
    pub fn to_ciphertext_array(
        &self,
        ciphertext: Vec<E::ScalarField>,
    ) -> Result<[E::ScalarField; CIPHERTEXT_LEN], ClientInputError> {
        let ciphertext: [E::ScalarField; CIPHERTEXT_LEN] = ciphertext.try_into().map_err(|_| {
            ClientInputError(format!(
                "Error converting ciphertext into ClientInputs. Expected len {CIPHERTEXT_LEN}"
            ))
        })?;
        Ok(ciphertext)
    }

    pub fn to_nullifiers_array(
        &self,
        nullifiers: Vec<E::ScalarField>,
    ) -> Result<[E::ScalarField; N], ClientInputError> {
        let nullifiers: [E::ScalarField; N] = nullifiers.try_into().map_err(|_| {
            ClientInputError(format!(
                "Error converting nullifiers into ClientInputs. Expected {N}"
            ))
        })?;
        Ok(nullifiers)
    }

    pub fn update_nullifier_tree<const H: usize>(
        &self,
        nullifier_tree: &mut IndexedMerkleTree<E::BaseField, H>,
        nullifiers: [E::ScalarField; N],
    ) -> LowNullifierInfo<E, N, H> {
        let lifted_nullifiers = nullifiers
            .iter()
            .map(field_switching::<E::ScalarField, E::BaseField>)
            .collect::<Vec<_>>();
        let mut low_nullifiers: [IndexedNode<E::BaseField>; N] =
            [IndexedNode::new(E::BaseField::from(0u32), 0, E::BaseField::from(0u32)); N];
        let mut low_indices: [E::BaseField; N] = [E::BaseField::from(0u32); N];
        let mut low_paths: [[E::BaseField; H]; N] = [[E::BaseField::from(0u32); H]; N];
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
        LowNullifierInfo {
            nullifiers: low_nullifiers,
            indices: low_indices,
            paths: low_paths,
        }
    }
}
