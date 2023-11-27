use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use common::crypto::poseidon::constants::PoseidonParams;
use derivative::Derivative;
use serde::{Deserialize, Serialize};

use crate::domain::{ark_de, ark_se, Preimage};

use super::keys::FullKey;

#[derive(
    Derivative, Default, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
#[derivative(
    Copy(bound = "E: SWCurveConfig"),
    Clone(bound = "E: SWCurveConfig"),
    PartialEq(bound = "E: SWCurveConfig"),
    Eq(bound = "E: SWCurveConfig"),
    Hash(bound = "E: SWCurveConfig")
)]
pub struct StoredPreimageInfo<E: SWCurveConfig> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub preimage: Preimage<E>,
    pub block_number: Option<u64>,
    pub leaf_index: Option<usize>,
    pub spent: bool,
}

pub trait PreimageDB {
    type E: SWCurveConfig;

    fn get_value(
        &self,
        value: <Self::E as CurveConfig>::BaseField,
    ) -> Option<StoredPreimageInfo<Self::E>>;
    fn get_spendable(&self) -> Option<Vec<StoredPreimageInfo<Self::E>>>;
    fn get_all_preimages(&self) -> Vec<StoredPreimageInfo<Self::E>>;
    fn get_preimage(
        &self,
        key: <Self::E as CurveConfig>::BaseField,
    ) -> Option<StoredPreimageInfo<Self::E>>;

    fn insert_preimage(
        &mut self,
        key: <Self::E as CurveConfig>::BaseField,
        preimage: StoredPreimageInfo<Self::E>,
    ) -> Option<()>;
}

pub trait TreeDB {
    type F: PrimeField + PoseidonParams<Field = Self::F>;
    fn get_sibling_path(&self, block_number: &u64, leaf_index: usize) -> Option<Vec<Self::F>>;
    fn add_block_leaves(&mut self, leaves: Vec<Self::F>, block_number: u64) -> Option<()>;
    fn get_root(&self, block_number: &u64) -> Option<Self::F>;
}

pub trait KeyDB {
    type E: SWCurveConfig;
    type Key: FullKey<Self::E>;
    fn get_key(&self, public_key: Affine<Self::E>) -> Option<Self::Key>;
    fn insert_key(&mut self, key: Affine<Self::E>, value: Self::Key) -> Option<()>;
}