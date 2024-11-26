use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use common::{crypto::poseidon::constants::PoseidonParams, structs::Block};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use trees::MembershipPath;

use crate::domain::{ark_de, ark_de_std, ark_se, ark_se_std, Preimage};
use crate::domain::{PreimageStatus, StoredPreimageInfo, StoredPreimageInfoVector};

use super::keys::FullKey;

pub trait PreimageDB {
    type E: SWCurveConfig;

    fn get_value(
        &self,
        value: <Self::E as CurveConfig>::BaseField,
    ) -> Option<StoredPreimageInfo<Self::E>>;
    fn get_spendable(&self) -> Option<StoredPreimageInfoVector<Self::E>>;
    fn get_all_preimages(&self) -> StoredPreimageInfoVector<Self::E>;
    fn get_preimage(
        &self,
        key: <Self::E as CurveConfig>::BaseField,
    ) -> Option<StoredPreimageInfo<Self::E>>;

    fn insert_preimage(
        &mut self,
        key: <Self::E as CurveConfig>::BaseField,
        preimage: StoredPreimageInfo<Self::E>,
    ) -> Option<()>;
    fn update_preimages(&mut self, block: Block<<Self::E as CurveConfig>::BaseField>);
}

pub trait TreeDB {
    type F: PrimeField + PoseidonParams<Field = Self::F>;
    fn get_sibling_path(
        &self,
        block_number: &u64,
        leaf_index: usize,
    ) -> Option<MembershipPath<Self::F>>;
    fn add_block_leaves(&mut self, leaves: Vec<Self::F>, block_number: u64) -> Option<()>;
    fn get_root(&self, block_number: &u64) -> Option<Self::F>;
}

pub trait KeyDB {
    type E: SWCurveConfig;
    type Key: FullKey<Self::E>;
    fn get_key(&self, public_key: Affine<Self::E>) -> Option<Self::Key>;
    fn insert_key(&mut self, key: Affine<Self::E>, value: Self::Key) -> Option<()>;
}
