use ark_ec::short_weierstrass::SWCurveConfig;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use derivative::Derivative;
use serde::{Deserialize, Serialize};

use crate::domain::{ark_de, ark_de_std, ark_se, ark_se_std, Preimage};

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
    #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
    pub preimage: Preimage<E>,
    pub block_number: Option<u64>,
    pub leaf_index: Option<usize>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub nullifier: E::BaseField,
    pub status: PreimageStatus,
}

#[derive(Serialize, Deserialize, Clone, Hash, PartialEq, Eq, Debug, Copy, Default)]
pub enum PreimageStatus {
    #[default]
    Unspent,
    Locked,
    Spent,
}

impl CanonicalSerialize for PreimageStatus {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: Compress,
    ) -> Result<(), SerializationError> {
        let value = match self {
            PreimageStatus::Unspent => [0u8],
            PreimageStatus::Locked => [1u8],
            PreimageStatus::Spent => [2u8],
        };
        Ok(writer.write_all(&value)?)
    }

    fn serialized_size(&self, _compress: Compress) -> usize {
        1
    }
}

impl CanonicalDeserialize for PreimageStatus {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        match buf[0] {
            0 => Ok(PreimageStatus::Unspent),
            1 => Ok(PreimageStatus::Locked),
            2 => Ok(PreimageStatus::Spent),
            _ => Err(SerializationError::InvalidData), // Handle invalid cases
        }
    }
}

impl Valid for PreimageStatus {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
pub type StoredPreimageInfoVector<E> = Vec<StoredPreimageInfo<E>>;
