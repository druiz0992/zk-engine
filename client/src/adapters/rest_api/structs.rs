use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use common::serialize::{ark_de, ark_se, vec_ark_de, vec_ark_se};
use derivative::Derivative;
use serde::{Deserialize, Serialize};

use crate::domain::StoredPreimageInfo;

#[derive(Debug, Serialize, Deserialize)]
pub struct MintInput {
    pub value: String,
    pub token_id: String,
    pub compressed_public_key: String,
    pub salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MnemonicInput {
    pub mnemonic: String,
}

#[derive(Derivative, Default, Deserialize, Serialize)]
#[derivative(
    Clone(bound = "P: SWCurveConfig"),
    Debug(bound = "P: SWCurveConfig"),
    PartialEq(bound = "P: SWCurveConfig"),
    Eq(bound = "P: SWCurveConfig"),
    Hash(bound = "P: SWCurveConfig")
)]
pub struct TransferInput<P: SWCurveConfig> {
    #[serde(serialize_with = "vec_ark_se", deserialize_with = "vec_ark_de")]
    pub commitments_to_use: Vec<P::BaseField>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub recipient: Affine<P>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub transfer_amount: P::BaseField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub eph_key: Option<P::BaseField>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sender: Affine<P>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct PreimageResponse<EmbedCurve: SWCurveConfig> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub stored_preimage: StoredPreimageInfo<EmbedCurve>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub commitment_hash: EmbedCurve::BaseField,
}
