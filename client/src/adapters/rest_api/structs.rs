use ark_ec::short_weierstrass::SWCurveConfig;
use derivative::Derivative;
use serde::{Deserialize, Serialize};

use crate::domain::{ark_de, ark_se};

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

#[derive(Derivative, Default, Debug, Deserialize, Serialize)]
#[derivative(
    Copy(bound = "P: SWCurveConfig"),
    Clone(bound = "P: SWCurveConfig"),
    PartialEq(bound = "P: SWCurveConfig"),
    Eq(bound = "P: SWCurveConfig"),
    Hash(bound = "P: SWCurveConfig")
)]
pub struct TransferInput<P: SWCurveConfig> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub commitments_to_use: Vec<P::BaseField>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub recipient: P::BaseField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub transfer_amount: P::BaseField,
}
