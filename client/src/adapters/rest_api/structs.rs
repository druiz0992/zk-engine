use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::CurveGroup;
use ark_poly::univariate::DensePolynomial;
use common::serialize::{ark_de, ark_de_std, ark_se, ark_se_std, vec_ark_de, vec_ark_se};
use common::structs::{Commitment, Nullifier};
use derivative::Derivative;
use jf_plonk::nightfall::ipa_structs::Proof;
use serde::{Deserialize, Serialize};

use crate::ports::storage::StoredPreimageInfo;

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
    Clone(bound = "P: SWCurveConfig"),
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
    pub sender: Affine<P>,
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct PreimageResponse<EmbedCurve: SWCurveConfig> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub stored_preimage: StoredPreimageInfo<EmbedCurve>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub commitment_hash: EmbedCurve::BaseField,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct Tx<P>
where
    P: Pairing,
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub ct: Vec<Commitment<P::ScalarField>>,
    phantom: std::marker::PhantomData<P>,
    pub nullifiers: Vec<Nullifier<P::ScalarField>>,
    #[serde(serialize_with = "vec_ark_se", deserialize_with = "vec_ark_de")]
    pub ciphertexts: Vec<P::ScalarField>,
    #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
    pub proof: Proof<P>,
    #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
    pub g_polys: DensePolynomial<P::ScalarField>,
}
