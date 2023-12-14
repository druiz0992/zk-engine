use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use jf_plonk::nightfall::ipa_structs::Proof;
use serde::{Deserialize, Serialize};

use crate::serialize::{ark_de, ark_de_std, ark_se, ark_se_std, vec_ark_de, vec_ark_se};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Block<F: Field> {
    pub block_number: u64,
    #[serde(serialize_with = "vec_ark_se", deserialize_with = "vec_ark_de")]
    pub commitments: Vec<F>,
    #[serde(serialize_with = "vec_ark_se", deserialize_with = "vec_ark_de")]
    pub nullifiers: Vec<F>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub commitment_root: F,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct Commitment<F: PrimeField>(
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
);

impl<F: PrimeField> From<F> for Commitment<F> {
    fn from(value: F) -> Self {
        Commitment(value)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Nullifier<F: PrimeField>(
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
);

impl<F: PrimeField> From<F> for Nullifier<F> {
    fn from(value: F) -> Self {
        Nullifier(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction<P: Pairing>
where
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub commitments: Vec<Commitment<P::ScalarField>>,
    pub nullifiers: Vec<Nullifier<P::ScalarField>>,
    #[serde(serialize_with = "vec_ark_se", deserialize_with = "vec_ark_de")]
    pub ciphertexts: Vec<P::ScalarField>,
    #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
    pub proof: Proof<P>,
    #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
    pub g_polys: DensePolynomial<P::ScalarField>,
    #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
    pub eph_pub_key: P::G1Affine,
    pub swap_field: bool,
}

impl<P: Pairing> Transaction<P>
where
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub fn new(
        commitments: Vec<Commitment<P::ScalarField>>,
        nullifiers: Vec<Nullifier<P::ScalarField>>,
        ciphertexts: Vec<P::ScalarField>,
        proof: Proof<P>,
        g_polys: DensePolynomial<P::ScalarField>,
        eph_pub_key: P::G1Affine,
        swap_field: bool,
    ) -> Self {
        Self {
            commitments,
            nullifiers,
            ciphertexts,
            proof,
            g_polys,
            eph_pub_key,
            swap_field,
        }
    }
}
