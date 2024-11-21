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
    pub eph_pub_key: Vec<P::ScalarField>,
    pub swap_field: bool,
    pub circuit_type: CircuitType,
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
        eph_pub_key: Vec<P::ScalarField>,
        swap_field: bool,
        circuit_type: CircuitType,
    ) -> Self {
        Self {
            commitments,
            nullifiers,
            ciphertexts,
            proof,
            g_polys,
            eph_pub_key,
            swap_field,
            circuit_type,
        }
    }
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

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum CircuitType {
    Mint(usize),
    Transfer(usize, usize),
    BaseRollup,
    BounceRollup,
    MergeRollup,
    BounceMergeRollup,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Fp256, MontBackend};
    use num_bigint::BigUint;
    use serde_json;

    // Define a dummy field type for testing
    // Adjust the underlying types as necessary for your use case
    type DummyField = Fp256<MontBackend<ark_bn254::FrConfig, 4>>;
    const VALUE: u64 = 42u64;

    fn get_dummy_field_value() -> DummyField {
        DummyField::from(VALUE) // or any value you wish to test with
    }

    fn get_test_block() -> Block<DummyField> {
        Block {
            block_number: 1,
            commitments: vec![get_dummy_field_value()],
            nullifiers: vec![get_dummy_field_value()],
            commitment_root: get_dummy_field_value(),
        }
    }

    #[test]
    fn test_block_serialization() {
        let block = get_test_block();
        let serialized = serde_json::to_string(&block).expect("Serialization failed");
        let hex_value = BigUint::from(VALUE).to_str_radix(16);
        assert!(serialized.contains(&hex_value)); // Check that serialized data contains expected value
    }

    #[test]
    fn test_block_deserialization() {
        let block = get_test_block();
        let serialized = serde_json::to_string(&block).expect("Serialization failed");
        let deserialized: Block<DummyField> =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(block.block_number, deserialized.block_number);
        assert_eq!(block.commitments, deserialized.commitments);
        assert_eq!(block.nullifiers, deserialized.nullifiers);
        assert_eq!(block.commitment_root, deserialized.commitment_root);
    }
}
