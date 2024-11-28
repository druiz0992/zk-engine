use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use jf_plonk::nightfall::ipa_structs::Proof;
use jf_utils::canonical;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Block<F: Field> {
    pub block_number: u64,
    #[serde(with = "canonical")]
    pub commitments: Vec<F>,
    #[serde(with = "canonical")]
    pub nullifiers: Vec<F>,
    #[serde(with = "canonical")]
    pub commitment_root: F,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug, PartialEq)]
pub struct Commitment<F: PrimeField>(#[serde(with = "canonical")] pub F);

impl<F: PrimeField> From<F> for Commitment<F> {
    fn from(value: F) -> Self {
        Commitment(value)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct Nullifier<F: PrimeField>(#[serde(with = "canonical")] pub F);

impl<F: PrimeField> From<F> for Nullifier<F> {
    fn from(value: F) -> Self {
        Nullifier(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyDensePolynomial {
    pub coeffs: Vec<[u64; 4]>,
}
impl<F: PrimeField> From<MyDensePolynomial> for DensePolynomial<F>
where
    F: PrimeField,
{
    fn from(compact_poly: MyDensePolynomial) -> Self {
        let coeffs: Vec<F> = compact_poly
            .coeffs
            .into_iter()
            .map(|coeff| {
                let b = BigInt::<4>::new(coeff).to_bytes_le();
                F::from_le_bytes_mod_order(&b)
            })
            .collect();

        DensePolynomial { coeffs }
    }
}

impl<F: PrimeField> From<&DensePolynomial<F>> for MyDensePolynomial {
    fn from(dense_poly: &DensePolynomial<F>) -> Self {
        let coeffs = dense_poly
            .coeffs
            .iter()
            .map(|coeff| {
                let b = coeff.into_bigint();
                b.as_ref().try_into().unwrap()
            })
            .collect();

        MyDensePolynomial { coeffs }
    }
}

// Serialization function
pub fn serialize_dense_polynomial<S, F>(
    polynomial: &DensePolynomial<F>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    F: PrimeField,
    S: Serializer,
{
    let p: MyDensePolynomial = MyDensePolynomial::from(polynomial);
    p.serialize(serializer)
}

// Deserialization function
pub fn deserialize_dense_polynomial<'de, D, F>(
    deserializer: D,
) -> Result<DensePolynomial<F>, D::Error>
where
    F: PrimeField,
    D: Deserializer<'de>,
{
    let p: MyDensePolynomial = MyDensePolynomial::deserialize(deserializer)?;
    Ok(p.into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction<P: Pairing>
where
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub commitments: Vec<Commitment<P::ScalarField>>,
    pub nullifiers: Vec<Nullifier<P::ScalarField>>,
    #[serde(with = "canonical")]
    pub ciphertexts: Vec<P::ScalarField>,
    #[serde(with = "canonical")]
    pub eph_pub_key: Vec<P::ScalarField>,
    pub swap_field: bool,
    pub circuit_type: CircuitType,
    #[serde(with = "canonical")]
    pub proof: Proof<P>,
    //#[serde(with = "canonical")]
    //pub g_polys: MyDensePolynomial<P::ScalarField>,
    #[serde(
        serialize_with = "serialize_dense_polynomial",
        deserialize_with = "deserialize_dense_polynomial"
    )]
    pub g_polys: DensePolynomial<P::ScalarField>,
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
    pub fn set_proof(&mut self, proof: Proof<P>) -> &mut Self {
        self.proof = proof;
        self
    }
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
