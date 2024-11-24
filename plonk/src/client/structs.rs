use crate::client::PoseidonParams;
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::Field;
use common::structs::Transaction;
use trees::{AppendTree, Tree};

#[derive(Clone, Debug)]
pub struct ClientPubInput<F: Field> {
    pub swap_field: bool,
    pub commitment_root: Vec<F>,
    pub nullifiers: Vec<F>,
    pub commitments: Vec<F>,
    pub ephemeral_public_key: Vec<F>,
    pub ciphertexts: Vec<F>,
}

impl<F: Field> ClientPubInput<F> {
    pub fn new(
        value: Vec<F>,
        commitment_nullifier_count: (usize, usize),
    ) -> Result<Self, &'static str> {
        let (c, n) = commitment_nullifier_count;
        // C + 2 (Ephemeral key) + 3 (Ciphertext) + max( 1 NULL + 1 ROOT, N NULL + N ROOT)
        if value.len() != c + std::cmp::max(2, 2 * n) + 6 {
            return Err("Invalid number of inputs");
        }
        let commitment_root_count = std::cmp::max(1, n);
        let nullifier_count = std::cmp::max(1, n);

        let nullifier_offset = 1 + commitment_root_count;
        let commitment_offset = nullifier_offset + nullifier_count;
        let eph_offset = commitment_offset + c;
        let ciph_offset = eph_offset + 2;
        Ok(Self {
            swap_field: value[0] == F::one(),
            commitment_root: value[1..nullifier_offset].to_vec(),
            nullifiers: value[nullifier_offset..commitment_offset].to_vec(),
            commitments: value[commitment_offset..eph_offset].to_vec(),
            ephemeral_public_key: value[eph_offset..ciph_offset].to_vec(),
            ciphertexts: value[ciph_offset..ciph_offset + 3].to_vec(),
        })
    }
    fn from_transaction<V>(
        transaction: &Transaction<V>,
    ) -> ClientPubInput<<V as Pairing>::ScalarField>
    where
        V: Pairing,
        <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
        <V as Pairing>::ScalarField: PoseidonParams<Field = V::ScalarField>,
    {
        let commitments = transaction
            .commitments
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>();
        let nullifiers = transaction
            .nullifiers
            .iter()
            .map(|n| n.0)
            .collect::<Vec<_>>();
        let commitments_tree = Tree::<V::ScalarField, 8>::from_leaves(commitments.clone());
        ClientPubInput {
            swap_field: transaction.swap_field,
            ciphertexts: transaction.ciphertexts.clone(),
            ephemeral_public_key: transaction.eph_pub_key.clone(),
            commitments,
            nullifiers,
            commitment_root: vec![commitments_tree.root(); transaction.nullifiers.len()],
        }
    }
}

impl<V> From<Transaction<V>> for ClientPubInput<<V as Pairing>::ScalarField>
where
    V: Pairing,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    <V as Pairing>::ScalarField: PoseidonParams<Field = V::ScalarField>,
{
    fn from(value: Transaction<V>) -> Self {
        ClientPubInput::<V::ScalarField>::from_transaction::<V>(&value)
    }
}

impl<V> From<&Transaction<V>> for ClientPubInput<<V as Pairing>::ScalarField>
where
    V: Pairing,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    <V as Pairing>::ScalarField: PoseidonParams<Field = V::ScalarField>,
{
    fn from(value: &Transaction<V>) -> Self {
        ClientPubInput::<V::ScalarField>::from_transaction::<V>(value)
    }
}
