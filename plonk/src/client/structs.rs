use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::Field;
use common::structs::Transaction;

pub struct ClientPubInputs<F: Field> {
    pub swap_field: bool,
    pub commitment_root: Vec<F>,
    pub nullifiers: Vec<F>,
    pub commitments: Vec<F>,
    pub ephemeral_public_key: Vec<F>,
    pub ciphertexts: Vec<F>,
}

impl<F: Field> ClientPubInputs<F> {
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
}
