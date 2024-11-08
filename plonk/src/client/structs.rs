use ark_ff::Field;

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
        Ok(Self {
            swap_field: value[0] == F::one(),
            commitment_root: value[1..n + 1].to_vec(),
            nullifiers: value[n + 1..2 * c + 1].to_vec(),
            commitments: value[2 * n + 1..2 * n + c + 1].to_vec(),
            ephemeral_public_key: value[2 * n + c + 1..2 * n + c + 3].to_vec(),
            ciphertexts: value[2 * n + c + 3..].to_vec(),
        })
    }
}
