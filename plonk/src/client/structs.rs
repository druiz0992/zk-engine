use ark_ff::Field;

pub struct ClientPubInputs<F: Field, const N: usize, const C: usize> {
    pub swap_field: bool,
    pub commitment_root: Vec<F>,
    pub nullifiers: Vec<F>,
    pub commitments: Vec<F>,
    pub ephemeral_public_key: Vec<F>,
    pub ciphertexts: Vec<F>,
}

impl<F: Field, const N: usize, const C: usize> TryFrom<Vec<F>> for ClientPubInputs<F, N, C> {
    type Error = &'static str;

    fn try_from(value: Vec<F>) -> Result<Self, Self::Error> {
        if value.len() != C + 2 * N + 6 {
            return Err("Invalid number of inputs");
        }
        Ok(Self {
            swap_field: value[0] == F::one(),
            commitment_root: value[1..N + 1].to_vec(),
            nullifiers: value[N + 1..2 * N + 1].to_vec(),
            commitments: value[2 * N + 1..2 * N + C + 1].to_vec(),
            ephemeral_public_key: value[2 * N + C + 1..2 * N + C + 3].to_vec(),
            ciphertexts: value[2 * N + C + 3..].to_vec(),
        })
    }
}
