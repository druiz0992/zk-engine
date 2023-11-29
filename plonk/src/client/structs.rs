use ark_ff::Field;

pub struct ClientPubInputs<F: Field, const N: usize, const C: usize> {
    pub commitments: Vec<F>,
    pub nullifiers: Vec<F>,
    pub ciphertexts: Vec<F>,
    pub commitment_root: F,
}

impl<F: Field, const N: usize, const C: usize> TryFrom<Vec<F>> for ClientPubInputs<F, N, C> {
    type Error = &'static str;

    fn try_from(value: Vec<F>) -> Result<Self, Self::Error> {
        if value.len() != N + C + 4 {
            return Err("Invalid number of inputs");
        }
        Ok(Self {
            commitments: value[0..N].to_vec(),
            nullifiers: value[N..N + C].to_vec(),
            ciphertexts: value[N + C..N + C + 3].to_vec(),
            commitment_root: value[N + C + 3],
        })
    }
}
