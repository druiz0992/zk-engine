use ark_ff::PrimeField;

pub trait MerkleTree {
    type Field: PrimeField;
    fn membership_witness(&self, leaf: Self::Field) -> Vec<Self::Field>;
}
