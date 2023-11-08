use ark_ff::PrimeField;

pub trait SparseMerkleTree {
    type Field: PrimeField;
    fn non_membership_witness(&self, leaf: Self::Field) -> Vec<Self::Field>;
}
