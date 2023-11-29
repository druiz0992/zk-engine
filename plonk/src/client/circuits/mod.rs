pub mod mint;
pub mod swap;
pub mod transfer;

pub mod structs {
    use ark_ec::{pairing::Pairing, short_weierstrass::Affine};
    use common::structs::{Commitment, Nullifier};
    pub struct ClientPublicInputs<V: Pairing> {
        pub nullifier: Vec<Nullifier<V::ScalarField>>,
        pub commitment: Vec<Commitment<V::ScalarField>>,
        pub ciphertext: Vec<V::ScalarField>,
        pub commitment_tree_root: V::ScalarField,
        // ephemeral key
    }
}
