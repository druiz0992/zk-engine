pub mod circuit_inputs;
pub mod mint;
pub mod swap;
pub mod transfer;

pub mod structs {
    use ark_ec::pairing::Pairing;
    use common::structs::{Commitment, Nullifier};

    pub struct ClientPublicInputs<V: Pairing> {
        pub nullifier: Vec<Nullifier<V::ScalarField>>,
        pub commitment: Vec<Commitment<V::ScalarField>>,
        pub ciphertext: Vec<V::ScalarField>,
        pub commitment_tree_root: V::ScalarField,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct CircuitId(String);

    impl CircuitId {
        pub const fn new(id: String) -> Self {
            CircuitId(id)
        }
    }
}
