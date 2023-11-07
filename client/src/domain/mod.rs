mod keypair;
mod transaction;
pub mod primitives {
    use std::marker::PhantomData;

    use ark_ec::pairing::Pairing;

    pub type Curve = ark_bn254::Bn254;
    pub type Fr = ark_bn254::Fr;
    pub type Fq = ark_bn254::Fq;

    pub type ECurve = ark_ed_on_bn254::EdwardsProjective;
    pub type EFr = ark_ed_on_bn254::Fr;
    pub type EFq = ark_ed_on_bn254::Fq;

    // This is just a stub until JF is better complete
    pub struct Proof<P: Pairing> {
        _phantom: PhantomData<P>,
    }
    impl<E: Pairing> Proof<E> {
        pub fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
        pub fn public_inputs(&self) -> Result<Vec<E::ScalarField>, String> {
            Ok(Default::default())
        }
    }
}
pub use self::keypair::*;
pub use self::transaction::*;
pub use primitives::*;
