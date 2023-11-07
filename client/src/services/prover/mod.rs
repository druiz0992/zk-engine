struct InMemProver;
mod in_memory_prover {
    use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveConfig, CurveGroup};

    use crate::{
        domain::{CircuitInputs, CircuitType, Proof},
        ports::prover::Prover,
    };

    use super::InMemProver;

    impl<E> Prover<E> for InMemProver
    where
        E: Pairing,
    {
        fn prove<I: Pairing>(
            circuit_type: CircuitType,
            circuit_inputs: CircuitInputs<I>,
        ) -> Result<(Proof<E>, Vec<E::ScalarField>), &'static str> {
            let proof = Proof::new();
            Ok((proof, [].to_vec()))
        }

        fn verify<F: ark_ff::FftField>(
            circuit_type: crate::domain::CircuitType,
            public_inputs: Option<Vec<F>>,
        ) -> bool {
            true
        }
    }
}
