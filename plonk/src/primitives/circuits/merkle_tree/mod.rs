use crate::primitives::circuits::poseidon::{PoseidonGadget, PoseidonParams, PoseidonStateVar};
use ark_ff::PrimeField;
use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};

// D is the depth of the merkle tree
pub trait BinaryMerkleTreeGadget<const D: usize, P: PrimeField> {
    fn decompose_leaf_index(&mut self, leaf_index: P) -> Result<Vec<BoolVar>, CircuitError>;
    fn calculate_root(
        &mut self,
        leaf_value: Variable,
        leaf_index: P,
        sibling_path: [P; D],
    ) -> Result<Variable, CircuitError>;
}

impl<const D: usize, P> BinaryMerkleTreeGadget<D, P> for PlonkCircuit<P>
where
    P: PrimeField + PoseidonParams,
{
    fn decompose_leaf_index(&mut self, leaf_index: P) -> Result<Vec<BoolVar>, CircuitError> {
        let leaf_index_var = self.create_variable(leaf_index)?;
        self.unpack(leaf_index_var, D)
    }

    fn calculate_root(
        &mut self,
        leaf_value: Variable,
        leaf_index: P,
        sibling_path: [P; D],
    ) -> Result<Variable, CircuitError> {
        let commitment_leaf_index_bit_var =
            BinaryMerkleTreeGadget::<D, P>::decompose_leaf_index(self, leaf_index)?;
        let mut acc_comm_hash_var = leaf_value;
        for (j, &sibling_path) in sibling_path.iter().enumerate() {
            let commitment_sibling_path_var = self.create_variable(sibling_path)?;
            let left_sibling = self.conditional_select(
                commitment_leaf_index_bit_var[j],
                acc_comm_hash_var,
                commitment_sibling_path_var,
            )?;
            let right_sibling = self.conditional_select(
                commitment_leaf_index_bit_var[j],
                commitment_sibling_path_var,
                acc_comm_hash_var,
            )?;
            acc_comm_hash_var = PoseidonGadget::<PoseidonStateVar<3>, P>::hash(
                self,
                &[left_sibling, right_sibling],
            )?;
        }
        Ok(acc_comm_hash_var)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ed_on_bn254::Fq;
    use ark_std::UniformRand;
    use poseidon_ark::Poseidon;

    #[test]
    fn test_binary_merkle_gadget() {
        test_binary_merkle_gadget_helper::<2>(1);
        test_binary_merkle_gadget_helper::<16>(20);
        test_binary_merkle_gadget_helper::<32>(5);
    }
    fn test_binary_merkle_gadget_helper<const D: usize>(index: u32) {
        let mut rng = ark_std::test_rng();
        let rand_leaf = Fq::rand(&mut rng);
        let rand_siblings = (0..D).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();

        let root = rand_siblings
            .clone()
            .into_iter()
            .enumerate()
            .fold(rand_leaf, |a, (i, b)| {
                let poseidon = Poseidon::new();
                let bit_dir = index >> i & 1;
                if bit_dir == 0 {
                    poseidon.hash(vec![a, b]).unwrap()
                } else {
                    poseidon.hash(vec![b, a]).unwrap()
                }
            });

        let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
        let rand_leaf_var = circuit.create_variable(rand_leaf).unwrap();
        let circuit_hash = BinaryMerkleTreeGadget::<D, Fq>::calculate_root(
            &mut circuit,
            rand_leaf_var,
            Fq::from(index),
            rand_siblings.try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(
            root.to_string(),
            circuit.witness(circuit_hash).unwrap().to_string()
        );
    }
}
