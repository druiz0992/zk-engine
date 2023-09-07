mod gate;
mod poseidon_constants;
use ark_ff::{PrimeField, Zero};
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit, Variable};

use self::gate::{FullRoundGate, PartialRoundGate};

pub const MAX_INPUT_LEN: usize = 16;

pub trait PoseidonParams: PrimeField {
    const N_ROUND_FULL: usize;
    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN];
}

pub trait PoseidonGadget<T, P> {
    fn ark(&mut self, state: T, constants: &[P], it: usize) -> Result<T, CircuitError>;
    fn sbox(
        &mut self,
        state: T,
        full_rounds: usize,
        partial_rounds: usize,
        round_index: usize,
    ) -> Result<T, CircuitError>;
    fn mix(&mut self, state: T, matrix: &[Vec<P>]) -> Result<T, CircuitError>;
    fn hash(&mut self, inputs: &[Variable]) -> Result<Variable, CircuitError>;
    fn full_round(&mut self, state: T, matrix: &[Vec<P>]) -> Result<T, CircuitError>;
    fn partial_round(&mut self, state: T, matrix: &[Vec<P>]) -> Result<T, CircuitError>;
}

pub type PoseidonStateVar<const N: usize> = [Variable; N];

impl<const N: usize, F> PoseidonGadget<PoseidonStateVar<N>, F> for PlonkCircuit<F>
where
    F: PoseidonParams,
{
    fn ark(
        &mut self,
        mut state: PoseidonStateVar<N>,
        constants: &[F],
        it: usize,
    ) -> Result<PoseidonStateVar<N>, CircuitError> {
        self.check_vars_bound(&state)?;
        for (idx, i) in state.iter_mut().enumerate() {
            *i = self.add_constant(*i, &constants[it + idx])?;
        }
        Ok(state)
    }

    fn sbox(
        &mut self,
        mut state: PoseidonStateVar<N>,
        full_rounds: usize,
        partial_rounds: usize,
        round_index: usize,
    ) -> Result<PoseidonStateVar<N>, CircuitError> {
        self.check_vars_bound(&state)?;
        if round_index < full_rounds / 2 || round_index >= full_rounds / 2 + partial_rounds {
            for k in state.iter_mut() {
                let x2 = self.mul(*k, *k)?;
                let x4 = self.mul(x2, x2)?;
                *k = self.mul(x4, *k)?;
            }
        } else {
            let x2 = self.mul(state[0], state[0])?;
            let x4 = self.mul(x2, x2)?;
            state[0] = self.mul(x4, state[0])?;
        }
        Ok(state)
    }

    fn mix(
        &mut self,
        state: PoseidonStateVar<N>,
        matrix: &[Vec<F>],
    ) -> Result<PoseidonStateVar<N>, CircuitError> {
        self.check_vars_bound(&state)?;
        let mut new_arr = [Variable::zero(); N];
        for (i, matrix_row) in matrix.iter().enumerate() {
            for (j, state_val) in state.iter().enumerate() {
                let mixed_val = self.mul_constant(*state_val, &matrix_row[j])?;
                new_arr[i] = self.add_constant(mixed_val, &self.witness(new_arr[i]).unwrap())?;
            }
        }
        Ok(new_arr)
    }

    fn hash(&mut self, inputs: &[Variable]) -> Result<Variable, CircuitError> {
        let t = inputs.len() + 1;
        let mut state = [Variable::zero(); N];
        state[1..].clone_from_slice(inputs);
        let n_rounds_p = F::N_ROUNDS_PARTIAL[t - 2];
        let (c_str, m_str) = poseidon_constants::constants::constants();
        let constants = c_str[t - 2]
            .iter()
            .map(|&c| F::from_str(c))
            .collect::<Result<Vec<F>, _>>()
            .map_err(|_| CircuitError::InternalError("InvalidConstant".to_string()))?;
        let matrix = m_str[t - 2]
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&c| F::from_str(c))
                    .collect::<Result<Vec<F>, _>>()
                    .map_err(|_| CircuitError::InternalError("InvalidConstant".to_string()))
            })
            .collect::<Result<Vec<Vec<F>>, _>>()?;

        if N <= 4 {
            for i in 0..F::N_ROUND_FULL / 2 {
                state = self.ark(state, constants.as_slice(), i * t)?;
                state = self.full_round(state, matrix.as_slice())?;
            }
            for i in F::N_ROUND_FULL / 2..n_rounds_p + F::N_ROUND_FULL / 2 {
                state = self.ark(state, constants.as_slice(), i * t)?;
                state = self.partial_round(state, matrix.as_slice())?;
            }
            for i in n_rounds_p + F::N_ROUND_FULL / 2..F::N_ROUND_FULL + n_rounds_p {
                state = self.ark(state, constants.as_slice(), i * t)?;
                state = self.full_round(state, matrix.as_slice())?;
            }
            return Ok(state[0]);
        }
        for i in 0..(n_rounds_p + F::N_ROUND_FULL) {
            state = self.ark(state, constants.as_slice(), i * t)?;
            state = self.sbox(state, F::N_ROUND_FULL, n_rounds_p, i)?;
            state = self.mix(state, matrix.as_slice())?;
        }
        Ok(state[0])
    }

    fn full_round(
        &mut self,
        state: PoseidonStateVar<N>,
        matrix: &[Vec<F>],
    ) -> Result<PoseidonStateVar<N>, CircuitError> {
        self.check_vars_bound(&state)?;
        // Only to be used when N < 5 (i.e. Poseidon 4 or Poseidon 5)

        let state_vals = state
            .iter()
            .map(|&s| self.witness(s))
            .collect::<Result<Vec<_>, _>>()?;
        // Perform i^5 - S-Box
        let x5s = state_vals
            .iter()
            .map(|&s| s.pow([5u64]))
            .collect::<Vec<_>>();
        let mut output = [F::zero(); N];
        // Run Mix
        for i in 0..N {
            let matrix_row = &matrix[i];
            let dot_product = x5s
                .iter()
                .zip(matrix_row.iter())
                .fold(F::zero(), |acc, (&a, &b)| acc + (a * b));
            output[i] = dot_product; //  + constants[it + i];
        }
        // Enforce constraints using a custom gate
        let output_vars = output
            .iter()
            .map(|&o| self.create_variable(o))
            .collect::<Result<Vec<_>, _>>()?;
        for i in 0..N {
            let mut wire_vars = [0, 0, 0, 0, output_vars[i]];
            for (i, s) in state.iter().enumerate() {
                wire_vars[i] = *s;
            }
            let mut matrix_row = matrix[i].clone();
            matrix_row.resize(4, F::zero());
            self.insert_gate(
                &wire_vars,
                Box::new(FullRoundGate::<F> {
                    matrix_vector: matrix_row,
                }),
            )?;
        }
        Ok(output_vars.try_into().unwrap())
    }

    fn partial_round(
        &mut self,
        state: PoseidonStateVar<N>,
        matrix: &[Vec<F>],
    ) -> Result<PoseidonStateVar<N>, CircuitError> {
        self.check_vars_bound(&state)?;
        // Only to be used when N < 5 (i.e. Poseidon 4 or Poseidon 5)
        let mut state_vals = state
            .iter()
            .map(|&s| self.witness(s))
            .collect::<Result<Vec<_>, _>>()?;
        // Perform i^5 - S-Box
        state_vals[0] = state_vals[0].pow([5u64]);
        let mut output = [F::zero(); N];
        for i in 0..N {
            let matrix_row = &matrix[i];
            let dot_product = state_vals
                .iter()
                .zip(matrix_row.iter())
                .fold(F::zero(), |acc, (&a, &b)| acc + (a * b));
            output[i] = dot_product;
        }
        let output_vars = output
            .iter()
            .map(|&o| self.create_variable(o))
            .collect::<Result<Vec<_>, _>>()?;
        for i in 0..N {
            let mut wire_vars = [0, 0, 0, 0, output_vars[i]];
            for (i, s) in state.iter().enumerate() {
                wire_vars[i] = *s;
            }
            let mut matrix_row = matrix[i].clone();
            matrix_row.resize(4, F::zero());
            self.insert_gate(
                &wire_vars,
                Box::new(PartialRoundGate::<F> {
                    matrix_vector: matrix_row,
                }),
            )?;
        }
        Ok(output_vars.try_into().unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ed_on_bn254::Fq;
    use ark_std::str::FromStr;
    use poseidon_ark::Poseidon;

    #[test]
    fn test_poseidon() {
        test_poseidon_helper::<2>(
            vec![Fq::from_str("1").unwrap()],
            "18586133768512220936620570745912940619677854269274689475585506675881198879027",
        );
    }
    fn test_poseidon_helper<const N: usize>(arr: Vec<Fq>, expected: &str) {
        let poseidon = Poseidon::new();
        let h = poseidon.hash(arr.clone()).unwrap();
        assert_eq!(h.to_string(), expected);

        let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
        let data_arr: Vec<_> = arr
            .iter()
            .map(|&b| circuit.create_variable(b).unwrap())
            .collect();
        let circuit_hash =
            PoseidonGadget::<PoseidonStateVar<N>, Fq>::hash(&mut circuit, data_arr.as_slice())
                .unwrap();
        assert_eq!(
            h.to_string(),
            circuit.witness(circuit_hash).unwrap().to_string()
        );
    }

    #[test]
    // Test against circom test vectors https://github.com/iden3/circomlib/blob/master/test/poseidoncircuit.js
    fn test_vectors_poseidon_6() {
        let vec_1: Vec<Fq> = vec![
            Fq::from_str("1").unwrap(),
            Fq::from_str("2").unwrap(),
            Fq::from_str("0").unwrap(),
            Fq::from_str("0").unwrap(),
            Fq::from_str("0").unwrap(),
        ];
        test_poseidon_helper::<6>(
            vec_1,
            "1018317224307729531995786483840663576608797660851238720571059489595066344487",
        );

        let vec_2: Vec<Fq> = vec![
            Fq::from_str("3").unwrap(),
            Fq::from_str("4").unwrap(),
            Fq::from_str("5").unwrap(),
            Fq::from_str("10").unwrap(),
            Fq::from_str("23").unwrap(),
        ];

        test_poseidon_helper::<6>(
            vec_2,
            "13034429309846638789535561449942021891039729847501137143363028890275222221409",
        );
    }

    #[test]
    fn test_vectors_poseidon_3() {
        let vec_1: Vec<Fq> = vec![Fq::from_str("1").unwrap(), Fq::from_str("2").unwrap()];
        test_poseidon_helper::<3>(
            vec_1,
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
        );

        let vec_2: Vec<Fq> = vec![Fq::from_str("3").unwrap(), Fq::from_str("4").unwrap()];

        test_poseidon_helper::<3>(
            vec_2,
            "14763215145315200506921711489642608356394854266165572616578112107564877678998",
        );
    }

    #[test]
    fn test_vectors_poseidon_16() {
        let vec_1 = vec![
            Fq::from_str("1").unwrap(),
            Fq::from_str("2").unwrap(),
            Fq::from_str("3").unwrap(),
            Fq::from_str("4").unwrap(),
            Fq::from_str("5").unwrap(),
            Fq::from_str("6").unwrap(),
            Fq::from_str("7").unwrap(),
            Fq::from_str("8").unwrap(),
            Fq::from_str("9").unwrap(),
            Fq::from_str("10").unwrap(),
            Fq::from_str("11").unwrap(),
            Fq::from_str("12").unwrap(),
            Fq::from_str("13").unwrap(),
            Fq::from_str("14").unwrap(),
            Fq::from_str("15").unwrap(),
            Fq::from_str("16").unwrap(),
        ];
        test_poseidon_helper::<17>(
            vec_1,
            "9989051620750914585850546081941653841776809718687451684622678807385399211877",
        );
    }
}
