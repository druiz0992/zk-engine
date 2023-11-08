// Modified from the original version by arnaucubeto be adaptable over F
pub mod constants;
use ark_ff::{Field, Zero};
use std::ops::{AddAssign, MulAssign};

use ark_ff::PrimeField;

use self::constants::PoseidonParams;

use super::crypto_errors::CryptoError;

#[derive(Debug)]
pub struct Constants<F: PrimeField> {
    pub c: Vec<Vec<F>>,
    pub m: Vec<Vec<Vec<F>>>,
}
pub struct Poseidon<P: PoseidonParams> {
    constants: Constants<P::Field>,
}
impl<P: PoseidonParams> Default for Poseidon<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: PoseidonParams> Poseidon<P> {
    pub fn new() -> Self {
        let (c, m) = P::load_constants();
        let constants = Constants { c, m };
        Poseidon { constants }
    }
    pub fn ark(&self, state: &mut Vec<P::Field>, c: &[P::Field], it: usize) {
        for i in 0..state.len() {
            state[i].add_assign(&c[it + i]);
        }
    }

    pub fn sbox(&self, n_rounds_f: usize, n_rounds_p: usize, state: &mut [P::Field], i: usize) {
        if i < n_rounds_f / 2 || i >= n_rounds_f / 2 + n_rounds_p {
            for j in state.iter_mut() {
                let aux = *j;
                j.square_in_place();
                j.square_in_place();
                *j *= aux
            }
        } else {
            let aux = state[0];
            state[0].square_in_place();
            state[0].square_in_place();
            state[0].mul_assign(&aux);
        }
    }

    pub fn mix(&self, state: &Vec<P::Field>, m: &[Vec<P::Field>]) -> Vec<P::Field> {
        let mut new_state: Vec<P::Field> = Vec::new();
        for i in 0..state.len() {
            new_state.push(P::Field::zero());
            for (j, item) in state.iter().enumerate() {
                let mut mij = m[i][j];
                mij.mul_assign(item);
                new_state[i].add_assign(&mij);
            }
        }
        new_state
    }

    pub fn hash(&self, inp: Vec<P::Field>) -> Result<P::Field, CryptoError> {
        let t = inp.len() + 1;
        // if inp.len() == 0 || inp.len() >= self.constants.n_rounds_p.len() - 1 {
        if inp.is_empty() || inp.len() > P::N_ROUNDS_PARTIAL.len() {
            return Err(CryptoError::HashError("Wrong inputs length".to_string()));
        }
        let n_rounds_f = P::N_ROUND_FULL;
        let n_rounds_p = P::N_ROUNDS_PARTIAL[t - 2];

        let mut state = vec![P::Field::zero(); t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(n_rounds_f + n_rounds_p) {
            self.ark(&mut state, &self.constants.c[t - 2], i * t);
            self.sbox(n_rounds_f, n_rounds_p, &mut state, i);
            state = self.mix(&state, &self.constants.m[t - 2]);
        }

        Ok(state[0])
    }

    /// This is like hash but without checking the length of the input
    /// Useful if we know the input length will be right
    pub fn hash_unchecked(&self, inp: Vec<P::Field>) -> P::Field {
        let t = inp.len() + 1;
        let n_rounds_f = P::N_ROUND_FULL;
        let n_rounds_p = P::N_ROUNDS_PARTIAL[t - 2];

        let mut state = vec![P::Field::zero(); t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(n_rounds_f + n_rounds_p) {
            self.ark(&mut state, &self.constants.c[t - 2], i * t);
            self.sbox(n_rounds_f, n_rounds_p, &mut state, i);
            state = self.mix(&state, &self.constants.m[t - 2]);
        }

        state[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use std::str::FromStr;

    #[test]
    fn test_hash() {
        let b0: Fr = Fr::from_str("0").unwrap();
        let b1: Fr = Fr::from_str("1").unwrap();
        let b2: Fr = Fr::from_str("2").unwrap();
        let b3: Fr = Fr::from_str("3").unwrap();
        let b4: Fr = Fr::from_str("4").unwrap();
        let b5: Fr = Fr::from_str("5").unwrap();
        let b6: Fr = Fr::from_str("6").unwrap();
        let b7: Fr = Fr::from_str("7").unwrap();
        let b8: Fr = Fr::from_str("8").unwrap();
        let b9: Fr = Fr::from_str("9").unwrap();
        let b10: Fr = Fr::from_str("10").unwrap();
        let b11: Fr = Fr::from_str("11").unwrap();
        let b12: Fr = Fr::from_str("12").unwrap();
        let b13: Fr = Fr::from_str("13").unwrap();
        let b14: Fr = Fr::from_str("14").unwrap();
        let b15: Fr = Fr::from_str("15").unwrap();
        let b16: Fr = Fr::from_str("16").unwrap();

        let poseidon: Poseidon<Fr> = Poseidon::new();

        let big_arr: Vec<Fr> = vec![b1];
        // let mut big_arr: Vec<Fr> = Vec::new();
        // big_arr.push(b1.clone());
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        );

        let big_arr: Vec<Fr> = vec![b1, b2];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b0, b0, b0];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "1018317224307729531995786483840663576608797660851238720571059489595066344487"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b0, b0, b0, b0];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "15336558801450556532856248569924170992202208561737609669134139141992924267169"
        );

        let big_arr: Vec<Fr> = vec![b3, b4, b0, b0, b0];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "5811595552068139067952687508729883632420015185677766880877743348592482390548"
        );

        let big_arr: Vec<Fr> = vec![b3, b4, b0, b0, b0, b0];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "12263118664590987767234828103155242843640892839966517009184493198782366909018"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "20400040500897583745843009878988256314335038853985262692600694741116813247201"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "8354478399926161176778659061636406690034081872658507739535256090879947077494"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "5540388656744764564518487011617040650780060800286365721923524861648744699539"
        );

        let big_arr: Vec<Fr> = vec![
            b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0, b0, b0,
        ];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "11882816200654282475720830292386643970958445617880627439994635298904836126497"
        );

        let big_arr: Vec<Fr> = vec![
            b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16,
        ];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "9989051620750914585850546081941653841776809718687451684622678807385399211877"
        );
    }

    #[test]
    fn test_wrong_inputs() {
        let b0: Fr = Fr::from_str("0").unwrap();
        let b1: Fr = Fr::from_str("1").unwrap();
        let b2: Fr = Fr::from_str("2").unwrap();

        let poseidon: Poseidon<Fr> = Poseidon::new();

        let big_arr: Vec<Fr> = vec![
            b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0,
        ];
        poseidon.hash(big_arr).expect_err("Wrong inputs length");
    }
}
