use ark_ff::PrimeField;
use ark_std::str::FromStr;

mod bn254_scalar;
pub const MAX_INPUT_LEN: usize = 16;

type Constants<F> = Vec<Vec<F>>;
type Mds<F> = Vec<Vec<Vec<F>>>;
pub trait PoseidonParams {
    type Field: PrimeField;
    const N_ROUND_FULL: usize;
    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN];
    fn load_constants() -> (Constants<Self::Field>, Mds<Self::Field>);
}

use ark_bn254::Fr;
impl PoseidonParams for ark_bn254::Fr {
    type Field = ark_bn254::Fr;
    const N_ROUND_FULL: usize = 8;

    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] = [
        56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
    ];

    fn load_constants() -> (Constants<ark_bn254::Fr>, Mds<ark_bn254::Fr>) {
        let (c_str, m_str) = bn254_scalar::constants();
        let mut c: Vec<Vec<Fr>> = Vec::new();
        for i in 0..c_str.len() {
            let mut cci: Vec<Fr> = Vec::new();
            for j in 0..c_str[i].len() {
                let b: Fr = Fr::from_str(c_str[i][j]).unwrap();
                cci.push(b);
            }
            c.push(cci);
        }
        let mut m: Vec<Vec<Vec<Fr>>> = Vec::new();
        for i in 0..m_str.len() {
            let mut mi: Vec<Vec<Fr>> = Vec::new();
            for j in 0..m_str[i].len() {
                let mut mij: Vec<Fr> = Vec::new();
                for k in 0..m_str[i][j].len() {
                    let b: Fr = Fr::from_str(m_str[i][j][k]).unwrap();
                    mij.push(b);
                }
                mi.push(mij);
            }
            m.push(mi);
        }

        (c, m)
    }
}
