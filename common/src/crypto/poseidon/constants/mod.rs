use std::io::Write;

use ark_ff::PrimeField;
use ark_std::str::FromStr;

mod bn254_scalar;
mod pasta_fq;
mod pasta_fr;
pub const MAX_INPUT_LEN: usize = 16;

type Constants<F> = Vec<F>;
type Mds<F> = Vec<Vec<F>>;
pub trait PoseidonParams {
    type Field: PrimeField;
    const N_ROUND_FULL: usize;
    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN];
    fn load_constants() -> (Vec<Constants<Self::Field>>, Vec<Mds<Self::Field>>);
    // useful for memory constrained environment (i.e. circuit)
    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>);
}

use ark_bn254::Fr;
impl PoseidonParams for ark_bn254::Fr {
    type Field = ark_bn254::Fr;
    const N_ROUND_FULL: usize = 8;

    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] = [
        56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
    ];

    fn load_constants() -> (Vec<Constants<ark_bn254::Fr>>, Vec<Mds<ark_bn254::Fr>>) {
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

    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>) {
        let (c_str, m_str) = bn254_scalar::constants();
        let constants = c_str[t - 2]
            .iter()
            .map(|&c| Fr::from_str(c).unwrap())
            .collect::<Vec<Fr>>();
        let matrix = m_str[t - 2]
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&c| Fr::from_str(c).unwrap())
                    .collect::<Vec<Fr>>()
            })
            .collect::<Vec<Vec<Fr>>>();

        (constants, matrix)
    }
}

use curves::pallas::Fr as PastaFr;
impl PoseidonParams for curves::pallas::Fr {
    type Field = curves::pallas::Fr;

    const N_ROUND_FULL: usize = 8;

    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] =
        [56, 56, 56, 56, 57, 57, 57, 57, 0, 0, 0, 0, 0, 0, 0, 0];

    fn load_constants() -> (Vec<Constants<PastaFr>>, Vec<Mds<PastaFr>>) {
        let (c_str, m_str) = pasta_fr::constants();
        let mut c: Vec<Vec<PastaFr>> = Vec::new();
        for i in 0..c_str.len() {
            let mut cci: Vec<PastaFr> = Vec::new();
            for j in 0..c_str[i].len() {
                let b: PastaFr = PastaFr::from_str(c_str[i][j]).unwrap();
                cci.push(b);
            }
            c.push(cci);
        }
        let mut m: Vec<Vec<Vec<PastaFr>>> = Vec::new();
        for i in 0..m_str.len() {
            let mut mi: Vec<Vec<PastaFr>> = Vec::new();
            for j in 0..m_str[i].len() {
                let mut mij: Vec<PastaFr> = Vec::new();
                for k in 0..m_str[i][j].len() {
                    let b: PastaFr = PastaFr::from_str(m_str[i][j][k]).unwrap();
                    mij.push(b);
                }
                mi.push(mij);
            }
            m.push(mi);
        }

        (c, m)
    }
    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>) {
        let (c_str, m_str) = pasta_fr::constants();
        let constants = c_str[t - 2]
            .iter()
            .map(|&c| PastaFr::from_str(c).unwrap())
            .collect::<Vec<PastaFr>>();
        let matrix = m_str[t - 2]
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&c| PastaFr::from_str(c).unwrap())
                    .collect::<Vec<PastaFr>>()
            })
            .collect::<Vec<Vec<PastaFr>>>();

        (constants, matrix)
    }
}

use curves::pallas::Fq as PastaFq;
impl PoseidonParams for curves::pallas::Fq {
    type Field = curves::pallas::Fq;

    const N_ROUND_FULL: usize = 8;

    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] =
        [56, 56, 56, 56, 57, 57, 57, 57, 0, 0, 0, 0, 0, 0, 0, 0];

    fn load_constants() -> (Vec<Constants<PastaFq>>, Vec<Mds<PastaFq>>) {
        let (c_str, m_str) = pasta_fq::constants();
        let mut c: Vec<Vec<PastaFq>> = Vec::new();
        for cs in c_str.into_iter() {
            let mut cci: Vec<PastaFq> = Vec::new();
            for j in cs.into_iter() {
                let b: PastaFq = PastaFq::from_str(j).unwrap();
                cci.push(b);
            }
            c.push(cci);
        }
        let mut m: Vec<Vec<Vec<PastaFq>>> = Vec::new();
        for i in 0..m_str.len() {
            let mut mi: Vec<Vec<PastaFq>> = Vec::new();
            for j in 0..m_str[i].len() {
                let mut mij: Vec<PastaFq> = Vec::new();
                for k in 0..m_str[i][j].len() {
                    let b: PastaFq = PastaFq::from_str(m_str[i][j][k]).unwrap();
                    mij.push(b);
                }
                mi.push(mij);
            }
            m.push(mi);
        }

        (c, m)
    }

    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>) {
        let (c_str, m_str) = pasta_fq::constants();
        let constants = c_str[t - 2]
            .iter()
            .map(|&c| PastaFq::from_str(c).unwrap())
            .collect::<Vec<PastaFq>>();
        let matrix = m_str[t - 2]
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&c| PastaFq::from_str(c).unwrap())
                    .collect::<Vec<PastaFq>>()
            })
            .collect::<Vec<Vec<PastaFq>>>();

        (constants, matrix)
    }
}
