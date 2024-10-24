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

    #[allow(clippy::type_complexity)]
    fn load_constants() -> (Vec<Constants<Self::Field>>, Vec<Mds<Self::Field>>);
    // useful for memory constrained environment (i.e. circuit)
    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>);
}

fn load_from_str<F>(
    c_str: Vec<Vec<&str>>,
    m_str: Vec<Vec<Vec<&str>>>,
) -> (Vec<Vec<F>>, Vec<Vec<Vec<F>>>)
where
    F: PrimeField,
    <F as FromStr>::Err: std::fmt::Debug,
{
    let constants = c_str
        .into_iter()
        .map(|c_row| {
            c_row
                .into_iter()
                .map(|c| F::from_str(c).expect("Failed to parse constant"))
                .collect()
        })
        .collect();

    let mds_matrix = m_str
        .into_iter()
        .map(|m_row| {
            m_row
                .into_iter()
                .map(|m_col| {
                    m_col
                        .into_iter()
                        .map(|m| F::from_str(m).expect("Failed to parse MDS matrix"))
                        .collect()
                })
                .collect()
        })
        .collect();

    (constants, mds_matrix)
}

fn load_subset_from_str<F>(
    t: usize,
    c_str: &[Vec<&str>],
    m_str: &[Vec<Vec<&str>>],
) -> (Vec<F>, Vec<Vec<F>>)
where
    F: PrimeField,
    <F as FromStr>::Err: std::fmt::Debug,
{
    let constants = c_str[t - 2]
        .iter()
        .map(|&c| F::from_str(c).expect("Failed to parse constants"))
        .collect();
    let matrix = m_str[t - 2]
        .iter()
        .map(|row| {
            row.iter()
                .map(|&c| F::from_str(c).expect("Failed to parse MDS matrix"))
                .collect()
        })
        .collect();
    (constants, matrix)
}

impl PoseidonParams for ark_bn254::Fr {
    type Field = ark_bn254::Fr;
    const N_ROUND_FULL: usize = 8;

    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] = [
        56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
    ];

    fn load_constants() -> (Vec<Constants<Self::Field>>, Vec<Mds<Self::Field>>) {
        let (c_str, m_str) = bn254_scalar::constants();
        load_from_str(c_str, m_str)
    }

    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>) {
        let (c_str, m_str) = bn254_scalar::constants();
        load_subset_from_str(t, &c_str, &m_str)
    }
}

use curves::pallas::Fr as PastaFr;
impl PoseidonParams for PastaFr {
    type Field = PastaFr;

    const N_ROUND_FULL: usize = 8;
    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] =
        [56, 56, 56, 56, 57, 57, 57, 57, 0, 0, 0, 0, 0, 0, 0, 0];

    fn load_constants() -> (Vec<Constants<Self::Field>>, Vec<Mds<Self::Field>>) {
        let (c_str, m_str) = pasta_fr::constants();
        load_from_str(c_str, m_str)
    }

    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>) {
        let (c_str, m_str) = pasta_fr::constants();
        load_subset_from_str(t, &c_str, &m_str)
    }
}

use curves::pallas::Fq as PastaFq;
impl PoseidonParams for PastaFq {
    type Field = PastaFq;

    const N_ROUND_FULL: usize = 8;
    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] =
        [56, 56, 56, 56, 57, 57, 57, 57, 0, 0, 0, 0, 0, 0, 0, 0];

    fn load_constants() -> (Vec<Constants<Self::Field>>, Vec<Mds<Self::Field>>) {
        let (c_str, m_str) = pasta_fq::constants();
        load_from_str(c_str, m_str)
    }

    fn load_subset_constants(t: usize) -> (Constants<Self::Field>, Mds<Self::Field>) {
        let (c_str, m_str) = pasta_fq::constants();
        load_subset_from_str(t, &c_str, &m_str)
    }
}
