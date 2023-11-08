use ark_ed_on_bn254::Fq;
use criterion::{criterion_group, criterion_main, Criterion};
use jf_relation::{Circuit, PlonkCircuit};
use plonk_prover::primitives::circuits::poseidon::{PoseidonGadget, PoseidonStateVar};
use std::str::FromStr;

pub fn benchmark_poseidon(c: &mut Criterion) {
    c.bench_function("Poseidon Circuit_3", |b| {
        b.iter(|| {
            let arr = vec![Fq::from_str("1").unwrap(), Fq::from_str("2").unwrap()];
            let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
            let data_arr: Vec<_> = arr
                .iter()
                .map(|&b| circuit.create_variable(b).unwrap())
                .collect();
            PoseidonGadget::<PoseidonStateVar<3>, Fq>::hash(&mut circuit, data_arr.as_slice())
                .unwrap();
            circuit.num_gates();
            circuit.finalize_for_arithmetization().unwrap();
        })
    });
    c.bench_function("Poseidon Circuit_6", |b| {
        b.iter(|| {
            let arr = vec![
                Fq::from_str("1").unwrap(),
                Fq::from_str("2").unwrap(),
                Fq::from_str("3").unwrap(),
                Fq::from_str("4").unwrap(),
                Fq::from_str("5").unwrap(),
            ];
            let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
            let data_arr: Vec<_> = arr
                .iter()
                .map(|&b| circuit.create_variable(b).unwrap())
                .collect();
            PoseidonGadget::<PoseidonStateVar<6>, Fq>::hash(&mut circuit, data_arr.as_slice())
                .unwrap();
            circuit.finalize_for_arithmetization().unwrap();
        })
    });
}

criterion_group!(benches, benchmark_poseidon);
criterion_main!(benches);
