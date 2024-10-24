use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ark_ff::UniformRand;
use ark_std::rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use trees::tree::{AppendTree, IndexedMerkleTree, Tree};

const H: usize = 16;
type F = ark_bn254::Fr;

fn leave_generator(size: i32) -> Vec<F> {
    let mut rng = ChaCha20Rng::seed_from_u64(0u64);
    let max_leaves = 1 << size;
    let leaf_count: u64 = rng.gen_range(1..max_leaves);
    (0..leaf_count).map(|_| F::rand(&mut rng)).collect()
}

fn criterion_benchmark_membership(c: &mut Criterion) {
    let mut group = c.benchmark_group("Membership Tree Building");

    for size in [2, 4, 8].iter() {
        let leaves: Vec<F> = leave_generator(*size);

        group.throughput(Throughput::Elements(*size as u64));

        group.bench_with_input(BenchmarkId::new("Parallel", *size), &leaves, |b, i| {
            b.iter(|| Tree::<F, H>::from_leaves(black_box(i.clone())))
        });
    }
}

fn criterion_benchmark_non_membership(c: &mut Criterion) {
    let mut group = c.benchmark_group("Non Membership Tree Building");

    for size in [2, 4, 8].iter() {
        let leaves: Vec<F> = leave_generator(*size);

        group.throughput(Throughput::Elements(*size as u64));

        group.bench_with_input(BenchmarkId::new("Parallel", *size), &leaves, |b, i| {
            b.iter(|| IndexedMerkleTree::<F, H>::from_leaves(black_box(i.clone())))
        });
    }
}

criterion_group!(
    benches,
    criterion_benchmark_membership,
    criterion_benchmark_non_membership
);
criterion_main!(benches);
