use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ark_ff::UniformRand;
use ark_std::rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use trees::tree::Tree;

const H: usize = 16;
type F = ark_bn254::Fr;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(0u64);

    let mut group = c.benchmark_group("Tree Building");

    for size in [2, 4, 8].iter() {
        let max_leaves = 1 << size;
        let leaf_count: u64 = rng.gen_range(1..max_leaves);
        let leaves: Vec<F> = (0..leaf_count).map(|_| F::rand(&mut rng)).collect();

        group.throughput(Throughput::Elements(*size as u64));

        group.bench_with_input(BenchmarkId::new("Parallel", *size), &leaves, |b, i| {
            b.iter(|| Tree::<F, H>::from_leaves_in_place(black_box(i.clone())))
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
