//! Benchmarks.

//use core::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use snowv::SnowV;

const SIZES: &[usize] = &[64, 256, 1024, 2028, 4096, 8192, 16384];

fn benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("basic");
    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64)).bench_function(
            BenchmarkId::new("try_apply_keystream", size),
            |b| {
                let mut data = vec![0; size];
                let cipher = SnowV::new(&[0; 32], &[0; 16]);
                b.iter(|| {
                    let _ = cipher
                        .clone()
                        .try_apply_keystream(data.as_mut_slice().into());
                });
            },
        );
    }

    g.finish();
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
