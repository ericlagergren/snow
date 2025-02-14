//! Benchmarks.

#![allow(missing_docs)]

use core::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use snowv::{SnowV, BLOCK_SIZE};

const SIZES: &[usize] = &[64, 256, 1024, 2028, 4096, 8192, 16384];
const BLOCKS: &[usize] = &[1, 2, 4, 8, 16, 32, 64];

fn benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("SNOW-V");

    g.throughput(Throughput::Elements(1))
        .bench_function("new", |b| {
            b.iter(|| {
                black_box(SnowV::new(black_box(&[0; 32]), black_box(&[0; 16])));
            });
        });

    for &size in SIZES {
        g.throughput(Throughput::Bytes(size as u64)).bench_function(
            BenchmarkId::new("apply_keystream", size),
            |b| {
                let mut data = vec![0; size];
                let cipher = SnowV::new(&[0; 32], &[0; 16]);
                b.iter(|| {
                    let _ = cipher.clone().apply_keystream(data.as_mut_slice().into());
                });
                black_box(&data);
            },
        );
    }

    for &size in BLOCKS {
        g.throughput(Throughput::Bytes((BLOCK_SIZE * size) as u64))
            .bench_function(BenchmarkId::new("apply_keystream_blocks", size), |b| {
                let mut data = vec![[0; BLOCK_SIZE]; size];
                let mut cipher = SnowV::new(&[0; 32], &[0; 16]);
                b.iter(|| {
                    let _ = cipher.apply_keystream_blocks(black_box(data.as_mut_slice().into()));
                });
                black_box(&data);
            });
    }

    g.finish();
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
