//! Hasher benchmark — TASK-018.
//!
//! Measures BLAKE3 throughput across realistic file sizes. The 256 MiB
//! sample doubles as a sanity check for the 1 MiB chunk size (`hasher.rs`
//! `DEFAULT_CHUNK_SIZE`) being the right floor.

use std::fs;
use std::io::Write;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mythkernel::hasher::Hasher;
use tempfile::TempDir;

fn write_payload(dir: &TempDir, bytes: usize) -> std::path::PathBuf {
    let path = dir.path().join(format!("payload_{bytes}.bin"));
    let mut f = fs::File::create(&path).unwrap();
    let chunk: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    let mut written = 0;
    while written < bytes {
        let n = (bytes - written).min(chunk.len());
        f.write_all(&chunk[..n]).unwrap();
        written += n;
    }
    path
}

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("hasher_blake3");
    let tmp = TempDir::new().unwrap();
    for &n in &[64 * 1024usize, 1024 * 1024, 16 * 1024 * 1024] {
        let path = write_payload(&tmp, n);
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            let hasher = Hasher::new();
            b.iter(|| hasher.hash_file(&path).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hash);
criterion_main!(benches);
