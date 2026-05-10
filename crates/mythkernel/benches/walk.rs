//! Walker benchmark — TASK-018.
//!
//! Measures the posix walker on synthetic trees of growing fan-out. Use
//! `scripts/bench-1m-files.sh` to drive a 1M-file end-to-end run that
//! asserts the NFR-001 cold-scan budget (`docs/prd.md` § 7).

use std::fs;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mythkernel::walker::{FileWalker, PosixWalker, WalkEvent, WalkOpts};
use tempfile::TempDir;

fn build_tree(root: &Path, files: usize) {
    let dirs = ((files as f64).sqrt() as usize).max(1);
    let per_dir = files / dirs.max(1);
    for d in 0..dirs {
        let dir = root.join(format!("d{d:04}"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..per_dir {
            fs::write(dir.join(format!("f{f:04}.txt")), b"x").unwrap();
        }
    }
}

fn bench_walk(c: &mut Criterion) {
    let mut group = c.benchmark_group("walker_posix");
    for &n in &[100usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // Build the tree once per benchmark configuration; the per-iter
            // work is the walk itself, not the FS-prep.
            let tmp = TempDir::new().unwrap();
            build_tree(tmp.path(), n);
            let walker = PosixWalker::new();
            b.iter(|| {
                let rx = walker.walk(tmp.path(), WalkOpts::default());
                let mut count = 0usize;
                for event in rx.iter() {
                    if matches!(event, WalkEvent::File { .. }) {
                        count += 1;
                    }
                }
                count
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_walk);
criterion_main!(benches);
