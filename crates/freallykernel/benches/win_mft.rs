//! Windows MFT walker benchmark — TASK-057.
//!
//! Compares the platform-fast walker (`NtfsWalker` — NTFS MFT on Windows,
//! `getdents64` on Linux, FSEvents-driven `read_dir` on macOS) against
//! the `PosixWalker` baseline. The interesting numbers come out on
//! Windows hosts because the MFT walk should beat per-entry `read_dir`
//! by a wide margin on large trees.
//!
//! On non-Windows hosts the bench still runs — `NtfsWalker` transparently
//! falls back to its Linux/macOS bootstrap walker via the vendored
//! Sourcerer journal subscriber, so the comparison stays meaningful (and
//! the cross-platform CI shape stays parallel).
//!
//! Drive the canonical 1M-file end-to-end harness via
//! `scripts/bench-1m-files.ps1` (Windows) / `scripts/bench-1m-files.sh`
//! (Linux). Those scripts assert NFR-001 cold-scan budgets per release
//! line — this bench is for finer-grained criterion measurements.

use std::fs;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use freallykernel::walker::{FileWalker, NtfsWalker, PosixWalker, WalkEvent, WalkOpts};
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

fn drain<W: FileWalker>(walker: &W, root: &Path) -> usize {
    let rx = walker.walk(root, WalkOpts::default());
    let mut count = 0usize;
    for event in rx.iter() {
        if matches!(event, WalkEvent::File { .. }) {
            count += 1;
        }
    }
    count
}

fn bench_walkers(c: &mut Criterion) {
    let mut group = c.benchmark_group("walker_compare");
    // Keep file counts small here so the bench finishes in seconds on
    // CI; the multi-million end-to-end measurement lives in
    // `scripts/bench-1m-files.ps1`. The shape of the curve is what we're
    // after — NtfsWalker should outpace PosixWalker as the tree grows.
    for &n in &[1_000usize, 10_000, 50_000] {
        let tmp = TempDir::new().unwrap();
        build_tree(tmp.path(), n);

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::new("ntfs_walker", n),
            &tmp.path().to_path_buf(),
            |b, root| {
                let walker = NtfsWalker::new();
                b.iter(|| drain(&walker, root));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("posix_walker", n),
            &tmp.path().to_path_buf(),
            |b, root| {
                let walker = PosixWalker::new();
                b.iter(|| drain(&walker, root));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_walkers);
criterion_main!(benches);
