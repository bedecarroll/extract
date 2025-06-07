use assert_cmd::Command;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_small_input(c: &mut Criterion) {
    let input = "1.2.3.4,5.6.7.8\nEOF\n";
    c.bench_function("extract_small", |b| {
        b.iter(|| {
            let mut cmd = Command::cargo_bin("extract").unwrap();
            cmd.write_stdin(input).assert().success();
        });
    });
}

criterion_group!(benches, bench_small_input);
criterion_main!(benches);
