# Advanced Tips

- Use custom regular expressions in `config.toml` to match proprietary patterns.
- Combine `extract` with other Unix tools for powerful pipelines.
- For performance benchmarking run `cargo bench --bench performance`.

## Custom Configuration

Create `~/.config/extract/config.toml` to tweak behaviour. You can supply your
own regex patterns and adjust logging level. For quick one-off patterns, use
the `--regex` flag on the command line and repeat it for multiple patterns:

```toml
log_level = "debug"
[custom_regexes]
"SERIAL\\d+" = "$0"
```

These patterns match anywhere on a line. Add word boundaries or anchors to
prevent capturing text across multiple tokens.

`log_level` controls verbosity. At `info` level, every match is reported. Use
`debug` for detailed processing steps showing how tokens are parsed and why
rules may not match.

## Benchmarking

Run Criterion benchmarks to gauge performance over time:

```bash
cargo bench --bench performance
```

Benchmarks print throughput statistics that help detect regressions.
