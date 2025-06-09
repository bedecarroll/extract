# Advanced Tips

- Use custom regular expressions in `config.toml` to match proprietary patterns.
- Combine `extract` with other Unix tools for powerful pipelines.
- For performance benchmarking run `cargo bench --bench performance`.

## Custom Configuration

Create `~/.config/extract/config.toml` to tweak behaviour. You can supply your
own regex patterns and adjust logging level:

```toml
log_level = "debug"
custom_regexes = { serial = "SERIAL\\d+" }
```

## Benchmarking

Run Criterion benchmarks to gauge performance over time:

```bash
cargo bench --bench performance
```

Benchmarks print throughput statistics that help detect regressions.
