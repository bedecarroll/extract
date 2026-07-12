# Repository Guidance

This repository contains a single-binary Rust CLI located in `src/main.rs`.
Unit and integration tests are defined in that file as well.

When modifying Rust source code in this project:

1. Format the code using **rustfmt** via `cargo fmt --all`.
2. Lint with **clippy** at the pedantic level and deny warnings: `cargo clippy
   -- -D warnings -W clippy::pedantic`.
3. Run the full test suite using `cargo test` (unit and integration tests cover
   many edge cases).
4. Optionally check performance with Criterion benchmarks using `cargo bench
   --bench performance`.
5. Lint all Markdown files using
   [`markdownlint-cli2`](https://github.com/DavidAnson/markdownlint-cli2) with
   `markdownlint-cli2 "**/*.md"`.
6. Write commit messages using the
   [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
   specification.

Ensure all steps succeed before committing changes.
