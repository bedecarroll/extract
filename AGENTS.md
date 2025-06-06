# Repository Guidance

This repository contains a single-binary Rust CLI located in `src/main.rs`.
Unit and integration tests are defined in that file as well.

When modifying Rust source code in this project:

1. Format the code with `cargo fmt --all`.
2. Run the full test suite using `cargo test`.
3. Write commit messages using the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

Ensure all steps succeed before committing changes.
