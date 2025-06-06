# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`extract` is a single-binary Rust CLI tool that extracts network identifiers from text input. The entire application logic is contained in `src/main.rs` as a straightforward command-line utility.

## Core Architecture

The application follows a simple pipeline architecture:
1. **Input processing**: Reads from stdin line by line
2. **Text parsing**: Uses regex patterns to split text on delimiters (`DELIMITERS` static)
3. **Network identifier extraction**: Multi-stage processing through helper functions to handle various formats
4. **Output**: Prints extracted identifiers to stdout

Key extraction functions:
- `ip_finder()` → extracts IP addresses (IPv4/IPv6 with ports, brackets, quotes)
- `cidr_finder()` → extracts CIDR notation (192.168.1.0/24, 2001:db8::/32)
- `mac_finder()` → extracts MAC addresses (colon, dash, Cisco formats)
- `range_finder()` → extracts IP ranges (192.168.1.1-192.168.1.10)
- `strip_quotes()` → removes surrounding quotes
- `remove_port_if_present()` → handles port removal logic (IPv4/IPv6 with different patterns)
- `strip_brackets()` → removes IPv6 brackets
- `is_an_ip()` → validates using `std::net::IpAddr`

The port detection uses `MAX_INT_IN_V6` constant (9999) to differentiate between IPv6 address components and actual port numbers.

## Development Commands

### Build and Test
```bash
# Build release binary
cargo build --release

# Run tests (includes integration tests with assert_cmd)
cargo test

# Run with debug logging
cargo run -- --debug

# Test specific function
cargo test test_ip_finder_basic
```

### Release Process
- Push tags matching `v*` pattern to trigger GitHub Actions release workflow
- Workflow builds cross-platform binaries (Linux, macOS, Windows) with musl variants
- Releases are automatically tagged as "latest" for stable download URLs

## Testing Strategy

Uses `assert_cmd` for integration testing with real CLI invocation. Tests cover:
- Various IP formats (IPv4, IPv6, with/without ports, brackets, quotes)
- CIDR notation extraction and validation
- MAC address formats (colon, dash, Cisco)
- IP range extraction
- Different delimiter types and combinations
- Complex text scenarios with mixed patterns (including comprehensive user complaint blob)
- CLI flags and version commands

Test patterns focus on all extraction functions and include realistic text blob scenarios.