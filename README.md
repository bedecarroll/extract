# extract

![Project Logo](docs/src/logo.png)

A Rust command-line tool for extracting network identifiers from text input.

See the [online documentation](https://bedecarroll.github.io/extract) for
complete usage details.

## Overview

`extract` intelligently parses text to identify and extract network identifiers
including IP addresses, CIDR blocks, MAC addresses, and IP ranges from
unstructured text blobs.

## Features

- **IP Address Extraction**: IPv4 and IPv6 addresses with port handling
- **CIDR Notation**: Network blocks like `192.168.1.0/24`, `2001:db8::/32`
- **MAC Addresses**: All common formats (colon, dash, Cisco)
- **IP Ranges**: Range notation like `192.168.1.1-192.168.1.10`
- **Smart Parsing**: Handles quotes, brackets, and various delimiters
- **Complex Text**: Works with logs, support tickets, and mixed content
- **Configurable Logging**: Info logs list matches.  
  Debug logs show tokenization steps.
- **Streaming Processing**: Lines are processed one by one for low memory usage

## Installation

### Download Pre-built Binary

Download the latest release for your platform:

**Linux (x86_64):**

```bash
curl -L https://github.com/bedecarroll/extract/releases/latest/download/extract-linux-x86_64 -o extract
chmod +x extract
sudo mv extract /usr/local/bin/
```

**Linux (musl):**

```bash
curl -L https://github.com/bedecarroll/extract/releases/latest/download/extract-linux-x86_64-musl -o extract
chmod +x extract
sudo mv extract /usr/local/bin/
```

**macOS (Intel):**

```bash
curl -L https://github.com/bedecarroll/extract/releases/latest/download/extract-macos-x86_64 -o extract
chmod +x extract
sudo mv extract /usr/local/bin/
```

**macOS (Apple Silicon):**

```bash
curl -L https://github.com/bedecarroll/extract/releases/latest/download/extract-macos-aarch64 -o extract
chmod +x extract
sudo mv extract /usr/local/bin/
```

**Windows:**
Download `extract-windows-x86_64.exe` from the [latest
release](https://github.com/bedecarroll/extract/releases/latest) and run
directly.

### Build from Source

```bash
cargo build --release
```

## Usage

### Basic Usage

Read from stdin and extract network identifiers:

```bash
echo "Server at 192.168.1.1 connected to 10.0.0.0/8" | extract
```

Output:

```text
192.168.1.1
10.0.0.0/8
```

### Interactive Mode

Run without arguments to launch your `$EDITOR` for interactive input. If no
editor is found – including when a configured editor is missing – you'll be
prompted to type the text directly:

```bash
extract
```

Enter your text in the editor and save. If using the stdin fallback, end the
input with Ctrl-D or EOF on a new line when finished.

### File Input

Provide one or more file paths to read input directly from those files:

```bash
extract network.log
```

### Command Options

- `--log-level <level>`: Set logging verbosity (error, warn, info, debug)
- `--regex <pattern>`: Apply a one-off regular expression (can be repeated)
- `--version`: Show version information
- `version`: Show version (subcommand)
- `config print`: Show the loaded configuration
- `config ls`: List paths checked for configuration files
- `config generate`: Create a default configuration file

### Configuration

`extract` also reads an optional configuration file from
`$XDG_CONFIG_HOME/extract/config.toml`. On Windows this defaults to
`%APPDATA%\extract\config.toml`, and on Unix-like systems falls back to
`~/.config/extract/config.toml` when `XDG_CONFIG_HOME` is not set. Additional
files in a sibling `conf.d` directory are loaded in alphabetical order. These
can override settings or extend the `custom_regexes` list. The configuration
supports a `log_level` option, an optional `editor` string, and a `custom_regexes`
table mapping regex patterns to replacement strings. Replacements can reference
capture groups using `$1`, `$2`, and so on. If the configured editor cannot be
found, the program falls back to reading from stdin:

```toml
log_level = "warn"
# editor to launch for interactive mode (empty string disables the editor)
editor = "nano"
# editor = ""

[custom_regexes]
# Translate host-based labels into IPs using capture groups
# "host-(\\d{3})-(\\d{3})-(\\d{3})" = "10.$1.$2.$3"

# Capture the entire match using `$0`, useful for custom identifiers
# like Oracle OCI IDs
# "(ocid1\\S+)" = "$0"

# Extract IP:PORT combinations (built-in extractors remove ports)
# "\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+" = "$0"

# Extract IPv6 with ports in custom format
# "\\[([0-9a-fA-F:]+)\\]:(\\d+)" = "$1:$2"
```

See `examples/config.toml` for a complete example.

#### Execution Order

Custom regexes are applied **after** the built-in extractors, which means:

1. **Built-in extractors** run first and apply automatic port removal for IP addresses
2. **Custom regexes** run on the original input text and can capture any
   patterns you define
   (regexes match across whitespace unless you add anchors like `\b`, `^`, or `$`)

This allows you to use custom regexes to extract patterns that the built-in
extractors might modify. For example:

- Built-in: `192.168.1.1:8080` → extracts `192.168.1.1`
- Custom regex: `192.168.1.1:8080` → can extract `192.168.1.1:8080` if desired

Both extractions will appear in the output, giving you flexibility to capture
both cleaned IPs and full IP:PORT combinations.

## Examples

### Complex Network Text

```bash
echo "MAC: 00:11:22:33:44:55 connects to 192.168.1.1:443 via 10.0.0.0/24" | extract
```

Output:

```text
192.168.1.1
10.0.0.0/24
00:11:22:33:44:55
```

### Support Ticket Analysis

```bash
cat support_ticket.txt | extract
```

### Log File Processing

```bash
tail -f /var/log/firewall.log | extract | sort | uniq
```

### Network Documentation

```bash
echo "Scan range 172.16.1.1-172.16.1.254 excluding 172.16.1.0/28" | extract
```

Output:

```text
172.16.1.1-172.16.1.254
172.16.1.0/28
```

## Supported Formats

### IP Addresses

- Plain IPs: `192.168.1.1`, `2001:db8::1`
- With ports: `192.168.1.1:8080`, `[2001:db8::1]:443`
- Quoted: `"192.168.1.1"`, `'192.168.1.1'`
- Prefixed: `src:192.168.1.1`, `dst:10.0.0.1`

### CIDR Blocks

- IPv4: `192.168.1.0/24`, `10.0.0.0/8`
- IPv6: `2001:db8::/32`, `fe80::/10`

### MAC Addresses

- Colon format: `00:11:22:33:44:55`
- Dash format: `00-11-22-33-44-55`
- Cisco format: `0011.2233.4455`

### IP Ranges

- IPv4 ranges: `192.168.1.1-192.168.1.10`
- IPv6 ranges: `2001:db8::1-2001:db8::10`

### Delimiters

- Spaces, commas, pipes, tabs, newlines
- Mixed punctuation and whitespace

## Unix Philosophy Integration

`extract` follows Unix principles - it does one thing well. Combine with
standard tools:

```bash
# Remove duplicates
extract input.txt | sort | uniq

# Filter specific types
extract logs.txt | grep "192.168"

# Count occurrences
extract data.txt | sort | uniq -c | sort -nr

# Save results
extract incident_report.txt > network_assets.txt
```

## Development Guidelines

To maintain a clean code base and catch problems early:

1. Format the code with `cargo fmt --all`.
2. Lint with `cargo clippy -- -D warnings -W clippy::pedantic`.
3. Run the test suite using `cargo test`.
4. Check benchmarks via `cargo bench --bench performance`.

## Testing

Run the comprehensive test suite:

```bash
cargo test
```

Tests include unit tests for each extraction function and integration tests
with realistic text blobs.

## Benchmarking

Criterion benchmarks are included to measure performance. Run:

```bash
cargo bench --bench performance
```

This executes sample benchmarks to evaluate throughput of the CLI.

## Dependencies

- `clap`: Command-line argument parsing
- `regex`: Regular expression support
- `log` & `env_logger`: Logging functionality

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.
