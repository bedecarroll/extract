# ipextract

A Rust command-line tool for extracting IP addresses from text input.

## Overview

`ipextract` intelligently parses text to identify and extract both IPv4 and IPv6 addresses, handling various formats including addresses with ports, brackets, and quotes.

## Features

- Extracts IPv4 and IPv6 addresses from text
- Handles IP addresses with port numbers (e.g., `192.168.1.1:8080`, `[::1]:443`)
- Strips quotes and brackets from IP addresses
- Supports multiple delimiter types (spaces, commas, pipes, tabs, newlines)
- Handles complex text patterns like `src:IP` and `dst:IP`
- Debug logging support

## Installation

### Download Pre-built Binary

Download the latest release for your platform:

**Linux (x86_64):**
```bash
curl -L https://github.com/USERNAME/REPO/releases/latest/download/ipextract-linux-x86_64.tar.gz | tar xz
sudo mv ipextract /usr/local/bin/
```

**Linux (musl):**
```bash
curl -L https://github.com/USERNAME/REPO/releases/latest/download/ipextract-linux-x86_64-musl.tar.gz | tar xz
sudo mv ipextract /usr/local/bin/
```

**macOS (Intel):**
```bash
curl -L https://github.com/USERNAME/REPO/releases/latest/download/ipextract-macos-x86_64.tar.gz | tar xz
sudo mv ipextract /usr/local/bin/
```

**macOS (Apple Silicon):**
```bash
curl -L https://github.com/USERNAME/REPO/releases/latest/download/ipextract-macos-aarch64.tar.gz | tar xz
sudo mv ipextract /usr/local/bin/
```

**Windows:**
Download `ipextract-windows-x86_64.zip` from the [latest release](https://github.com/USERNAME/REPO/releases/latest) and extract it.

### Build from Source

```bash
cargo build --release
```

## Usage

### Basic Usage

Read from stdin and extract IP addresses:

```bash
echo "Server at 192.168.1.1 connected to 10.0.0.1" | ipextract
```

Output:
```
192.168.1.1
10.0.0.1
```

### Interactive Mode

Run without arguments to enter interactive mode:

```bash
ipextract
```

Type your text and end with `EOF` or Ctrl-D.

### Command Options

- `--debug`: Enable debug logging
- `--version`: Show version information
- `version`: Show version (subcommand)

### Examples

Extract IPs from complex text:
```bash
echo "src:192.168.1.1:8080 -> dst:[2001:db8::1]:443" | ipextract
```

Output:
```
192.168.1.1
2001:db8::1
```

Extract from comma-separated values:
```bash
echo "1.1.1.1, 2.2.2.2, 3.3.3.3" | ipextract
```

Output:
```
1.1.1.1
2.2.2.2
3.3.3.3
```

## Supported Formats

- Plain IP addresses: `192.168.1.1`, `2001:db8::1`
- IPs with ports: `192.168.1.1:8080`, `[2001:db8::1]:443`
- Quoted IPs: `"192.168.1.1"`, `'192.168.1.1'`
- Prefixed IPs: `src:192.168.1.1`, `dst:10.0.0.1`
- Mixed delimiters: spaces, commas, pipes, tabs, newlines

## Testing

Run the test suite:

```bash
cargo test
```

## Dependencies

- `clap`: Command-line argument parsing
- `regex`: Regular expression support
- `log` & `env_logger`: Logging functionality

## License

This project uses Cargo's default license configuration.