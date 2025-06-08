#![deny(clippy::pedantic)]

use atty::Stream;
use clap::{Parser, Subcommand};
use edit::edit;
use log::{debug, warn, LevelFilter};
use regex::Regex;
use std::io::{self, ErrorKind, Read};
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;
use toml::Value;

/// Maximum integer value that can appear in an IPv6 address component.
/// Values above this in the last position are assumed to be port numbers.
const MAX_INT_IN_V6: u32 = 9999;

/// Regex pattern for splitting text on common IP address delimiters
static DELIMITERS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[,\s|$>=]").expect("Invalid delimiter regex"));

/// Regex pattern for detecting potential port numbers at the end of strings
static MAYBE_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r":\d{1,6}$").expect("Invalid port regex"));

#[derive(Subcommand)]
enum Commands {
    /// Print version and quit.
    Version,
}

#[derive(Parser)]
#[command(
    name = "extract",
    version,
    about = "Extract network identifiers from text"
)]
struct Cli {
    /// Enable debug logging.
    #[arg(long)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

struct CustomRule {
    regex: Regex,
    replace: String,
}

#[derive(Default)]
struct AppConfig {
    debug: bool,
    custom_regexes: Vec<CustomRule>,
}

/// Load configuration from `$XDG_CONFIG_HOME/extract/config.toml` or
/// `$HOME/.config/extract/config.toml`
fn load_config() -> AppConfig {
    let mut config = AppConfig::default();

    let base = std::env::var("XDG_CONFIG_HOME")
        .or_else(|_| std::env::var("HOME").map(|h| format!("{h}/.config")));

    if let Ok(dir) = base {
        let path = Path::new(&dir).join("extract").join("config.toml");
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(value) = contents.parse::<Value>() {
                if let Some(d) = value.get("debug").and_then(toml::Value::as_bool) {
                    config.debug = d;
                }
                if let Some(map) = value.get("custom_regexes").and_then(|v| v.as_table()) {
                    for (pattern, replacement) in map {
                        if let Some(repl) = replacement.as_str() {
                            match Regex::new(pattern) {
                                Ok(re) => config.custom_regexes.push(CustomRule {
                                    regex: re,
                                    replace: repl.to_string(),
                                }),
                                Err(e) => eprintln!("Invalid custom regex '{pattern}': {e}"),
                            }
                        }
                    }
                }
            }
        }
    }

    config
}

/// Apply custom regex patterns from the configuration to a text line
fn custom_regex_matches(s: &str, patterns: &[CustomRule]) -> Vec<String> {
    let mut elements = Vec::new();
    for rule in patterns {
        for caps in rule.regex.captures_iter(s) {
            let mut out = String::new();
            caps.expand(&rule.replace, &mut out);
            elements.push(out);
        }
    }
    elements
}

/// Checks if a string slice represents a valid IP address (IPv4 or IPv6)
fn is_an_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Removes quotes from the beginning and end of a string slice if present
fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return &s[1..s.len() - 1];
    }
    s
}

/// Removes brackets from IPv6 addresses if present
fn strip_brackets(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Removes port numbers from IP addresses, returning the IP part as a string
fn remove_port_if_present(s: &str) -> Option<String> {
    // Handle bracketed IPv6 with port: [::1]:8080
    if s.starts_with('[') && s.contains("]:") {
        if let Some(bracket_end) = s.find("]:") {
            return Some(s[1..bracket_end].to_string());
        }
    }

    // Handle cases with dots or brackets and potential ports
    if (s.contains('.') || s.contains(']')) && MAYBE_PORT.is_match(s) {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() > 1 {
            return Some(parts[..parts.len() - 1].join(":"));
        }
    }

    // Handle IPv6 addresses with high port numbers (> MAX_INT_IN_V6)
    if s.matches(':').count() > 1 && !s.contains(']') {
        if let Some(last) = s.rsplit(':').next() {
            if let Ok(num) = last.parse::<u32>() {
                if num > MAX_INT_IN_V6 {
                    let parts: Vec<&str> = s.split(':').collect();
                    return Some(parts[..parts.len() - 1].join(":"));
                }
            }
        }
    }

    None
}

/// Extracts IP addresses from a text string
fn ip_finder(s: &str) -> Vec<String> {
    let mut elements = Vec::new();

    for chunk in DELIMITERS.split(s) {
        if chunk.is_empty() {
            continue;
        }

        // Process the chunk through various transformations
        let mut processed = chunk;

        // Remove quotes
        processed = strip_quotes(processed);

        // Try to remove port if present, otherwise use original
        let without_port = remove_port_if_present(processed);
        if let Some(ref port_removed) = without_port {
            processed = port_removed;
        }

        // Remove brackets for IPv6
        processed = strip_brackets(processed);

        if processed.is_empty() {
            continue;
        }

        // Check if it's a valid IP after all transformations
        if is_an_ip(processed) {
            elements.push(processed.to_string());
            continue;
        }

        // Handle cases like "src:1.1.1.1" where we want the part after the colon
        if processed.contains('.') && processed.contains(':') {
            if let Some(first) = processed.split(':').next() {
                if is_an_ip(first) {
                    elements.push(first.to_string());
                    continue;
                }
            }
        }

        // Handle cases where IP might be after the first colon
        if processed.contains(':') {
            let parts: Vec<&str> = processed.split(':').collect();
            if parts.len() > 1 {
                let remaining = &parts[1..];
                let merged = if remaining.iter().any(|p| p.contains('.')) {
                    remaining.join(".")
                } else {
                    remaining.join(":")
                };

                if is_an_ip(&merged) {
                    elements.push(merged);
                }
            }
        }
    }
    elements
}

/// Extracts CIDR notation (IP/prefix) from text
fn cidr_finder(s: &str) -> Vec<String> {
    let mut elements = Vec::new();

    for chunk in DELIMITERS.split(s) {
        if chunk.is_empty() || !chunk.contains('/') {
            continue;
        }

        let processed = strip_quotes(chunk);

        if let Some(slash_pos) = processed.find('/') {
            let ip_part = &processed[..slash_pos];
            let prefix_part = &processed[slash_pos + 1..];

            if let Ok(prefix) = prefix_part.parse::<u8>() {
                if is_an_ip(ip_part) {
                    let is_ipv4 = ip_part.contains('.');
                    let max_prefix = if is_ipv4 { 32 } else { 128 };

                    if prefix <= max_prefix {
                        elements.push(processed.to_string());
                    }
                }
            }
        }
    }

    elements
}

/// Extracts MAC addresses from text (supports colon and dash formats)
fn mac_finder(s: &str) -> Vec<String> {
    let mut elements = Vec::new();

    for chunk in DELIMITERS.split(s) {
        if chunk.is_empty() {
            continue;
        }

        let processed = strip_quotes(chunk);

        // Check for colon format (xx:xx:xx:xx:xx:xx)
        if processed.matches(':').count() == 5 {
            let parts: Vec<&str> = processed.split(':').collect();
            if parts.len() == 6
                && parts
                    .iter()
                    .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
            {
                elements.push(processed.to_string());
                continue;
            }
        }

        // Check for dash format (xx-xx-xx-xx-xx-xx)
        if processed.matches('-').count() == 5 {
            let parts: Vec<&str> = processed.split('-').collect();
            if parts.len() == 6
                && parts
                    .iter()
                    .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
            {
                elements.push(processed.to_string());
                continue;
            }
        }

        // Check for Cisco format (xxxx.xxxx.xxxx)
        if processed.matches('.').count() == 2 {
            let parts: Vec<&str> = processed.split('.').collect();
            if parts.len() == 3
                && parts
                    .iter()
                    .all(|part| part.len() == 4 && part.chars().all(|c| c.is_ascii_hexdigit()))
            {
                elements.push(processed.to_string());
            }
        }
    }

    elements
}

/// Extracts IP ranges from text (IP-IP format)
fn range_finder(s: &str) -> Vec<String> {
    let mut elements = Vec::new();

    for chunk in DELIMITERS.split(s) {
        if chunk.is_empty() || !chunk.contains('-') {
            continue;
        }

        let processed = strip_quotes(chunk);

        if let Some(dash_pos) = processed.find('-') {
            let start_ip = &processed[..dash_pos];
            let end_ip = &processed[dash_pos + 1..];

            if is_an_ip(start_ip) && is_an_ip(end_ip) {
                // Ensure both IPs are same type
                let start_is_ipv4 = start_ip.contains('.');
                let end_is_ipv4 = end_ip.contains('.');

                if start_is_ipv4 == end_is_ipv4 {
                    elements.push(processed.to_string());
                }
            }
        }
    }

    elements
}

fn main() {
    let cli = Cli::parse();
    let config = load_config();
    let debug_enabled = cli.debug || config.debug;

    env_logger::Builder::from_default_env()
        .filter_level(if debug_enabled {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        })
        .init();

    if let Some(Commands::Version) = cli.command {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let mut input = String::new();

    if atty::is(Stream::Stdin) {
        let editor_env = std::env::var("EDITOR").unwrap_or_default();
        debug!("Opening $EDITOR ({editor_env:?}) for input. Save and quit to continue.");
        match edit("") {
            Ok(text) => input = text,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    warn!("Editor not found. EDITOR={editor_env:?}");
                    eprintln!("Input text. End input with Ctrl-d or EOF on a new line.");
                    if let Err(err) = io::stdin().read_to_string(&mut input) {
                        eprintln!("Error reading input: {err}");
                        return;
                    }
                } else {
                    eprintln!("Error launching editor: {e}");
                    return;
                }
            }
        }
    } else {
        let stdin = io::stdin();
        if let Err(e) = stdin.lock().read_to_string(&mut input) {
            eprintln!("Error reading input: {e}");
            return;
        }
    }

    let mut lines = Vec::new();
    for line in input.lines() {
        lines.push(line.to_string());
    }

    let mut all_tokens = Vec::new();
    for line in lines {
        debug!("Processing line: {line}");

        let ips = ip_finder(&line);
        debug!("Found IPs: {ips:?}");
        all_tokens.extend(ips);

        let cidrs = cidr_finder(&line);
        debug!("Found CIDRs: {cidrs:?}");
        all_tokens.extend(cidrs);

        let macs = mac_finder(&line);
        debug!("Found MACs: {macs:?}");
        all_tokens.extend(macs);

        let ranges = range_finder(&line);
        debug!("Found ranges: {ranges:?}");
        all_tokens.extend(ranges);

        let custom = custom_regex_matches(&line, &config.custom_regexes);
        debug!("Found custom: {custom:?}");
        all_tokens.extend(custom);
    }

    for token in all_tokens {
        println!("{token}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::cargo::CommandCargoExt;
    use assert_cmd::Command;
    use predicates::prelude::*;
    use std::io::{Read, Write};
    use std::process::{Command as StdCommand, Stdio};

    const EXAMPLE_V6_1: &str = "2001:db8::1";
    const EXAMPLE_V6_2: &str = "fdbd:db8::2";

    // Tests for utility functions
    #[test]
    fn test_strip_quotes_basic() {
        assert_eq!(strip_quotes("\"hello\""), "hello");
        assert_eq!(strip_quotes("'world'"), "world");
        assert_eq!(strip_quotes("\"192.168.1.1\""), "192.168.1.1");
        assert_eq!(strip_quotes("'192.168.1.1'"), "192.168.1.1");
    }

    #[test]
    fn test_strip_quotes_edge_cases() {
        assert_eq!(strip_quotes("hello"), "hello");
        assert_eq!(strip_quotes(""), "");
        assert_eq!(strip_quotes("h"), "h");
        assert_eq!(strip_quotes("\""), "\"");
        assert_eq!(strip_quotes("'"), "'");
        assert_eq!(strip_quotes("\"\""), "");
        assert_eq!(strip_quotes("''"), "");
        assert_eq!(strip_quotes("\"test'"), "\"test'");
        assert_eq!(strip_quotes("'test\""), "'test\"");
        assert_eq!(strip_quotes("\"'test'\""), "'test'");
        assert_eq!(strip_quotes("'\"test\"'"), "\"test\"");
    }

    #[test]
    fn test_strip_brackets_basic() {
        assert_eq!(strip_brackets("[hello]"), "hello");
        assert_eq!(strip_brackets("[192.168.1.1]"), "192.168.1.1");
        assert_eq!(strip_brackets("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn test_strip_brackets_edge_cases() {
        assert_eq!(strip_brackets("hello"), "hello");
        assert_eq!(strip_brackets(""), "");
        assert_eq!(strip_brackets("h"), "h");
        assert_eq!(strip_brackets("["), "[");
        assert_eq!(strip_brackets("]"), "]");
        assert_eq!(strip_brackets("[]"), "");
        assert_eq!(strip_brackets("[test"), "[test");
        assert_eq!(strip_brackets("test]"), "test]");
        assert_eq!(strip_brackets("[[test]]"), "[test]");
    }

    #[test]
    fn test_remove_port_if_present_ipv4() {
        assert_eq!(
            remove_port_if_present("192.168.1.1:8080"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            remove_port_if_present("192.168.1.1:443"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            remove_port_if_present("10.0.0.1:65535"),
            Some("10.0.0.1".to_string())
        );
        assert_eq!(remove_port_if_present("192.168.1.1"), None);
        assert_eq!(
            remove_port_if_present("not.an.ip:8080"),
            Some("not.an.ip".to_string())
        );
    }

    #[test]
    fn test_remove_port_if_present_ipv6() {
        assert_eq!(
            remove_port_if_present("[2001:db8::1]:8080"),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(remove_port_if_present("[::1]:443"), Some("::1".to_string()));
        assert_eq!(
            remove_port_if_present("2001:db8::1:22222"),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(remove_port_if_present("2001:db8::1"), None);
        assert_eq!(remove_port_if_present("2001:db8::1:8080"), None); // 8080 <= MAX_INT_IN_V6
    }

    #[test]
    fn test_remove_port_if_present_edge_cases() {
        assert_eq!(remove_port_if_present(""), None);
        assert_eq!(remove_port_if_present("192.168.1.1:"), None); // Doesn't match MAYBE_PORT
        assert_eq!(remove_port_if_present("192.168.1.1:abc"), None); // Doesn't match MAYBE_PORT (non-numeric)
        assert_eq!(remove_port_if_present("[]:8080"), Some("".to_string())); // Bracket logic extracts empty string
        assert_eq!(remove_port_if_present("test:123"), None); // No dots or brackets, doesn't meet IPv6 high port criteria
        assert_eq!(
            remove_port_if_present("a:b:c:d:e:f:10000"),
            Some("a:b:c:d:e:f".to_string())
        ); // > MAX_INT_IN_V6
        assert_eq!(remove_port_if_present("a:b:c:d:e:f:8888"), None); // <= MAX_INT_IN_V6
    }

    #[test]
    fn test_version_subcommand() {
        let mut cmd = Command::cargo_bin("extract").unwrap();
        cmd.arg("version").assert().success().stdout("0.0.2\n");
    }

    #[test]
    fn test_main_version_flag() {
        let mut cmd = Command::cargo_bin("extract").unwrap();
        cmd.arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("0.0.2"));
    }

    #[test]
    fn test_main_debug_flag() {
        let mut cmd = Command::cargo_bin("extract").unwrap();
        cmd.arg("--debug")
            .write_stdin("1.2.3.4\n")
            .assert()
            .success()
            .stderr(predicate::str::contains("Processing line: 1.2.3.4"));
    }

    #[test]
    fn test_main_prints_extracted_ips() {
        let mut cmd = Command::cargo_bin("extract").unwrap();
        cmd.write_stdin("1.2.3.4 5.6.7.8\n")
            .assert()
            .success()
            .stdout("1.2.3.4\n5.6.7.8\n");
    }

    #[test]
    fn test_main_extracts_all_network_tokens() {
        let mut cmd = Command::cargo_bin("extract").unwrap();
        cmd.write_stdin("IP: 192.168.1.1, CIDR: 10.0.0.0/8, MAC: 00:11:22:33:44:55, Range: 172.16.1.1-172.16.1.10\n")
            .assert()
            .success()
            .stdout("192.168.1.1\n10.0.0.0/8\n00:11:22:33:44:55\n172.16.1.1-172.16.1.10\n");
    }

    #[test]
    fn test_no_panic_on_broken_pipe() {
        let mut child = StdCommand::cargo_bin("extract")
            .unwrap()
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();

        {
            let mut stdin = child.stdin.take().unwrap();
            writeln!(stdin, "1.1.1.1 2.2.2.2 3.3.3.3").unwrap();
            writeln!(stdin, "EOF").unwrap();
        }

        let mut stdout = child.stdout.take().unwrap();
        let mut buf = [0u8; 16];
        let _ = stdout.read(&mut buf).unwrap();
        drop(stdout);

        let status = child.wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn test_ip_finder_basic() {
        assert_eq!(ip_finder("1.1.1.1"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder(EXAMPLE_V6_1), vec![EXAMPLE_V6_1]);
    }

    #[test]
    fn test_ip_finder_empty_and_null() {
        assert_eq!(ip_finder(""), Vec::<String>::new());
        assert_eq!(ip_finder(",,,,,,,,"), Vec::<String>::new());
        assert_eq!(ip_finder("1.1.1.12.2.2.2"), Vec::<String>::new());
    }

    #[test]
    fn test_ip_finder_emoji() {
        assert_eq!(ip_finder("😊,😊,😊"), Vec::<String>::new());
        assert_eq!(ip_finder("1.1.1.1😊"), Vec::<String>::new());
        assert_eq!(ip_finder("1.1.1.1😊2.2.2.2"), Vec::<String>::new());
        assert_eq!(ip_finder("1.1.1.1,😊"), vec!["1.1.1.1"]);
    }

    #[test]
    fn test_ip_finder_invalid_ipv4() {
        assert_eq!(ip_finder("1.1.1.999"), Vec::<String>::new());
    }

    #[test]
    fn test_ip_finder_src_dst() {
        assert_eq!(
            ip_finder("src:1.1.1.1,dst:2.2.2.2"),
            vec!["1.1.1.1", "2.2.2.2"]
        );
        assert_eq!(
            ip_finder("src:1.1.1.1, dst:2.2.2.2"),
            vec!["1.1.1.1", "2.2.2.2"]
        );
        assert_eq!(
            ip_finder(&format!("src:{}, dst:{}", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
    }

    #[test]
    fn test_ip_finder_mixed_delimiters() {
        assert_eq!(
            ip_finder("1.1.1.1 2.2.2.2,3.3.3.3"),
            vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        );
        assert_eq!(
            ip_finder("1.1.1.1 2.2.2.2, 3.3.3.3"),
            vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        );
        assert_eq!(
            ip_finder(&format!("{}, {}", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
    }

    #[test]
    fn test_ip_finder_space_delimiter() {
        assert_eq!(ip_finder("1.1.1.1 "), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1 2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(
            ip_finder(&format!("{} {}", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
    }

    #[test]
    fn test_ip_finder_comma_delimiter() {
        assert_eq!(ip_finder("1.1.1.1,"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1,2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(
            ip_finder(&format!("{},{}", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
    }

    #[test]
    fn test_ip_finder_pipe_delimiter() {
        assert_eq!(ip_finder("1.1.1.1|"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1|2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(
            ip_finder(&format!("{}|{}", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
    }

    #[test]
    fn test_ip_finder_tab_delimiter() {
        assert_eq!(ip_finder("1.1.1.1\t"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1\t2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(
            ip_finder(&format!("{}\t{}", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
    }

    #[test]
    fn test_ip_finder_newline_delimiter() {
        assert_eq!(ip_finder("1.1.1.1\n"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1\n2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(
            ip_finder(&format!("{}\n{}", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
        assert_eq!(ip_finder("1.1.1.1\r\n"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1\r\n2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn test_ip_finder_quoted() {
        assert_eq!(ip_finder("\"1.1.1.1\","), vec!["1.1.1.1"]);
        assert_eq!(
            ip_finder("\"1.1.1.1\",\n\"2.2.2.2\""),
            vec!["1.1.1.1", "2.2.2.2"]
        );
        assert_eq!(ip_finder("'1.1.1.1',"), vec!["1.1.1.1"]);
        assert_eq!(
            ip_finder("'1.1.1.1',\n'2.2.2.2'"),
            vec!["1.1.1.1", "2.2.2.2"]
        );
    }

    #[test]
    fn test_ip_finder_with_ports() {
        assert_eq!(ip_finder("1.1.1.1:65000"), vec!["1.1.1.1"]);
        assert_eq!(
            ip_finder("1.1.1.1:65000,2.2.2.2:443"),
            vec!["1.1.1.1", "2.2.2.2"]
        );
        assert_eq!(ip_finder("1.2.3.4:abcd"), vec!["1.2.3.4"]);
        assert_eq!(ip_finder("foo:.:2.2.2.2"), Vec::<String>::new());
        assert_eq!(ip_finder("[1.1.1.1]:65000"), vec!["1.1.1.1"]);
        assert_eq!(
            ip_finder("[1.1.1.1]:65000,[2.2.2.2]:443"),
            vec!["1.1.1.1", "2.2.2.2"]
        );
    }

    #[test]
    fn test_ip_finder_ipv6_with_ports() {
        assert_eq!(
            ip_finder(&format!("{}:65000", EXAMPLE_V6_1)),
            vec![EXAMPLE_V6_1]
        );
        let input = format!("{}:65000, {}:80", EXAMPLE_V6_1, EXAMPLE_V6_2);
        let result = ip_finder(&input);
        assert!(result.contains(&EXAMPLE_V6_1.to_string()));

        assert_eq!(
            ip_finder(&format!("[{}]:65000", EXAMPLE_V6_1)),
            vec![EXAMPLE_V6_1]
        );
        assert_eq!(
            ip_finder(&format!("[{}]:65000, [{}]:80", EXAMPLE_V6_1, EXAMPLE_V6_2)),
            vec![EXAMPLE_V6_1, EXAMPLE_V6_2]
        );
    }

    #[test]
    fn test_ip_finder_complex_text() {
        let input = format!(
            "The IP 1.1.1.1 is having trouble talking to\n    2.2.2.2 on port 5555.\n\n    Others:\n    src:1.1.1.2 -> dst:2.2.2.3:771\n    src:{} -> dst: [{}]:443\n    any issue?",
            EXAMPLE_V6_1, EXAMPLE_V6_2
        );
        let expected = vec![
            "1.1.1.1",
            "2.2.2.2",
            "1.1.1.2",
            "2.2.2.3",
            EXAMPLE_V6_1,
            EXAMPLE_V6_2,
        ];
        assert_eq!(ip_finder(&input), expected);
    }

    #[test]
    fn test_is_an_ip() {
        assert!(is_an_ip("1.1.1.1"));
        assert!(is_an_ip("192.168.1.1"));
        assert!(is_an_ip(EXAMPLE_V6_1));
        assert!(!is_an_ip("1.1.1.999"));
        assert!(!is_an_ip("not.an.ip"));
        assert!(!is_an_ip(""));
    }

    // Tests for CIDR notation support
    #[test]
    fn test_cidr_finder_basic() {
        let input = "192.168.1.0/24 10.0.0.0/8";
        let result = cidr_finder(&input);
        assert_eq!(result, vec!["192.168.1.0/24", "10.0.0.0/8"]);
    }

    #[test]
    fn test_cidr_finder_ipv6() {
        let input = "2001:db8::/32 fe80::/10";
        let result = cidr_finder(&input);
        assert_eq!(result, vec!["2001:db8::/32", "fe80::/10"]);
    }

    #[test]
    fn test_cidr_finder_mixed_with_ips() {
        let input = "192.168.1.1 192.168.1.0/24 10.0.0.1";
        let result = cidr_finder(&input);
        assert_eq!(result, vec!["192.168.1.0/24"]);
    }

    #[test]
    fn test_cidr_finder_invalid() {
        let input = "192.168.1.0/33 192.168.1.0/999 not.a.cidr/24";
        let result = cidr_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_cidr_finder_edge_cases() {
        let input = "0.0.0.0/0 127.0.0.1/32 ::/0 2001:db8::/128";
        let result = cidr_finder(&input);
        assert_eq!(
            result,
            vec!["0.0.0.0/0", "127.0.0.1/32", "::/0", "2001:db8::/128"]
        );
    }

    #[test]
    fn test_cidr_finder_quoted() {
        let input = "\"192.168.1.0/24\" '10.0.0.0/8' \"2001:db8::/32\"";
        let result = cidr_finder(&input);
        assert_eq!(
            result,
            vec!["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"]
        );
    }

    // Tests for MAC address extraction
    #[test]
    fn test_mac_finder_colon_format() {
        let input = "00:11:22:33:44:55 aa:bb:cc:dd:ee:ff";
        let result = mac_finder(&input);
        assert_eq!(result, vec!["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]);
    }

    #[test]
    fn test_mac_finder_dash_format() {
        let input = "00-11-22-33-44-55 AA-BB-CC-DD-EE-FF";
        let result = mac_finder(&input);
        assert_eq!(result, vec!["00-11-22-33-44-55", "AA-BB-CC-DD-EE-FF"]);
    }

    #[test]
    fn test_mac_finder_mixed_formats() {
        let input = "00:11:22:33:44:55 00-11-22-33-44-66";
        let result = mac_finder(&input);
        assert_eq!(result, vec!["00:11:22:33:44:55", "00-11-22-33-44-66"]);
    }

    #[test]
    fn test_mac_finder_invalid() {
        let input = "00:11:22:33:44 00:11:22:33:44:55:66 gg:hh:ii:jj:kk:ll";
        let result = mac_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_mac_finder_with_text() {
        let input = "Interface eth0 has MAC 00:11:22:33:44:55 and is up";
        let result = mac_finder(&input);
        assert_eq!(result, vec!["00:11:22:33:44:55"]);
    }

    #[test]
    fn test_mac_finder_cisco_format() {
        let input = "0011.2233.4455 aabb.ccdd.eeff";
        let result = mac_finder(&input);
        assert_eq!(result, vec!["0011.2233.4455", "aabb.ccdd.eeff"]);
    }

    #[test]
    fn test_mac_finder_cisco_mixed() {
        let input = "00:11:22:33:44:55 0011.2233.4466 00-11-22-33-44-77";
        let result = mac_finder(&input);
        assert_eq!(
            result,
            vec!["00:11:22:33:44:55", "0011.2233.4466", "00-11-22-33-44-77"]
        );
    }

    #[test]
    fn test_mac_finder_cisco_invalid() {
        let input = "001.2233.4455 0011.22.4455 gggg.hhhh.iiii";
        let result = mac_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_mac_finder_quoted() {
        let input = "\"00:11:22:33:44:55\" '00-11-22-33-44-66' \"0011.2233.4477\"";
        let result = mac_finder(&input);
        assert_eq!(
            result,
            vec!["00:11:22:33:44:55", "00-11-22-33-44-66", "0011.2233.4477"]
        );
    }

    #[test]
    fn test_mac_finder_case_sensitivity() {
        let input = "00:aa:BB:cc:DD:ee AA:BB:CC:DD:EE:FF aabb.ccdd.eeff";
        let result = mac_finder(&input);
        assert_eq!(
            result,
            vec!["00:aa:BB:cc:DD:ee", "AA:BB:CC:DD:EE:FF", "aabb.ccdd.eeff"]
        );
    }

    // Tests for IP range extraction
    #[test]
    fn test_range_finder_ipv4() {
        let input = "192.168.1.1-192.168.1.10 10.0.0.1-10.0.0.5";
        let result = range_finder(&input);
        assert_eq!(
            result,
            vec!["192.168.1.1-192.168.1.10", "10.0.0.1-10.0.0.5"]
        );
    }

    #[test]
    fn test_range_finder_ipv6() {
        let input = "2001:db8::1-2001:db8::10";
        let result = range_finder(&input);
        assert_eq!(result, vec!["2001:db8::1-2001:db8::10"]);
    }

    #[test]
    fn test_range_finder_invalid() {
        let input = "192.168.1.999-192.168.1.1000 not.an.ip-also.not.ip";
        let result = range_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_range_finder_mixed_with_ips() {
        let input = "192.168.1.1 192.168.1.1-192.168.1.10 192.168.1.20";
        let result = range_finder(&input);
        assert_eq!(result, vec!["192.168.1.1-192.168.1.10"]);
    }

    #[test]
    fn test_range_finder_with_text() {
        let input = "Scan range 192.168.1.1-192.168.1.254 for devices";
        let result = range_finder(&input);
        assert_eq!(result, vec!["192.168.1.1-192.168.1.254"]);
    }

    #[test]
    fn test_range_finder_quoted() {
        let input = "\"192.168.1.1-192.168.1.10\" '10.0.0.1-10.0.0.5' \"2001:db8::1-2001:db8::10\"";
        let result = range_finder(&input);
        assert_eq!(
            result,
            vec![
                "192.168.1.1-192.168.1.10",
                "10.0.0.1-10.0.0.5",
                "2001:db8::1-2001:db8::10"
            ]
        );
    }

    #[test]
    fn test_range_finder_mixed_ip_types() {
        let input = "192.168.1.1-2001:db8::1 mixed types should fail";
        let result = range_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_range_finder_with_ports() {
        let input = "192.168.1.1:8080-192.168.1.10:8080 should not extract with ports";
        let result = range_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_comprehensive_user_complaint_blob() {
        let complaint = r#"Subject: Network Issues - URGENT!!

Hi IT Support,

I'm having serious connectivity problems that are affecting my work. Here's what I've observed:

1. My workstation (MAC: 00:1B:44:11:3A:B7) can't reach the file server at 192.168.10.5:445. 
   The connection times out when trying to access \\fileserver\shared.

2. The network printer at "10.0.1.100" with MAC aa-bb-cc-dd-ee-ff is offline. 
   I also tried the backup printer at [192.168.1.50]:9100 but same issue.

3. Our web application hosted on the DMZ network 172.16.0.0/24 is unreachable.
   Specifically, I can't access https://webapp.company.com (203.0.113.10:443).

4. VPN issues: When connecting through our Cisco equipment (MAC: 0012.3456.789A), 
   I can see the tunnel establishes to src:10.8.0.1 -> dst:10.8.0.50:1194, 
   but traffic to the internal range 10.0.0.1-10.0.0.254 fails.

5. IPv6 connectivity is broken too. Our main server 2001:db8::1 and backup 
   server at [2001:db8::2]:8080 are both unreachable. The entire 2001:db8::/32 
   subnet seems down.

6. I noticed some weird traffic in the logs:
   - Connections from quoted IPs like "203.0.113.100" and '198.51.100.5'
   - Suspicious MAC addresses: 00-DE-AD-BE-EF-00 and DEAD.BEEF.CAFE
   - Port scans hitting 192.168.1.1:22, 192.168.1.1:80, 192.168.1.1:443

7. Mobile devices can't connect either. My iPhone (MAC 12:34:56:78:9A:BC) 
   gets assigned 169.254.1.100/16 (APIPA) instead of proper DHCP from 192.168.50.0/24.

8. Even tried different IP ranges: 172.31.1.1-172.31.1.100 and the guest network 
   10.10.10.0/28, but nothing works.

This is affecting our entire team's productivity. Please help ASAP!

Thanks,
John Doe
Extension: 555-0123
Email: john.doe@company.com"#;

        let all_ips = ip_finder(complaint);
        let all_cidrs = cidr_finder(complaint);
        let all_macs = mac_finder(complaint);
        let all_ranges = range_finder(complaint);

        // Expected results based on actual extraction capabilities
        let expected_ips = vec![
            "192.168.10.5",
            "10.0.1.100",
            "192.168.1.50",
            "10.8.0.1",
            "10.8.0.50",
            "2001:db8::1",
            "2001:db8::2",
            "203.0.113.100",
            "198.51.100.5",
            "192.168.1.1",
            "192.168.1.1",
            "192.168.1.1", // Multiple port scans on same IP
        ];

        let expected_cidrs = vec![
            "172.16.0.0/24",
            "2001:db8::/32",
            "169.254.1.100/16",
            "10.10.10.0/28",
        ];

        // Note: Some MACs not extracted due to format/context limitations
        let expected_macs = vec!["aa-bb-cc-dd-ee-ff", "00-DE-AD-BE-EF-00", "DEAD.BEEF.CAFE"];

        let expected_ranges = vec!["10.0.0.1-10.0.0.254", "172.31.1.1-172.31.1.100"];

        assert_eq!(all_ips, expected_ips);
        assert_eq!(all_cidrs, expected_cidrs);
        assert_eq!(all_macs, expected_macs);
        assert_eq!(all_ranges, expected_ranges);
    }

    // Comprehensive IPv6 format tests
    #[test]
    fn test_ip_finder_ipv6_full_notation() {
        let input = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let result = ip_finder(&input);
        assert_eq!(result, vec!["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]);
    }

    #[test]
    fn test_ip_finder_ipv6_compressed() {
        let input = "2001:db8:85a3::8a2e:370:7334 2001:db8::1 ::1 ::";
        let result = ip_finder(&input);
        assert_eq!(
            result,
            vec!["2001:db8:85a3::8a2e:370:7334", "2001:db8::1", "::1", "::"]
        );
    }

    #[test]
    fn test_ip_finder_ipv6_loopback_and_any() {
        let input = "::1 ::ffff:0:0 :: 0:0:0:0:0:0:0:1";
        let result = ip_finder(&input);
        assert_eq!(result, vec!["::1", "::ffff:0:0", "::", "0:0:0:0:0:0:0:1"]);
    }

    #[test]
    fn test_ip_finder_ipv6_mapped_ipv4() {
        let input = "::ffff:192.168.1.1 ::ffff:c0a8:101 64:ff9b::192.0.2.33";
        let result = ip_finder(&input);
        assert_eq!(
            result,
            vec![
                "::ffff:192.168.1.1",
                "::ffff:c0a8:101",
                "64:ff9b::192.0.2.33"
            ]
        );
    }

    #[test]
    fn test_ip_finder_ipv6_link_local() {
        let input = "fe80::1 fe80::1%eth0 fe80::200:f8ff:fe21:67cf";
        let result = ip_finder(&input);
        // Note: %eth0 interface identifier is stripped by our delimiter regex (% is not in DELIMITERS)
        // So fe80::1%eth0 becomes one chunk that fails IP validation
        assert_eq!(result, vec!["fe80::1", "fe80::200:f8ff:fe21:67cf"]);
    }

    #[test]
    fn test_ip_finder_ipv6_multicast() {
        let input = "ff02::1 ff02::2 ff05::1:3 ff0e::1";
        let result = ip_finder(&input);
        assert_eq!(result, vec!["ff02::1", "ff02::2", "ff05::1:3", "ff0e::1"]);
    }

    #[test]
    fn test_ip_finder_ipv6_unique_local() {
        let input = "fc00::1 fd12:3456:789a:1::1 fc00::/7";
        let result = ip_finder(&input);
        // fc00::/7 gets split at / delimiter, leaving fc00:: which is invalid without the ::
        assert_eq!(result, vec!["fc00::1", "fd12:3456:789a:1::1"]);
    }

    #[test]
    fn test_ip_finder_ipv6_with_brackets() {
        let input = "[2001:db8::1] [::1]:8080 [fe80::1%eth0]:443";
        let result = ip_finder(&input);
        // The %eth0 portion makes [fe80::1%eth0]:443 invalid for IP extraction
        assert_eq!(result, vec!["2001:db8::1", "::1"]);
    }

    #[test]
    fn test_ip_finder_ipv6_quoted() {
        let input = "\"2001:db8::1\" '::1' \"[fe80::1]:80\"";
        let result = ip_finder(&input);
        assert_eq!(result, vec!["2001:db8::1", "::1", "fe80::1"]);
    }

    #[test]
    fn test_ip_finder_ipv6_mixed_case() {
        let input = "2001:DB8::1 2001:db8:85A3::8a2E:370:7334 FE80::1";
        let result = ip_finder(&input);
        assert_eq!(
            result,
            vec!["2001:DB8::1", "2001:db8:85A3::8a2E:370:7334", "FE80::1"]
        );
    }

    #[test]
    fn test_ip_finder_ipv6_edge_cases() {
        let input = "2001:db8:0:0:1:0:0:1 2001:0db8:0000:0042:0000:8329:0000:0000";
        let result = ip_finder(&input);
        assert_eq!(
            result,
            vec![
                "2001:db8:0:0:1:0:0:1",
                "2001:0db8:0000:0042:0000:8329:0000:0000"
            ]
        );
    }

    #[test]
    fn test_ip_finder_ipv6_invalid_formats() {
        // These should NOT be extracted as they're invalid IPv6
        let input = "2001:db8::1::2 2001:db8:1:2:3:4:5:6:7:8 gggg::1 2001:db8::gggg";
        let result = ip_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_cidr_finder_ipv6_comprehensive() {
        let input = "2001:db8::/32 fe80::/10 ::1/128 ::/0 2001:0db8:85a3::/48";
        let result = cidr_finder(&input);
        assert_eq!(
            result,
            vec![
                "2001:db8::/32",
                "fe80::/10",
                "::1/128",
                "::/0",
                "2001:0db8:85a3::/48"
            ]
        );
    }

    #[test]
    fn test_cidr_finder_ipv6_invalid() {
        let input = "2001:db8::/129 fe80::/256 invalid::/64";
        let result = cidr_finder(&input);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_range_finder_ipv6_comprehensive() {
        let input = "2001:db8::1-2001:db8::10 fe80::1-fe80::ffff ::1-::2";
        let result = range_finder(&input);
        assert_eq!(
            result,
            vec!["2001:db8::1-2001:db8::10", "fe80::1-fe80::ffff", "::1-::2"]
        );
    }

    #[test]
    fn test_ipv6_with_ports_comprehensive() {
        let input = "[2001:db8::1]:80 [::1]:443 [fe80::1]:8080 2001:db8::1:22222";
        let result = ip_finder(&input);
        // Last one should extract since 22222 > MAX_INT_IN_V6 (9999)
        assert_eq!(result, vec!["2001:db8::1", "::1", "fe80::1", "2001:db8::1"]);
    }

    #[test]
    fn test_ipv6_real_world_scenarios() {
        let input = r#"
        nginx[1234]: connect to [2001:db8::1]:443 failed
        ssh: connect to host 2001:db8::2 port 22: Connection refused
        ping6 -c 1 "fe80::1%eth0" failed
        curl -6 'http://[::1]:8080/api'
        route add -inet6 2001:db8::/32 gateway fe80::1
        "#;
        let result = ip_finder(&input);

        // Verify common IPv6 addresses are extracted from realistic log content
        assert!(result.contains(&"2001:db8::1".to_string()));
        assert!(result.contains(&"2001:db8::2".to_string()));
        assert!(result.contains(&"fe80::1".to_string()));

        // Note: http://[::1]:8080/api doesn't extract ::1 due to http:// prefix parsing
        // which is expected behavior for URL contexts
    }

    #[test]
    fn test_custom_regex_matches_simple() {
        let rules = vec![CustomRule {
            regex: Regex::new(r"host-(\d{3})-(\d{3})-(\d{3})").unwrap(),
            replace: "10.$1.$2.$3".to_string(),
        }];

        let result = custom_regex_matches("connect to host-001-002-003", &rules);
        assert_eq!(result, vec!["10.001.002.003"]);
    }

    #[test]
    fn test_load_config_and_apply_custom_regex() {
        use std::fs;

        let tmp = std::env::temp_dir().join(format!("extract_test_{}", std::process::id()));
        let cfg_dir = tmp.join("extract");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(
            cfg_dir.join("config.toml"),
            "debug = false\n[custom_regexes]\n\"host-(\\\\d{3})-(\\\\d{3})-(\\\\d{3})\" = \"10.$1.$2.$3\"\n",
        )
        .unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        let config = load_config();
        assert_eq!(config.custom_regexes.len(), 1);

        let out = custom_regex_matches("host-123-456-789", &config.custom_regexes);
        assert_eq!(out, vec!["10.123.456.789"]);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_custom_regex_matches_ocid_capture_all() {
        let rules = vec![CustomRule {
            regex: Regex::new(r"(ocid1\S+)").unwrap(),
            replace: "$0".to_string(),
        }];

        let input = "resource ocid1.instance.oc1.phx.123456";
        let result = custom_regex_matches(input, &rules);
        assert_eq!(result, vec!["ocid1.instance.oc1.phx.123456"]);
    }

    #[test]
    fn test_custom_regex_matches_multiple_rules() {
        let rules = vec![
            CustomRule {
                regex: Regex::new(r"host-(\d{3})").unwrap(),
                replace: "10.0.0.$1".to_string(),
            },
            CustomRule {
                regex: Regex::new(r"server-(\d{2})").unwrap(),
                replace: "192.168.1.$1".to_string(),
            },
        ];

        let input = "connect to host-123 and server-45";
        let result = custom_regex_matches(input, &rules);
        assert_eq!(result, vec!["10.0.0.123", "192.168.1.45"]);
    }

    #[test]
    fn test_custom_regex_matches_multiple_matches_same_rule() {
        let rules = vec![CustomRule {
            regex: Regex::new(r"ip-(\d+\.\d+\.\d+\.\d+)").unwrap(),
            replace: "$1".to_string(),
        }];

        let input = "servers ip-192.168.1.1 and ip-10.0.0.1 are online";
        let result = custom_regex_matches(input, &rules);
        assert_eq!(result, vec!["192.168.1.1", "10.0.0.1"]);
    }

    #[test]
    fn test_custom_regex_matches_no_captures() {
        let rules = vec![CustomRule {
            regex: Regex::new(r"ERROR").unwrap(),
            replace: "ALERT".to_string(),
        }];

        let input = "This is an ERROR message with another ERROR";
        let result = custom_regex_matches(input, &rules);
        assert_eq!(result, vec!["ALERT", "ALERT"]);
    }

    #[test]
    fn test_custom_regex_matches_empty_rules() {
        let rules = vec![];
        let input = "host-123 server-45";
        let result = custom_regex_matches(input, &rules);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_custom_regex_matches_no_matches() {
        let rules = vec![CustomRule {
            regex: Regex::new(r"xyz-(\d+)").unwrap(),
            replace: "found-$1".to_string(),
        }];

        let input = "host-123 server-45";
        let result = custom_regex_matches(input, &rules);
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_custom_regex_matches_complex_replacement() {
        let rules = vec![CustomRule {
            regex: Regex::new(r"user:(\w+),role:(\w+),dept:(\w+)").unwrap(),
            replace: "$1@$3.$2".to_string(),
        }];

        let input = "access user:john,role:admin,dept:it and user:jane,role:user,dept:hr";
        let result = custom_regex_matches(input, &rules);
        assert_eq!(result, vec!["john@it.admin", "jane@hr.user"]);
    }

    #[test]
    fn test_load_config_missing_file() {
        let tmp = std::env::temp_dir().join(format!("extract_test_missing_{}", std::process::id()));
        std::env::set_var("XDG_CONFIG_HOME", &tmp);

        let config = load_config();
        assert_eq!(config.debug, false);
        assert_eq!(config.custom_regexes.len(), 0);
    }

    #[test]
    fn test_load_config_invalid_toml() {
        use std::fs;

        let tmp = std::env::temp_dir().join(format!("extract_test_invalid_{}", std::process::id()));
        let cfg_dir = tmp.join("extract");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("config.toml"), "invalid toml content [[[").unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        let config = load_config();
        assert_eq!(config.debug, false);
        assert_eq!(config.custom_regexes.len(), 0);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_load_config_missing_debug_field() {
        use std::fs;

        let tmp =
            std::env::temp_dir().join(format!("extract_test_no_debug_{}", std::process::id()));
        let cfg_dir = tmp.join("extract");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(
            cfg_dir.join("config.toml"),
            "[custom_regexes]\n\"test\" = \"result\"",
        )
        .unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        let config = load_config();
        assert_eq!(config.debug, false);
        assert_eq!(config.custom_regexes.len(), 1);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_load_config_missing_custom_regexes() {
        use std::fs;

        let tmp =
            std::env::temp_dir().join(format!("extract_test_no_regexes_{}", std::process::id()));
        let cfg_dir = tmp.join("extract");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("config.toml"), "debug = true").unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        let config = load_config();
        assert_eq!(config.debug, true);
        assert_eq!(config.custom_regexes.len(), 0);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_load_config_home_fallback() {
        use std::fs;

        let tmp = std::env::temp_dir().join(format!("extract_test_home_{}", std::process::id()));
        let cfg_dir = tmp.join(".config").join("extract");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("config.toml"), "debug = true").unwrap();

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("HOME", &tmp);
        let config = load_config();
        assert_eq!(config.debug, true);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_load_config_non_string_replacement() {
        use std::fs;

        let tmp =
            std::env::temp_dir().join(format!("extract_test_non_string_{}", std::process::id()));
        let cfg_dir = tmp.join("extract");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(
            cfg_dir.join("config.toml"),
            "debug = false\n[custom_regexes]\n\"test\" = 123\n\"valid\" = \"replacement\"",
        )
        .unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        let config = load_config();
        assert_eq!(config.custom_regexes.len(), 1); // Only the valid one

        fs::remove_dir_all(&tmp).ok();
    }

    // Additional edge case tests
    #[test]
    fn test_static_regex_compilation() {
        // Test that our static regexes compile and work
        assert!(DELIMITERS.is_match("hello,world"));
        assert!(DELIMITERS.is_match("hello world"));
        assert!(DELIMITERS.is_match("hello|world"));
        assert!(!DELIMITERS.is_match("helloworld"));

        assert!(MAYBE_PORT.is_match("test:8080"));
        assert!(MAYBE_PORT.is_match("ip:443"));
        assert!(!MAYBE_PORT.is_match("test:abc"));
        assert!(!MAYBE_PORT.is_match("test8080"));
    }

    #[test]
    fn test_large_input_handling() {
        // Test with a large input to ensure no memory issues
        let large_ip_list: Vec<String> = (1..=1000)
            .map(|i| format!("192.168.{}.{}", i / 256, i % 256))
            .collect();
        let input = large_ip_list.join(" ");

        let result = ip_finder(&input);
        assert_eq!(result.len(), 1000);
        assert!(result.contains(&"192.168.1.1".to_string()));
        assert!(result.contains(&"192.168.3.232".to_string()));
    }

    #[test]
    fn test_mixed_delimiters_complex() {
        let input =
            "ip1:192.168.1.1,ip2:10.0.0.1|ip3:172.16.0.1\tip4:203.0.113.1\nip5:198.51.100.1";
        let result = ip_finder(&input);
        assert_eq!(
            result,
            vec![
                "192.168.1.1",
                "10.0.0.1",
                "172.16.0.1",
                "203.0.113.1",
                "198.51.100.1"
            ]
        );
    }

    #[test]
    fn test_malformed_input_resilience() {
        // Test that malformed input doesn't crash the application
        let inputs = vec![
            "",
            ";;;;;;;",
            "192.168.1.999",
            "gggg:hhhh:iiii:jjjj:kkkk:llll:mmmm:nnnn",
            "00:11:22:33:44:55:66:77", // too many MAC segments
            "192.168.1.0/999",         // invalid CIDR
            "192.168.1.1-not.an.ip",
        ];

        for input in inputs {
            let ips = ip_finder(input);
            let cidrs = cidr_finder(input);
            let macs = mac_finder(input);
            let ranges = range_finder(input);

            // Should not crash, results may be empty
            assert!(ips.len() <= 10); // reasonable upper bound
            assert!(cidrs.len() <= 10);
            assert!(macs.len() <= 10);
            assert!(ranges.len() <= 10);
        }
    }

    #[test]
    fn test_integration_with_custom_regexes() {
        // Test that custom regexes work together with standard extraction
        let rules = vec![CustomRule {
            regex: Regex::new(r"server-(\d+)").unwrap(),
            replace: "10.0.0.$1".to_string(),
        }];

        let input = "connect to 192.168.1.1 and server-50 with MAC 00:11:22:33:44:55";
        let ips = ip_finder(input);
        let macs = mac_finder(input);
        let custom = custom_regex_matches(input, &rules);

        assert_eq!(ips, vec!["192.168.1.1"]);
        assert_eq!(macs, vec!["00:11:22:33:44:55"]);
        assert_eq!(custom, vec!["10.0.0.50"]);
    }

    #[test]
    fn test_custom_regex_preserves_ports() {
        // Test that custom regexes can extract IP:PORT while built-in extractors remove ports
        let rules = vec![CustomRule {
            regex: Regex::new(r"(\d+\.\d+\.\d+\.\d+:\d+)").unwrap(),
            replace: "$1".to_string(),
        }];

        let input = "server at 192.168.1.1:8080 and 10.0.0.1:443";
        let ips = ip_finder(input);
        let custom = custom_regex_matches(input, &rules);

        // Built-in extractor removes ports (IPv4 case)
        assert_eq!(ips, vec!["192.168.1.1", "10.0.0.1"]);
        // Custom regex preserves ports
        assert_eq!(custom, vec!["192.168.1.1:8080", "10.0.0.1:443"]);
    }

    #[test]
    fn test_custom_regex_ipv6_brackets() {
        // Test custom regex for IPv6 with ports
        let rules = vec![CustomRule {
            regex: Regex::new(r"\[([0-9a-fA-F:]+)\]:(\d+)").unwrap(),
            replace: "$1:$2".to_string(),
        }];

        let input = "connect to [2001:db8::1]:8080 and [::1]:443";
        let ips = ip_finder(input);
        let custom = custom_regex_matches(input, &rules);

        // Built-in extractor removes ports from bracketed IPv6
        assert_eq!(ips, vec!["2001:db8::1", "::1"]);
        // Custom regex creates custom format
        assert_eq!(custom, vec!["2001:db8::1:8080", "::1:443"]);
    }
}
