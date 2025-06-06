use clap::{Parser, Subcommand};
use log::{debug, LevelFilter};
use regex::Regex;
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::sync::LazyLock;

/// Maximum integer value that can appear in an IPv6 address component.
/// Values above this in the last position are assumed to be port numbers.
const MAX_INT_IN_V6: u32 = 9999;

/// Regex pattern for splitting text on common IP address delimiters
static DELIMITERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[,\s|$>=]").expect("Invalid delimiter regex")
});

/// Regex pattern for detecting potential port numbers at the end of strings
static MAYBE_PORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r":\d{1,6}$").expect("Invalid port regex")
});

#[derive(Subcommand)]
enum Commands {
    /// Print version and quit.
    Version,
}

#[derive(Parser)]
#[command(name = "ipextract-rs", version, about = "IPEXtract CLI in Rust")]
struct Cli {
    /// Enable debug logging.
    #[arg(long)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Checks if a string slice represents a valid IP address (IPv4 or IPv6)
fn is_an_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Removes quotes from the beginning and end of a string slice if present
fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2 {
        if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
            return &s[1..s.len()-1];
        }
    }
    s
}

/// Removes brackets from IPv6 addresses if present
fn strip_brackets(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len()-1]
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
            return Some(parts[..parts.len()-1].join(":"));
        }
    }

    // Handle IPv6 addresses with high port numbers (> MAX_INT_IN_V6)
    if s.matches(':').count() > 1 && !s.contains(']') {
        if let Some(last) = s.rsplit(':').next() {
            if let Ok(num) = last.parse::<u32>() {
                if num > MAX_INT_IN_V6 {
                    let parts: Vec<&str> = s.split(':').collect();
                    return Some(parts[..parts.len()-1].join(":"));
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

fn main() {
    let cli = Cli::parse();

    if cli.debug {
        env_logger::Builder::from_default_env()
            .filter_level(LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(LevelFilter::Info)
            .init();
    }

    if let Some(Commands::Version) = cli.command {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    eprintln!("Input text. End input with Ctrl-d or EOF on a new line.");

    let stdin = io::stdin();
    let mut lines = Vec::new();
    for line in stdin.lock().lines() {
        match line {
            Ok(l) => {
                if l == "EOF" {
                    break;
                }
                lines.push(l);
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }

    let mut parsed_ips = Vec::new();
    for line in lines {
        debug!("Processing line: {}", line);
        let ips = ip_finder(&line);
        debug!("Found IPs: {:?}", ips);
        parsed_ips.extend(ips);
    }

    for ip in parsed_ips {
        println!("{}", ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use predicates::prelude::*;

    const EXAMPLE_V6_1: &str = "2001:db8::1";
    const EXAMPLE_V6_2: &str = "fdbd:db8::2";

    #[test]
    fn test_version_subcommand() {
        let mut cmd = Command::cargo_bin("ipextract-rs").unwrap();
        cmd.arg("version")
            .assert()
            .success()
            .stdout("0.1.0\n");
    }

    #[test]
    fn test_main_version_flag() {
        let mut cmd = Command::cargo_bin("ipextract-rs").unwrap();
        cmd.arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("0.1.0"));
    }

    #[test]
    fn test_main_debug_flag() {
        let mut cmd = Command::cargo_bin("ipextract-rs").unwrap();
        cmd.arg("--debug")
            .write_stdin("EOF\n")
            .assert()
            .success()
            .stderr(predicate::str::contains("Input text. End input with Ctrl-d or EOF on a new line."));
    }

    #[test]
    fn test_main_prints_extracted_ips() {
        let mut cmd = Command::cargo_bin("ipextract-rs").unwrap();
        cmd.write_stdin("1.2.3.4 5.6.7.8\nEOF\n")
            .assert()
            .success()
            .stdout("1.2.3.4\n5.6.7.8\n");
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
        assert_eq!(ip_finder("src:1.1.1.1,dst:2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder("src:1.1.1.1, dst:2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder(&format!("src:{}, dst:{}", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
    }

    #[test]
    fn test_ip_finder_mixed_delimiters() {
        assert_eq!(ip_finder("1.1.1.1 2.2.2.2,3.3.3.3"), vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
        assert_eq!(ip_finder("1.1.1.1 2.2.2.2, 3.3.3.3"), vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
        assert_eq!(ip_finder(&format!("{}, {}", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
    }

    #[test]
    fn test_ip_finder_space_delimiter() {
        assert_eq!(ip_finder("1.1.1.1 "), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1 2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder(&format!("{} {}", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
    }

    #[test]
    fn test_ip_finder_comma_delimiter() {
        assert_eq!(ip_finder("1.1.1.1,"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1,2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder(&format!("{},{}", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
    }

    #[test]
    fn test_ip_finder_pipe_delimiter() {
        assert_eq!(ip_finder("1.1.1.1|"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1|2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder(&format!("{}|{}", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
    }

    #[test]
    fn test_ip_finder_tab_delimiter() {
        assert_eq!(ip_finder("1.1.1.1\t"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1\t2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder(&format!("{}\t{}", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
    }

    #[test]
    fn test_ip_finder_newline_delimiter() {
        assert_eq!(ip_finder("1.1.1.1\n"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1\n2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder(&format!("{}\n{}", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
        assert_eq!(ip_finder("1.1.1.1\r\n"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1\r\n2.2.2.2"), vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn test_ip_finder_quoted() {
        assert_eq!(ip_finder("\"1.1.1.1\","), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("\"1.1.1.1\",\n\"2.2.2.2\""), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder("'1.1.1.1',"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("'1.1.1.1',\n'2.2.2.2'"), vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn test_ip_finder_with_ports() {
        assert_eq!(ip_finder("1.1.1.1:65000"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("1.1.1.1:65000,2.2.2.2:443"), vec!["1.1.1.1", "2.2.2.2"]);
        assert_eq!(ip_finder("1.2.3.4:abcd"), vec!["1.2.3.4"]);
        assert_eq!(ip_finder("foo:.:2.2.2.2"), Vec::<String>::new());
        assert_eq!(ip_finder("[1.1.1.1]:65000"), vec!["1.1.1.1"]);
        assert_eq!(ip_finder("[1.1.1.1]:65000,[2.2.2.2]:443"), vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn test_ip_finder_ipv6_with_ports() {
        assert_eq!(ip_finder(&format!("{}:65000", EXAMPLE_V6_1)), vec![EXAMPLE_V6_1]);
        let input = format!("{}:65000, {}:80", EXAMPLE_V6_1, EXAMPLE_V6_2);
        let result = ip_finder(&input);
        assert!(result.contains(&EXAMPLE_V6_1.to_string()));
        
        assert_eq!(ip_finder(&format!("[{}]:65000", EXAMPLE_V6_1)), vec![EXAMPLE_V6_1]);
        assert_eq!(ip_finder(&format!("[{}]:65000, [{}]:80", EXAMPLE_V6_1, EXAMPLE_V6_2)), vec![EXAMPLE_V6_1, EXAMPLE_V6_2]);
    }

    #[test]
    fn test_ip_finder_complex_text() {
        let input = format!(
            "The IP 1.1.1.1 is having trouble talking to\n    2.2.2.2 on port 5555.\n\n    Others:\n    src:1.1.1.2 -> dst:2.2.2.3:771\n    src:{} -> dst: [{}]:443\n    any issue?",
            EXAMPLE_V6_1, EXAMPLE_V6_2
        );
        let expected = vec!["1.1.1.1", "2.2.2.2", "1.1.1.2", "2.2.2.3", EXAMPLE_V6_1, EXAMPLE_V6_2];
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
}
