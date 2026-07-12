//! CLI and config integration tests: everything that spawns the extract
//! binary lives here so `CARGO_BIN_EXE_extract` is available.

use assert_cmd::Command;
use assert_cmd::cargo::CommandCargoExt;
use escargot::CargoBuild;
use predicates::prelude::*;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::process::{Command as StdCommand, Stdio};

static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvGuard {
    fn set<V: AsRef<OsStr>>(key: &'static str, value: V) -> Self {
        let original = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(ref value) = self.original {
            unsafe {
                std::env::set_var(self.key, value);
            }
        } else {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }
}

fn cli_cmd() -> Command {
    if let Some(bin) = std::env::var_os("EXTRACT_BIN") {
        return Command::from_std(StdCommand::new(bin));
    }
    Command::cargo_bin("extract").unwrap_or_else(|_| {
        let build = CargoBuild::new()
            .bin("extract")
            .run()
            .expect("failed to build extract binary");
        Command::from_std(build.command())
    })
}

fn cli_std_cmd() -> StdCommand {
    if let Some(bin) = std::env::var_os("EXTRACT_BIN") {
        return StdCommand::new(bin);
    }
    StdCommand::cargo_bin("extract").unwrap_or_else(|_| {
        CargoBuild::new()
            .bin("extract")
            .run()
            .expect("failed to build extract binary")
            .command()
    })
}

#[test]
fn test_version_subcommand() {
    let mut cmd = cli_cmd();
    cmd.arg("version").assert().success().stdout("0.2.2\n");
}

#[test]
fn test_main_version_flag() {
    let mut cmd = cli_cmd();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.2.2"));
}

#[test]
fn test_main_debug_flag() {
    let mut cmd = cli_cmd();
    cmd.args(["--log-level", "debug"])
        .write_stdin("1.2.3.4\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Processing line: 1.2.3.4"));
}

#[test]
fn test_main_prints_extracted_ips() {
    let mut cmd = cli_cmd();
    cmd.write_stdin("1.2.3.4 5.6.7.8\n")
        .assert()
        .success()
        .stdout("1.2.3.4\n5.6.7.8\n");
}

#[test]
fn test_main_extracts_all_network_tokens() {
    let mut cmd = cli_cmd();
    cmd.write_stdin("IP: 192.168.1.1, CIDR: 10.0.0.0/8, MAC: 00:11:22:33:44:55, Range: 172.16.1.1-172.16.1.10\n")
        .assert()
        .success()
        .stdout("192.168.1.1\n10.0.0.0/8\n00:11:22:33:44:55\n172.16.1.1-172.16.1.10\n");
}

#[test]
fn test_main_reads_from_file() {
    use std::fs;

    let path = std::env::temp_dir().join("extract_test_input.txt");
    fs::write(&path, "1.2.3.4 5.6.7.8\n").unwrap();

    let mut cmd = cli_cmd();
    cmd.arg(path.to_str().unwrap())
        .assert()
        .success()
        .stdout("1.2.3.4\n5.6.7.8\n");

    fs::remove_file(path).ok();
}

#[test]
fn test_config_ls_command() {
    let mut cmd = cli_cmd();
    cmd.args(["config", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config.toml").and(predicate::str::contains("conf.d")));
}

#[test]
fn test_config_generate_and_print() {
    use std::fs;

    let tmp = std::env::temp_dir().join(format!("extract_test_generate_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let _env_lock = ENV_MUTEX.lock().unwrap();
    let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", &tmp);
    // Mirrors config_dirs(): with XDG_CONFIG_HOME set, the preferred config
    // location is $XDG_CONFIG_HOME/extract/config.toml.
    let path = tmp.join("extract").join("config.toml");
    let _ = fs::remove_file(&path);

    let mut cmd = cli_cmd();
    cmd.args(["config", "generate"]).assert().success();

    assert!(path.exists());

    let mut cmd = cli_cmd();
    cmd.args(["config", "print"])
        .assert()
        .success()
        .stdout(predicate::str::contains("log_level = \"warn\""));

    fs::remove_file(&path).ok();
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn test_config_print_without_any_config() {
    let mut cmd = cli_cmd();
    cmd.env_remove("XDG_CONFIG_HOME")
        .env_remove("APPDATA")
        .env_remove("HOME")
        .args(["config", "print"])
        .assert()
        .success()
        .stdout(predicate::str::contains("log_level = \"warn\""));
}

#[test]
fn test_config_ls_without_any_config() {
    let mut cmd = cli_cmd();
    cmd.env_remove("XDG_CONFIG_HOME")
        .env_remove("APPDATA")
        .env_remove("HOME")
        .args(["config", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_config_generate_without_any_config() {
    let mut cmd = cli_cmd();
    cmd.env_remove("XDG_CONFIG_HOME")
        .env_remove("APPDATA")
        .env_remove("HOME")
        .args(["config", "generate"])
        .assert()
        .success()
        .stderr(predicate::str::contains("No config path"));
}

#[test]
fn test_no_panic_on_broken_pipe() {
    let mut child = cli_std_cmd()
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
fn test_cli_single_regex() {
    let mut cmd = cli_cmd();
    cmd.args(["--regex", r"\d+\.\d+\.\d+\.\d+:\d+"])
        .write_stdin("connected 1.2.3.4:8080\n")
        .assert()
        .success()
        .stdout("1.2.3.4\n1.2.3.4:8080\n");
}

#[test]
fn test_cli_multiple_regex_flags() {
    let mut cmd = cli_cmd();
    cmd.args([
        "--regex",
        r"\d+\.\d+\.\d+\.\d+:\d+",
        "--regex",
        r"server-(\d+)",
    ])
    .write_stdin("server-42 10.0.0.1:99\n")
    .assert()
    .success()
    .stdout("10.0.0.1\n10.0.0.1:99\nserver-42\n");
}
