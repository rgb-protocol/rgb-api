use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
/// A NIA transfer on regtest, whose witness transactions are unknown to [`esplora_without_txs`].
const NIA_TRANSFER: &str = "nia_transfer.rgb";
const NIA_SCHEMA: &str = "NonInflatableAsset.rgb";
const REGTEST_GENESIS_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Spawns an Esplora server serving the regtest chain without any transaction, so that it
/// answers every witness lookup with "not found", as it would for a TX never broadcast.
fn esplora_without_txs() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock Esplora server");
    let address = listener.local_addr().expect("read mock server address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.expect("accept Esplora connection");
            let mut request_line = String::new();
            BufReader::new(&stream)
                .read_line(&mut request_line)
                .expect("read Esplora request");
            let (status, body) = if request_line.starts_with("GET /block-height/0 ") {
                ("200 OK", REGTEST_GENESIS_HASH)
            } else {
                ("404 Not Found", "")
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write mock Esplora response");
        }
    });
    format!("http://{address}")
}

fn rgb(data_dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rgb"));
    cmd.arg("-d").arg(data_dir).args(["-n", "regtest"]);
    cmd
}

/// A data dir whose stock knows the NIA schema.
fn data_dir_with_nia_schema() -> TempDir {
    let data_dir = TempDir::new().unwrap();
    rgb(data_dir.path())
        .arg("import")
        .arg(Path::new(FIXTURES).join(NIA_SCHEMA))
        .assert()
        .success();
    data_dir
}

#[test]
fn accept_rejects_witness_unknown_to_indexer() {
    let data_dir = data_dir_with_nia_schema();
    rgb(data_dir.path())
        .arg(format!("--esplora={}", esplora_without_txs()))
        .arg("accept")
        .arg(Path::new(FIXTURES).join(NIA_TRANSFER))
        .assert()
        .failure()
        .stderr(predicate::str::contains("is unknown to the indexer"))
        .stderr(predicate::str::contains("--force"))
        .stderr(predicate::str::contains("Transfer accepted into the store").not());
}

#[test]
fn accept_force_takes_witness_from_consignment() {
    let data_dir = data_dir_with_nia_schema();
    rgb(data_dir.path())
        .arg(format!("--esplora={}", esplora_without_txs()))
        .args(["accept", "--force"])
        .arg(Path::new(FIXTURES).join(NIA_TRANSFER))
        .assert()
        .success()
        .stderr(predicate::str::contains("Transfer accepted into the store"));
}

#[test]
fn validate_warns_about_witness_unknown_to_indexer() {
    let data_dir = data_dir_with_nia_schema();
    rgb(data_dir.path())
        .arg(format!("--esplora={}", esplora_without_txs()))
        .arg("validate")
        .arg(Path::new(FIXTURES).join(NIA_TRANSFER))
        .assert()
        .success()
        .stderr(predicate::str::contains("The provided consignment is valid"))
        .stderr(predicate::str::contains("unknown to the indexer"));
}
