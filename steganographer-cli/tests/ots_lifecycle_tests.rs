//! Standard detached proof lifecycle against local calendar/Esplora HTTP fixtures.
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use steganographer_core::crypto::decode_hex;

const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
// Public genesis coinbase: https://blockstream.info/api/tx/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b/hex
const GENESIS_TRANSACTION: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

struct Server {
    url: String,
    paths: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let recorded = paths.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut header = Vec::new();
                        let mut byte = [0];
                        while !header.ends_with(b"\r\n\r\n") {
                            assert!(header.len() < 8192);
                            stream.read_exact(&mut byte).unwrap();
                            header.push(byte[0]);
                        }
                        let text = std::str::from_utf8(&header).unwrap();
                        let mut first = text.lines().next().unwrap().split_whitespace();
                        assert_eq!(first.next(), Some("GET"));
                        let path = first.next().unwrap();
                        recorded.lock().unwrap().push(path.to_owned());
                        let (status, body) = match path {
                            "/block-height/0" => (200, GENESIS_HASH),
                            p if p == format!("/block/{GENESIS_HASH}/header") => {
                                (200, GENESIS_HEADER)
                            }
                            p if p.starts_with("/timestamp/") => (503, "calendar offline"),
                            _ => panic!("unexpected OTS request: {path}"),
                        };
                        write!(
                            stream,
                            "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            paths,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn pending(calendar: &str) -> Vec<u8> {
    let mut tree = vec![0, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
    assert!(calendar.len() + 1 < 128);
    tree.push((calendar.len() + 1) as u8);
    tree.push(calendar.len() as u8);
    tree.extend_from_slice(calendar.as_bytes());
    tree
}
fn proof(data: &[u8], calendar: &str, complete: bool) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&[1, 8]);
    bytes.extend_from_slice(&Sha256::digest(data));
    if complete {
        bytes.push(0xff);
    }
    bytes.extend(pending(calendar));
    if complete {
        // SHA256(file) -> SHA256 -> genesis transaction id -> Bitcoin height 0.
        bytes.extend_from_slice(&[8, 0, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 1, 0]);
    }
    bytes
}
fn verify(config: &Path, input: &Path, proof: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_steganographer"))
        .arg("--config")
        .arg(config)
        .args(["ots", "verify", "--input"])
        .arg(input)
        .arg("--proof")
        .arg(proof)
        .args(["--format", "json"])
        .output()
        .unwrap()
}
fn envelope(output: &Output) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid JSON ({error}): {output:?}"));
    assert_eq!(value["schema"], "steganographer.cli/v1");
    value
}

#[test]
fn completed_proof_with_stale_calendar_verifies_but_invalid_and_pending_do_not() {
    let server = Server::new();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let input = dir.path().join("genesis.bin");
    let receipt = dir.path().join("receipt.ots");
    std::fs::write(&config, format!(
        "[global]\n\n[ots]\nserver_url = {:?}\nbitcoin_explorer_url = {:?}\nproof_dir = {:?}\ntimeout_secs = 2\n",
        server.url, server.url, dir.path().to_str().unwrap()
    )).unwrap();
    let data = decode_hex(GENESIS_TRANSACTION).unwrap();
    std::fs::write(&input, &data).unwrap();
    let complete = proof(&data, &server.url, true);
    std::fs::write(&receipt, &complete).unwrap();
    let output = verify(&config, &input, &receipt);
    assert!(output.status.success(), "{output:?}");
    let result = envelope(&output);
    assert_eq!(result["result"]["verified"], true);
    assert_eq!(result["result"]["pending"], false);
    assert_eq!(result["result"]["timestamp"], 1231006505u64);
    assert_eq!(result["result"]["digest_scheme"], "sha256-file");
    assert_eq!(result["result"]["proof_file"], receipt.to_str().unwrap());
    assert_eq!(std::fs::read(&receipt).unwrap(), complete);

    // Matching file digest with a false Bitcoin commitment must still fail.
    let invalid_data = b"not the genesis transaction";
    std::fs::write(&input, invalid_data).unwrap();
    std::fs::write(&receipt, proof(invalid_data, &server.url, true)).unwrap();
    let output = verify(&config, &input, &receipt);
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(envelope(&output)["status"], "error");
    {
        let paths = server.paths.lock().unwrap();
        assert_eq!(paths.len(), 4);
        assert!(paths.iter().all(|path| !path.starts_with("/timestamp/")));
    }

    // Calendar failures remain explicit when a pending-only proof actually needs upgrade.
    std::fs::write(&receipt, proof(&data, &server.url, false)).unwrap();
    std::fs::write(&input, &data).unwrap();
    let output = verify(&config, &input, &receipt);
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(envelope(&output)["status"], "error");
    let paths = server.paths.lock().unwrap();
    assert_eq!(paths.len(), 5);
    assert!(paths.last().unwrap().starts_with("/timestamp/"));
}
