//! Real standard-protocol fixtures, no live services or fabricated success JSON.
#![cfg(feature = "ots")]
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use steganographer_core::{
    crypto::{decode_hex, encode_hex},
    ots_client::{OTSClient, OTSError, OTSMethod, MAX_PROOF_BYTES},
    ots_config::OtsConfig,
    ots_handler,
};
const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
// Public Bitcoin genesis coinbase, source:
// https://blockstream.info/api/tx/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b/hex
const GENESIS_TRANSACTION: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
fn varint(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
    out
}
fn pending(uri: &str) -> Vec<u8> {
    let mut payload = varint(uri.len());
    payload.extend_from_slice(uri.as_bytes());
    let mut tree = vec![0];
    tree.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
    tree.extend(varint(payload.len()));
    tree.extend(payload);
    tree
}
fn detached(digest: &[u8; 32], tree: &[u8]) -> Vec<u8> {
    let mut proof = MAGIC.to_vec();
    proof.extend_from_slice(&[1, 8]);
    proof.extend_from_slice(digest);
    proof.extend_from_slice(tree);
    proof
}
// SHA256(file) -> SHA256 -> genesis transaction id -> genesis Merkle root.
fn confirmed_tree() -> Vec<u8> {
    vec![8, 0, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 1, 0]
}
// Independently evaluate the serialized blinding operations, without the core parser.
fn submitted_commitment(proof: &[u8], digest: &[u8; 32], calendar: &str) -> ([u8; 32], [u8; 32]) {
    assert_eq!(&proof[..MAGIC.len()], MAGIC);
    assert_eq!(&proof[MAGIC.len()..MAGIC.len() + 2], &[1, 8]);
    assert_eq!(&proof[MAGIC.len() + 2..MAGIC.len() + 34], digest);
    let tree = &proof[MAGIC.len() + 34..];
    assert_eq!(&tree[..2], &[0xf0, 32]);
    let nonce: [u8; 32] = tree[2..34].try_into().unwrap();
    assert_eq!(tree[34], 0x08);
    assert_eq!(&tree[35..], pending(calendar));
    let mut message = digest.to_vec();
    message.extend_from_slice(&nonce);
    (nonce, Sha256::digest(&message).into())
}
#[derive(Clone)]
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}
struct Reply {
    status: u16,
    body: Vec<u8>,
    chunked: bool,
    stall: bool,
    truncated: bool,
}
impl Reply {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            chunked: false,
            stall: false,
            truncated: false,
        }
    }
}
struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new(handler: impl Fn(&Request, &str) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let record = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let base = url.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // BSD/macOS inherits the listener's nonblocking flag.
                        // This fixture intentionally uses synchronous exact reads.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        if let Some(request) = request(&mut stream) {
                            let reply = handler(&request, &base);
                            record.lock().unwrap().push(request);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 {} Test\r\nConnection: close\r\n",
                                reply.status
                            );
                            if reply.chunked {
                                let _ = stream.write_all(b"Transfer-Encoding: chunked\r\n\r\n");
                                let _ = write!(stream, "{:x}\r\n", reply.body.len());
                                let _ = stream.write_all(&reply.body);
                                let _ = stream.write_all(b"\r\n0\r\n\r\n");
                            } else {
                                let _ = write!(
                                    stream,
                                    "Content-Length: {}\r\n\r\n",
                                    reply.body.len() + usize::from(reply.stall || reply.truncated)
                                );
                                let _ = stream.write_all(&reply.body);
                                let _ = stream.flush();
                                if reply.stall {
                                    std::thread::sleep(Duration::from_millis(1300));
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    fn client(&self) -> OTSClient {
        OTSClient::from_config(&OtsConfig {
            server_url: self.url.clone(),
            bitcoin_explorer_url: self.url.clone(),
            timeout_secs: 1,
            ..Default::default()
        })
        .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn request(stream: &mut TcpStream) -> Option<Request> {
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() > 8192 || stream.read_exact(&mut byte).is_err() {
            return None;
        }
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header).ok()?;
    let mut lines = text.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.into();
    let path = first.next()?.into();
    let len = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    if len > MAX_PROOF_BYTES {
        return None;
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).ok()?;
    Some(Request { method, path, body })
}
#[tokio::test]
async fn standard_submit_pending_and_atomic_admission() {
    let server = Server::new(|request, base| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/digest");
        assert_eq!(request.body.len(), 32);
        Reply::ok(pending(base))
    });
    let client = server.client();
    let digest = OTSClient::compute_sha256_digest(b"public fixture");
    let (a, b) = tokio::join!(client.stamp_digest(&digest), client.stamp_digest(&digest));
    let (proof, rejected) = if a.is_ok() {
        (a.unwrap(), b)
    } else {
        (b.unwrap(), a)
    };
    assert!(matches!(rejected, Err(OTSError::RateLimited)));
    assert!(!client.can_stamp());
    assert!(OTSClient::validate_proof(&proof, &digest).unwrap());
    assert!(matches!(
        OTSClient::validate_proof(&proof, &[0; 32]),
        Err(OTSError::VerificationFailed(_))
    ));
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    let forced = client.stamp_digest_force(&digest).await.unwrap();
    let (nonce, commitment) = submitted_commitment(&proof, &digest, &server.url);
    let (forced_nonce, forced_commitment) = submitted_commitment(&forced, &digest, &server.url);
    assert_ne!(nonce, forced_nonce);
    assert_ne!(commitment, forced_commitment);
    assert_ne!(proof, forced);
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for (request, expected) in requests.iter().zip([commitment, forced_commitment]) {
        assert_ne!(request.body, digest);
        assert_eq!(request.body, expected);
    }
}
#[tokio::test]
async fn real_genesis_fixture_upgrades_and_verifies_only_its_file() {
    let transaction = decode_hex(GENESIS_TRANSACTION).unwrap();
    let digest = OTSClient::compute_sha256_digest(&transaction);
    let upgrade_path = format!("/timestamp/{}", encode_hex(&digest));
    let server = Server::new(move |request, _| match request.path.as_str() {
        "/digest" => panic!("historical unblinded receipt must not be submitted again"),
        "/block-height/0" => Reply::ok(GENESIS_HASH.as_bytes().to_vec()),
        p if p == format!("/block/{GENESIS_HASH}/header") => {
            Reply::ok(GENESIS_HEADER.as_bytes().to_vec())
        }
        p if p == upgrade_path => Reply::ok(confirmed_tree()),
        _ => panic!("unexpected standard protocol request"),
    });
    let client = server.client();
    // Historical receipt rooted directly at SHA256(transaction), before blinding.
    let proof = detached(&digest, &pending(&server.url));
    let (result, upgraded) = client.verify_with_upgrade(&proof, &digest).await.unwrap();
    let upgraded = upgraded.expect("completed upgrade bytes must be available for publication");
    assert!(upgraded
        .windows(pending(&server.url).len())
        .any(|branch| branch == pending(&server.url)));
    assert!(!OTSClient::validate_proof(&upgraded, &digest).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.ots");
    client.save_proof_to(&proof, &path).await.unwrap();
    let upgraded_path = client.save_proof_to(&upgraded, &path).await.unwrap();
    assert_ne!(upgraded_path, path);
    assert_eq!(OTSClient::load_proof(&path).await.unwrap(), proof);
    assert_eq!(
        OTSClient::load_proof(&upgraded_path).await.unwrap(),
        upgraded
    );
    assert!(result.verified);
    assert!(!result.pending);
    assert_eq!(result.timestamp, Some(1231006505));
    assert!(result.details.contains("trusted Esplora"));
    let expected_paths = [
        format!("/timestamp/{}", encode_hex(&digest)),
        "/block-height/0".into(),
        format!("/block/{GENESIS_HASH}/header"),
    ];
    {
        let recorded = server.requests.lock().unwrap();
        assert_eq!(
            recorded.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            expected_paths
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        assert!(recorded
            .iter()
            .all(|r| r.method == "GET" && r.body.is_empty()));
    }
    let requests = server.requests.lock().unwrap().len();
    let other = OTSClient::compute_sha256_digest(b"another file");
    assert!(matches!(
        client.verify(&proof, &other).await,
        Err(OTSError::VerificationFailed(_))
    ));
    assert_eq!(server.requests.lock().unwrap().len(), requests);
}
#[tokio::test]
async fn completed_proof_with_stale_pending_skips_calendar_but_rejects_invalid_commitment() {
    let server = Server::new(|request, _| match request.path.as_str() {
        "/block-height/0" => Reply::ok(GENESIS_HASH.as_bytes().to_vec()),
        p if p == format!("/block/{GENESIS_HASH}/header") => {
            Reply::ok(GENESIS_HEADER.as_bytes().to_vec())
        }
        _ => {
            let mut reply = Reply::ok(b"calendar offline".to_vec());
            reply.status = 503;
            reply
        }
    });
    let client = server.client();
    // This is the append-only shape produced by upgrading a historical receipt.
    let mut tree = vec![0xff];
    tree.extend(pending(&server.url));
    tree.extend(confirmed_tree());
    let digest = OTSClient::compute_sha256_digest(&decode_hex(GENESIS_TRANSACTION).unwrap());
    let proof = detached(&digest, &tree);
    let (result, upgraded) = client.verify_with_upgrade(&proof, &digest).await.unwrap();
    assert!(result.verified);
    assert!(!result.pending);
    assert_eq!(result.timestamp, Some(1231006505));
    assert!(upgraded.is_none());
    assert!(client.verify(&proof, &digest).await.unwrap().verified);
    // A Bitcoin tag alone is not sufficient: the evaluated commitment must match.
    let invalid_digest = [42; 32];
    let invalid = detached(&invalid_digest, &tree);
    assert!(matches!(
        client.verify_with_upgrade(&invalid, &invalid_digest).await,
        Err(OTSError::VerificationFailed(_))
    ));
    assert!(matches!(
        client.verify(&invalid, &invalid_digest).await,
        Err(OTSError::VerificationFailed(_))
    ));
    let paths = server.requests.lock().unwrap();
    assert_eq!(paths.len(), 8);
    assert!(paths.iter().all(|request| {
        request.path == "/block-height/0" || request.path == format!("/block/{GENESIS_HASH}/header")
    }));
}
#[tokio::test]
async fn fresh_blinded_genesis_file_is_pending_not_a_historical_confirmation() {
    let transaction = decode_hex(GENESIS_TRANSACTION).unwrap();
    let digest = OTSClient::compute_sha256_digest(&transaction);
    for forged_confirmation in [false, true] {
        let submitted = Arc::new(Mutex::new(None::<Vec<u8>>));
        let captured = submitted.clone();
        let server = Server::new(move |request, base| match request.path.as_str() {
            "/digest" => {
                assert_eq!(request.method, "POST");
                assert_eq!(request.body.len(), 32);
                *captured.lock().unwrap() = Some(request.body.clone());
                Reply::ok(pending(base))
            }
            p if p.starts_with("/timestamp/") => {
                let commitment = captured.lock().unwrap();
                assert_eq!(
                    p,
                    format!("/timestamp/{}", encode_hex(commitment.as_ref().unwrap()))
                );
                if forged_confirmation {
                    Reply::ok(confirmed_tree())
                } else {
                    let mut reply = Reply::ok(Vec::new());
                    reply.status = 404;
                    reply
                }
            }
            "/block-height/0" if forged_confirmation => Reply::ok(GENESIS_HASH.as_bytes().to_vec()),
            p if forged_confirmation && p == format!("/block/{GENESIS_HASH}/header") => {
                Reply::ok(GENESIS_HEADER.as_bytes().to_vec())
            }
            _ => panic!("unexpected fresh submission protocol request"),
        });
        let client = server.client();
        let proof = client.stamp_digest(&digest).await.unwrap();
        let (_, commitment) = submitted_commitment(&proof, &digest, &server.url);
        assert_ne!(commitment, digest);
        assert_eq!(
            submitted.lock().unwrap().as_deref(),
            Some(commitment.as_slice())
        );
        let upgraded = client.upgrade(&proof, &digest).await.unwrap();
        let result = client.verify_attestations(&upgraded, &digest).await;
        if forged_confirmation {
            assert!(matches!(result, Err(OTSError::VerificationFailed(_))));
        } else {
            assert_eq!(upgraded, proof);
            let result = result.unwrap();
            assert!(!result.verified);
            assert!(result.pending);
            assert_eq!(result.timestamp, None);
            assert_eq!(server.requests.lock().unwrap().len(), 2);
        }
    }
}
#[tokio::test]
async fn forged_header_or_wrong_merkle_is_not_verified() {
    let transaction = decode_hex(GENESIS_TRANSACTION).unwrap();
    let digest = OTSClient::compute_sha256_digest(&transaction);
    for forged in [false, true] {
        let server = Server::new(move |request, _| {
            if request.path == "/block-height/0" {
                Reply::ok(GENESIS_HASH.as_bytes().to_vec())
            } else {
                let mut header = decode_hex(GENESIS_HEADER).unwrap();
                if forged {
                    header[68] ^= 1;
                }
                Reply::ok(encode_hex(&header).into_bytes())
            }
        });
        let proof = detached(if forged { &digest } else { &[42; 32] }, &confirmed_tree());
        let expected = if forged { digest } else { [42; 32] };
        assert!(matches!(
            server.client().verify(&proof, &expected).await,
            Err(OTSError::VerificationFailed(_))
        ));
    }
}

#[tokio::test]
async fn matching_header_hash_without_valid_mainnet_work_is_rejected() {
    let mut header = decode_hex(GENESIS_HEADER).unwrap();
    header[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes());
    let inner = OTSClient::compute_sha256_digest(&header);
    let mut hash = OTSClient::compute_sha256_digest(&inner);
    hash.reverse();
    let hash_text = encode_hex(&hash);
    let header_text = encode_hex(&header);
    let server = Server::new(move |request, _| {
        Reply::ok(if request.path == "/block-height/0" {
            hash_text.as_bytes().to_vec()
        } else {
            header_text.as_bytes().to_vec()
        })
    });
    let digest = OTSClient::compute_sha256_digest(&decode_hex(GENESIS_TRANSACTION).unwrap());
    assert!(matches!(
        server
            .client()
            .verify(&detached(&digest, &confirmed_tree()), &digest)
            .await,
        Err(OTSError::VerificationFailed(_))
    ));
}
#[tokio::test]
async fn pending_is_inconclusive_and_proof_uri_cannot_trigger_ssrf() {
    let server = Server::new(|_, _| panic!("untrusted URI must never be contacted"));
    let digest = OTSClient::compute_sha256_digest(b"public fixture");
    let proof = detached(&digest, &pending("http://169.254.169.254/latest"));
    let result = server.client().verify(&proof, &digest).await.unwrap();
    assert!(!result.verified);
    assert!(result.pending);
    assert_eq!(result.timestamp, None);
    assert!(server.requests.lock().unwrap().is_empty());
}
#[tokio::test]
async fn blinding_prefix_counts_against_detached_proof_depth_budget() {
    for depth in [253, 254] {
        let server = Server::new(move |_, base| {
            let mut tree = vec![0x08; depth];
            tree.extend(pending(base));
            Reply::ok(tree)
        });
        let result = server.client().stamp_digest(&[9; 32]).await;
        if depth == 253 {
            let proof = result
                .expect("253 calendar operations plus blinding must fit the proof depth budget");
            assert!(OTSClient::validate_proof(&proof, &[9; 32]).unwrap());
        } else {
            assert!(matches!(result, Err(OTSError::InvalidProof(_))));
        }
    }
}
#[tokio::test]
async fn malformed_json_and_resource_budgets_are_rejected() {
    let digest = [9; 32];
    for body in [
        b"NOT_OTS!".to_vec(),
        b"{\"success\":true}".to_vec(),
        vec![8; 257],
        vec![0; 10001],
    ] {
        for chunked in [false, true] {
            let bytes = body.clone();
            let server = Server::new(move |_, _| {
                let mut r = Reply::ok(bytes.clone());
                r.chunked = chunked;
                r
            });
            assert!(server.client().stamp_digest(&digest).await.is_err());
        }
    }
    let mut proof = detached(&digest, &pending("https://a.pool.opentimestamps.org"));
    proof.resize(MAX_PROOF_BYTES + 1, 0);
    assert!(OTSClient::validate_proof(&proof, &digest).is_err());
    let mut unsupported = confirmed_tree();
    unsupported[2] = 0xff;
    assert!(OTSClient::validate_proof(&detached(&digest, &unsupported), &digest).is_err());
}
#[tokio::test]
async fn successful_headers_do_not_swallow_body_timeout_or_truncation() {
    for stall in [true, false] {
        let server = Server::new(move |_, _| {
            let mut r = Reply::ok(Vec::new());
            r.stall = stall;
            r.truncated = !stall;
            r
        });
        let proof = detached(&[1; 32], &pending(&server.url));
        let error = server.client().verify(&proof, &[1; 32]).await.unwrap_err();
        assert!(matches!(error, OTSError::Http(_) | OTSError::Timeout));
        assert_eq!(ots_handler::error_to_http(&error).0, 503);
    }
}
#[tokio::test]
async fn publication_preserves_old_evidence_and_validates_cache_binding() {
    let temp = tempfile::tempdir().unwrap();
    let client = OTSClient::new(OTSMethod::Bitcoin)
        .unwrap()
        .with_proof_dir(temp.path());
    let digest = [7; 32];
    let hex = encode_hex(&digest);
    let old = detached(&digest, &pending("https://a.pool.opentimestamps.org"));
    let new = detached(&digest, &pending("https://b.pool.opentimestamps.org"));
    let old_path = client.save_proof(&old, &hex).await.unwrap();
    let new_path = client.save_proof(&new, &hex).await.unwrap();
    assert_ne!(old_path, new_path);
    assert_eq!(OTSClient::load_proof(&old_path).await.unwrap(), old);
    assert_eq!(OTSClient::load_proof(&new_path).await.unwrap(), new);
    assert!(client
        .save_proof(&old, &encode_hex(&[8; 32]))
        .await
        .is_err());
    assert!(client.proof_path_for("../../untrusted").is_err());
    let oversized = temp.path().join("oversized.ots");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len((MAX_PROOF_BYTES + 1) as u64)
        .unwrap();
    assert!(OTSClient::load_proof(&oversized).await.is_err());
    std::fs::write(temp.path().join("invalid.ots"), b"NOT_OTS!").unwrap();
    assert!(OTSClient::load_proof(&temp.path().join("invalid.ots"))
        .await
        .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = temp.path().join("evidence");
        std::fs::write(&target, b"original evidence").unwrap();
        let link = temp.path().join("link.ots");
        symlink(&target, &link).unwrap();
        assert!(OTSClient::load_proof(&link).await.is_err());
        let published = client.save_proof_to(&old, &link).await.unwrap();
        assert_ne!(published, link);
        assert_eq!(std::fs::read(&target).unwrap(), b"original evidence");
        assert!(std::fs::symlink_metadata(link).unwrap().is_symlink());
        let hard = temp.path().join("hard.ots");
        std::fs::hard_link(&old_path, &hard).unwrap();
        assert!(OTSClient::load_proof(&hard).await.is_err());
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let fifo = temp.path().join("fifo.ots");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: owned NUL-terminated filename in the isolated temporary dir.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), OTSClient::load_proof(&fifo))
                .await
                .unwrap()
                .is_err()
        );
        assert_ne!(client.save_proof_to(&old, &fifo).await.unwrap(), fifo);
    }
}
#[test]
fn invalid_configuration_and_methods_never_fall_back() {
    for method in ["ethereum", "eth", "unknown", ""] {
        let cfg = OtsConfig {
            method: method.into(),
            ..Default::default()
        };
        assert!(OTSClient::from_config(&cfg).is_err());
        assert!(OTSMethod::parse(method).is_err());
    }
    for url in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com?query",
        "file:///tmp/test",
    ] {
        assert!(OTSClient::from_config(&OtsConfig {
            server_url: url.into(),
            ..Default::default()
        })
        .is_err());
    }
    for value in [0, 301] {
        assert!(OTSClient::from_config(&OtsConfig {
            timeout_secs: value,
            ..Default::default()
        })
        .is_err());
    }
    assert!(OTSMethod::from_tag(1).is_err());
    assert_eq!(OTSMethod::from_tag(0).unwrap(), OTSMethod::Bitcoin);
}
