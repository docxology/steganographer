//! Bounded OpenTimestamps v1 detached proofs and calendar protocol.
//!
//! Calendar submission is `POST /digest`; upgrade is `GET /timestamp/<commitment>`.
//! Fresh submissions blind SHA256(file) with a cryptographic 32-byte nonce;
//! standard append/SHA256 operations retain the original digest as proof root.
//! Verification evaluates the proof locally and binds its SHA256 digest to the
//! caller's content. Bitcoin headers are checked against a configured trusted
//! Esplora height index. This is NOT independent full-node chain validation.
//!
//! Limits: 1 MiB detached proofs, 10,000-byte calendar responses, 256 tree
//! levels, 4,096 operations/branches, 4,096-byte messages, 64 attestations,
//! eight calendar upgrades / Bitcoin attestations per operation, and a total
//! configured deadline. Unknown attestations and algorithms are rejected.
//! Proof-directory parents are trusted configuration; final file names are
//! no-follow and publication is atomic/no-clobber. Force stamps and upgrades
//! preserve old receipts under their original names, publishing distinct proof
//! bytes as `<original-name>.<SHA256(proof)>.ots`. Cancelled blocking disk work
//! may complete after the caller's deadline, but cannot expose partial proofs.
use crate::{
    crypto::{decode_hex, encode_hex},
    ots_config::OtsConfig,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use thiserror::Error;

pub const STAMP_PATH: &str = "/digest";
pub const MAX_PROOF_BYTES: usize = 1_048_576;
const MAX_CALENDAR_BYTES: usize = 10_000;
const MAX_DEPTH: usize = 256;
const MAX_STEPS: usize = 4096;
const MAX_MESSAGE: usize = 4096;
const MAX_ATTESTATIONS: usize = 64;
const MAX_REQUESTS: usize = 8;
const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OTSMethod {
    Bitcoin,
}
impl OTSMethod {
    pub fn as_str(&self) -> &'static str {
        "bitcoin"
    }
    pub fn tag(&self) -> u8 {
        0
    }
    pub fn from_tag(tag: u8) -> Result<Self, OTSError> {
        if tag == 0 {
            Ok(Self::Bitcoin)
        } else {
            Err(OTSError::Configuration(
                "unsupported attestation method tag".into(),
            ))
        }
    }
    pub fn parse(name: &str) -> Result<Self, OTSError> {
        if name.eq_ignore_ascii_case("bitcoin") {
            Ok(Self::Bitcoin)
        } else {
            Err(OTSError::Configuration(
                "only Bitcoin attestations are supported".into(),
            ))
        }
    }
}
impl std::fmt::Display for OTSMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OTSVResult {
    pub verified: bool,
    pub pending: bool,
    pub method: String,
    pub timestamp: Option<u64>,
    pub details: String,
}
impl OTSVResult {
    pub fn no_proof() -> Self {
        Self {
            verified: false,
            pending: false,
            method: "none".into(),
            timestamp: None,
            details: "No OpenTimestamps proof found".into(),
        }
    }
}
#[derive(Debug, Error)]
pub enum OTSError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OTS server returned HTTP {status}: {body}")]
    ServerStatus { status: u16, body: String },
    #[error("invalid proof format: {0}")]
    InvalidProof(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("proof file I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid OTS configuration: {0}")]
    Configuration(String),
    #[error("OTS stamp interval has not elapsed")]
    RateLimited,
    #[error("OTS operation deadline exceeded")]
    Timeout,
}
fn invalid(s: impl Into<String>) -> OTSError {
    OTSError::InvalidProof(s.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Attestation {
    Pending(String),
    Bitcoin(u32),
}
#[derive(Debug, Clone)]
enum Branch {
    Att(Attestation),
    Op(u8, Vec<u8>, Node),
}
#[derive(Debug, Clone)]
struct Node {
    message: Vec<u8>,
    branches: Vec<Branch>,
}
struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
    steps: usize,
    attestations: usize,
}
impl<'a> Parser<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], OTSError> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| invalid("length overflow"))?;
        let v = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated proof"))?;
        self.offset = end;
        Ok(v)
    }
    fn byte(&mut self) -> Result<u8, OTSError> {
        Ok(self.take(1)?[0])
    }
    fn uint(&mut self) -> Result<u32, OTSError> {
        let mut value = 0u32;
        for shift in (0..35).step_by(7) {
            let b = self.byte()?;
            if shift == 28 && b > 15 {
                return Err(invalid("integer overflow"));
            }
            value |= u32::from(b & 127) << shift;
            if b & 128 == 0 {
                if shift != 0 && b == 0 {
                    return Err(invalid("noncanonical integer"));
                }
                return Ok(value);
            }
        }
        Err(invalid("integer overflow"))
    }
    fn varbytes(&mut self, max: usize) -> Result<&'a [u8], OTSError> {
        let n = self.uint()? as usize;
        if n > max {
            return Err(invalid("field byte budget exceeded"));
        }
        self.take(n)
    }
    fn node(&mut self, message: Vec<u8>, depth: usize) -> Result<Node, OTSError> {
        if depth >= MAX_DEPTH || message.len() > MAX_MESSAGE {
            return Err(invalid("proof depth/message limit"));
        }
        let mut branches = Vec::new();
        let mut operations = std::collections::BTreeSet::new();
        loop {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Err(invalid("proof work limit"));
            }
            let first = self.byte()?;
            let more = first == 0xff;
            let tag = if more { self.byte()? } else { first };
            let branch = if tag == 0 {
                self.attestations += 1;
                if self.attestations > MAX_ATTESTATIONS {
                    return Err(invalid("too many attestations"));
                }
                let att_tag = self.take(8)?;
                let payload = self.varbytes(8192)?;
                let mut p = Parser {
                    bytes: payload,
                    offset: 0,
                    steps: 0,
                    attestations: 0,
                };
                let att = if att_tag == PENDING {
                    let uri = p.varbytes(1000)?;
                    if uri.is_empty()
                        || !uri
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._/:".contains(b))
                    {
                        return Err(invalid("invalid pending URI"));
                    }
                    let uri = std::str::from_utf8(uri)
                        .map_err(|_| invalid("invalid URI"))?
                        .to_owned();
                    let parsed =
                        reqwest::Url::parse(&uri).map_err(|_| invalid("invalid pending URI"))?;
                    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                        return Err(invalid("invalid pending URI scheme/host"));
                    }
                    Attestation::Pending(uri)
                } else if att_tag == BITCOIN {
                    if message.len() != 32 {
                        return Err(invalid("Bitcoin commitment must be 32 bytes"));
                    }
                    Attestation::Bitcoin(p.uint()?)
                } else {
                    return Err(invalid(
                        "unsupported attestation (only Bitcoin/pending supported)",
                    ));
                };
                if p.offset != payload.len() {
                    return Err(invalid("trailing attestation bytes"));
                }
                Branch::Att(att)
            } else {
                let arg: &'a [u8] = if tag == 0xf0 || tag == 0xf1 {
                    let a = self.varbytes(MAX_MESSAGE)?;
                    if a.is_empty() {
                        return Err(invalid("empty binary operation"));
                    }
                    a
                } else {
                    &[]
                };
                if !operations.insert((tag, arg)) {
                    return Err(invalid("duplicate operation"));
                }
                let result = operation(tag, arg, &message)?;
                Branch::Op(tag, arg.to_vec(), self.node(result, depth + 1)?)
            };
            branches.push(branch);
            if !more {
                break;
            }
        }
        Ok(Node { message, branches })
    }
}
fn operation(tag: u8, arg: &[u8], msg: &[u8]) -> Result<Vec<u8>, OTSError> {
    let result = match tag {
        0x02 => sha1::Sha1::digest(msg).to_vec(),
        0x03 => ripemd::Ripemd160::digest(msg).to_vec(),
        0x08 => Sha256::digest(msg).to_vec(),
        0x67 => sha3::Keccak256::digest(msg).to_vec(),
        0xf0 | 0xf1 => {
            if msg.len() + arg.len() > MAX_MESSAGE {
                return Err(invalid("operation message budget"));
            }
            let mut v = Vec::with_capacity(msg.len() + arg.len());
            if tag == 0xf0 {
                v.extend_from_slice(msg);
                v.extend_from_slice(arg);
            } else {
                v.extend_from_slice(arg);
                v.extend_from_slice(msg);
            }
            v
        }
        0xf2 => {
            let mut v = msg.to_vec();
            v.reverse();
            v
        }
        0xf3 => {
            if msg.len() > MAX_MESSAGE / 2 {
                return Err(invalid("hexlify message budget"));
            }
            encode_hex(msg).into_bytes()
        }
        _ => return Err(invalid("unsupported operation")),
    };
    Ok(result)
}
fn parse_tree(bytes: &[u8], digest: &[u8]) -> Result<Node, OTSError> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(invalid("proof byte budget"));
    }
    let mut p = Parser {
        bytes,
        offset: 0,
        steps: 0,
        attestations: 0,
    };
    let node = p.node(digest.to_vec(), 0)?;
    if p.offset != bytes.len() {
        return Err(invalid("trailing proof bytes"));
    }
    Ok(node)
}
fn parse_proof(bytes: &[u8], expected: Option<&[u8; 32]>) -> Result<Node, OTSError> {
    let header_len = MAGIC.len() + 34;
    if bytes.len() > MAX_PROOF_BYTES
        || bytes.len() < header_len
        || !bytes.starts_with(MAGIC)
        || bytes[MAGIC.len()..MAGIC.len() + 2] != [1, 8]
    {
        return Err(invalid("expected detached OTS v1 SHA256 proof"));
    }
    let digest = &bytes[MAGIC.len() + 2..header_len];
    if expected.is_some_and(|e| e.as_slice() != digest) {
        return Err(OTSError::VerificationFailed(
            "proof digest does not match content".into(),
        ));
    }
    parse_tree(&bytes[header_len..], digest)
}
fn uint(mut n: u32, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn varbytes(b: &[u8], out: &mut Vec<u8>) {
    uint(b.len() as u32, out);
    out.extend_from_slice(b);
}
fn serialize_node(node: &Node, out: &mut Vec<u8>) -> Result<(), OTSError> {
    for (i, branch) in node.branches.iter().enumerate() {
        if i + 1 < node.branches.len() {
            out.push(0xff);
        }
        match branch {
            Branch::Att(att) => {
                out.push(0);
                let mut payload = Vec::new();
                match att {
                    Attestation::Pending(uri) => {
                        out.extend_from_slice(&PENDING);
                        varbytes(uri.as_bytes(), &mut payload);
                    }
                    Attestation::Bitcoin(h) => {
                        out.extend_from_slice(&BITCOIN);
                        uint(*h, &mut payload);
                    }
                }
                varbytes(&payload, out);
            }
            Branch::Op(tag, arg, child) => {
                out.push(*tag);
                if *tag == 0xf0 || *tag == 0xf1 {
                    varbytes(arg, out);
                }
                serialize_node(child, out)?;
            }
        }
        if out.len() > MAX_PROOF_BYTES {
            return Err(invalid("serialized proof byte budget"));
        }
    }
    Ok(())
}
fn detached(node: &Node) -> Result<Vec<u8>, OTSError> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&[1, 8]);
    out.extend_from_slice(&node.message);
    serialize_node(node, &mut out)?;
    parse_proof(&out, None)?;
    Ok(out)
}
fn attestations<'a>(node: &'a Node, out: &mut Vec<(&'a [u8], &'a Attestation)>) {
    for b in &node.branches {
        match b {
            Branch::Att(a) => out.push((&node.message, a)),
            Branch::Op(_, _, n) => attestations(n, out),
        }
    }
}
fn endpoint(raw: &str) -> Result<String, OTSError> {
    let url = reqwest::Url::parse(raw).map_err(|e| OTSError::Configuration(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OTSError::Configuration(
            "endpoint must be an HTTP(S) base URL without credentials/query/fragment".into(),
        ));
    }
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() == "http" && !loopback {
        return Err(OTSError::Configuration(
            "HTTP endpoints are allowed only on explicit loopback hosts; use HTTPS".into(),
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

#[derive(Debug)]
pub struct OTSClient {
    client: reqwest::Client,
    server_url: String,
    explorer_url: String,
    min_interval: Duration,
    timeout: Duration,
    last_attempt: Mutex<Option<Instant>>,
    proof_dir: PathBuf,
}
impl OTSClient {
    pub fn new(method: OTSMethod) -> Result<Self, OTSError> {
        Self::from_config(&OtsConfig {
            enabled: true,
            method: method.as_str().into(),
            ..Default::default()
        })
    }
    pub fn from_config(cfg: &OtsConfig) -> Result<Self, OTSError> {
        cfg.validate()
            .map_err(|e| OTSError::Configuration(e.to_string()))?;
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(cfg.timeout())
                .connect_timeout(cfg.timeout())
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("steganographer/", env!("CARGO_PKG_VERSION")))
                .build()?,
            server_url: endpoint(&cfg.server_url)?,
            explorer_url: endpoint(&cfg.bitcoin_explorer_url)?,
            min_interval: cfg.interval(),
            timeout: cfg.timeout(),
            last_attempt: Mutex::new(None),
            proof_dir: cfg.proof_dir.clone().into(),
        })
    }
    pub fn with_server_url(mut self, url: impl Into<String>) -> Result<Self, OTSError> {
        self.server_url = endpoint(&url.into())?;
        Ok(self)
    }
    pub fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_interval = interval;
        self
    }
    pub fn with_proof_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.proof_dir = dir.into();
        self
    }
    pub fn method(&self) -> OTSMethod {
        OTSMethod::Bitcoin
    }
    pub fn proof_dir(&self) -> &Path {
        &self.proof_dir
    }
    pub fn compute_sha256_digest(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }
    pub fn can_stamp(&self) -> bool {
        self.last_attempt
            .lock()
            .is_ok_and(|v| v.is_none_or(|t| t.elapsed() >= self.min_interval))
    }
    fn admit(&self, force: bool) -> Result<(), OTSError> {
        let mut slot = self
            .last_attempt
            .lock()
            .map_err(|_| OTSError::ServiceUnavailable("stamp admission unavailable".into()))?;
        if !force && slot.is_some_and(|t| t.elapsed() < self.min_interval) {
            return Err(OTSError::RateLimited);
        }
        *slot = Some(Instant::now());
        Ok(())
    }
    /// Atomically reserve an attempt before I/O. Failed attempts also consume the interval.
    pub async fn stamp_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, OTSError> {
        self.admit(false)?;
        self.submit(digest).await
    }
    /// Explicit user-requested rate-limit override; still records the attempt.
    pub async fn stamp_digest_force(&self, digest: &[u8; 32]) -> Result<Vec<u8>, OTSError> {
        self.admit(true)?;
        self.submit(digest).await
    }
    async fn submit(&self, digest: &[u8; 32]) -> Result<Vec<u8>, OTSError> {
        tokio::time::timeout(self.timeout, async {
            let mut nonce = [0u8; 32];
            OsRng.try_fill_bytes(&mut nonce).map_err(|e| {
                OTSError::ServiceUnavailable(format!("cannot generate OTS blinding nonce: {e}"))
            })?;
            let appended = operation(0xf0, &nonce, digest)?;
            let commitment: [u8; 32] = Sha256::digest(&appended).into();
            let response = self
                .client
                .post(format!("{}{STAMP_PATH}", self.server_url))
                .header("Content-Type", "application/octet-stream")
                .header("Accept", "application/vnd.opentimestamps.v1")
                .body(commitment.to_vec())
                .send()
                .await?;
            let body = bounded_response(response, MAX_CALENDAR_BYTES).await?;
            let calendar = parse_tree(&body, &commitment)?;
            let node = Node {
                message: digest.to_vec(),
                branches: vec![Branch::Op(
                    0xf0,
                    nonce.to_vec(),
                    Node {
                        message: appended,
                        branches: vec![Branch::Op(0x08, Vec::new(), calendar)],
                    },
                )],
            };
            detached(&node)
        })
        .await
        .map_err(|_| OTSError::Timeout)?
    }
    pub async fn stamp_data(&self, data: &[u8]) -> Result<Vec<u8>, OTSError> {
        self.stamp_digest(&Self::compute_sha256_digest(data)).await
    }
    /// Upgrade only through the explicitly configured calendar, never an arbitrary proof URI.
    /// Returns a standard detached proof; publication never overwrites earlier evidence.
    pub async fn upgrade(&self, proof: &[u8], expected: &[u8; 32]) -> Result<Vec<u8>, OTSError> {
        tokio::time::timeout(self.timeout, self.upgrade_inner(proof, expected))
            .await
            .map_err(|_| OTSError::Timeout)?
    }
    async fn upgrade_inner(&self, proof: &[u8], expected: &[u8; 32]) -> Result<Vec<u8>, OTSError> {
        let mut node = parse_proof(proof, Some(expected))?;
        let mut pending = Vec::new();
        fn collect(node: &Node, base: &str, out: &mut Vec<Vec<u8>>) {
            for b in &node.branches {
                match b {
                    Branch::Att(Attestation::Pending(uri)) if uri.trim_end_matches('/') == base => {
                        if !out.contains(&node.message) {
                            out.push(node.message.clone());
                        }
                    }
                    Branch::Op(_, _, n) => collect(n, base, out),
                    _ => {}
                }
            }
        }
        collect(&node, &self.server_url, &mut pending);
        if pending.len() > MAX_REQUESTS {
            return Err(invalid("calendar request budget exceeded"));
        }
        for message in pending {
            let response = self
                .client
                .get(format!(
                    "{}/timestamp/{}",
                    self.server_url,
                    encode_hex(&message)
                ))
                .header("Accept", "application/vnd.opentimestamps.v1")
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                continue;
            }
            let bytes = bounded_response(response, MAX_CALENDAR_BYTES).await?;
            let upgraded = parse_tree(&bytes, &message)?;
            fn merge_branches(node: &mut Node, upgraded: &Node) {
                for branch in &upgraded.branches {
                    match branch {
                        Branch::Att(att) => {
                            if !node
                                .branches
                                .iter()
                                .any(|b| matches!(b, Branch::Att(a) if a == att))
                            {
                                node.branches.push(branch.clone());
                            }
                        }
                        Branch::Op(tag, arg, child) => {
                            if let Some(Branch::Op(_, _, existing)) = node
                                .branches
                                .iter_mut()
                                .find(|b| matches!(b, Branch::Op(t,a,_) if t == tag && a == arg))
                            {
                                merge_branches(existing, child);
                            } else {
                                node.branches.push(branch.clone());
                            }
                        }
                    }
                }
            }
            fn merge(node: &mut Node, message: &[u8], upgraded: &Node) {
                for b in &mut node.branches {
                    if let Branch::Op(_, _, n) = b {
                        merge(n, message, upgraded);
                    }
                }
                if node.message == message {
                    merge_branches(node, upgraded);
                }
            }
            merge(&mut node, &message, &upgraded);
        }
        detached(&node)
    }
    pub async fn verify(
        &self,
        proof: &[u8],
        expected_digest: &[u8; 32],
    ) -> Result<OTSVResult, OTSError> {
        self.verify_with_upgrade(proof, expected_digest)
            .await
            .map(|(result, _)| result)
    }
    /// Verify through the shared lifecycle, returning changed proof bytes for optional publication.
    ///
    /// Proofs carrying Bitcoin attestations skip calendar upgrades, including when historical
    /// pending branches remain. Every Bitcoin attestation still requires trusted explorer
    /// header verification. Pending-only proofs may upgrade through the configured calendar.
    /// Returned bytes preserve the original branches; callers publish them without replacing
    /// earlier receipts. `None` means the supplied proof was unchanged.
    pub async fn verify_with_upgrade(
        &self,
        proof: &[u8],
        expected_digest: &[u8; 32],
    ) -> Result<(OTSVResult, Option<Vec<u8>>), OTSError> {
        tokio::time::timeout(self.timeout, async {
            let original = parse_proof(proof, Some(expected_digest))?;
            let mut original_att = Vec::new();
            attestations(&original, &mut original_att);
            // Completed proofs need no calendar contact, but are not trusted until verified.
            if original_att
                .iter()
                .any(|(_, a)| matches!(a, Attestation::Bitcoin(_)))
            {
                return Ok((self.verify_node(&original).await?, None));
            }
            let upgraded = self.upgrade_inner(proof, expected_digest).await?;
            let node = parse_proof(&upgraded, Some(expected_digest))?;
            let result = self.verify_node(&node).await?;
            Ok((result, (upgraded != proof).then_some(upgraded)))
        })
        .await
        .map_err(|_| OTSError::Timeout)?
    }
    /// Check a locally upgraded proof without requesting the calendar again.
    /// Still performs Bitcoin header verification through the trusted explorer.
    pub async fn verify_attestations(
        &self,
        proof: &[u8],
        expected_digest: &[u8; 32],
    ) -> Result<OTSVResult, OTSError> {
        let node = parse_proof(proof, Some(expected_digest))?;
        tokio::time::timeout(self.timeout, self.verify_node(&node))
            .await
            .map_err(|_| OTSError::Timeout)?
    }
    async fn verify_node(&self, node: &Node) -> Result<OTSVResult, OTSError> {
        let mut all = Vec::new();
        attestations(node, &mut all);
        let mut timestamp = None;
        let mut requests = 0;
        let mut pending = false;
        for (message, att) in all {
            match att {
                Attestation::Pending(_) => pending = true,
                Attestation::Bitcoin(height) => {
                    requests += 1;
                    if requests > MAX_REQUESTS {
                        return Err(invalid("Bitcoin request budget exceeded"));
                    }
                    let t = self.verify_bitcoin(message, *height).await?;
                    timestamp = Some(timestamp.map_or(t, |old: u64| old.min(t)));
                }
            }
        }
        let verified = timestamp.is_some();
        Ok(OTSVResult {
            verified,
            pending: !verified && pending,
            method: "bitcoin".into(),
            timestamp,
            details: if verified {
                format!("Bitcoin header commitment verified using trusted Esplora height index {}; not independent full-node validation", self.explorer_url)
            } else {
                "Pending calendar commitment; not Bitcoin-confirmed".into()
            },
        })
    }
    async fn verify_bitcoin(&self, message: &[u8], height: u32) -> Result<u64, OTSError> {
        let hash = bounded_response(
            self.client
                .get(format!("{}/block-height/{height}", self.explorer_url))
                .send()
                .await?,
            128,
        )
        .await?;
        let hash = std::str::from_utf8(&hash)
            .map_err(|_| invalid("explorer block hash encoding"))?
            .trim();
        let hash_bytes = decode_hex(hash).map_err(|_| invalid("explorer block hash hex"))?;
        if hash_bytes.len() != 32 {
            return Err(invalid("explorer block hash length"));
        }
        let raw = bounded_response(
            self.client
                .get(format!(
                    "{}/block/{}/header",
                    self.explorer_url,
                    encode_hex(&hash_bytes)
                ))
                .send()
                .await?,
            256,
        )
        .await?;
        let raw = std::str::from_utf8(&raw)
            .map_err(|_| invalid("header encoding"))?
            .trim();
        let header = decode_hex(raw).map_err(|_| invalid("header hex"))?;
        validate_header(&header, &hash_bytes, message)
    }
    pub fn proof_path_for(&self, digest_hex: &str) -> Result<PathBuf, OTSError> {
        let digest = decode_hex(digest_hex)
            .map_err(|_| invalid("digest filename must be 64 hex characters"))?;
        if digest.len() != 32 {
            return Err(invalid("digest filename must be 64 hex characters"));
        }
        Ok(self.proof_dir.join(format!("{}.ots", encode_hex(&digest))))
    }
    pub async fn save_proof(&self, proof: &[u8], digest_hex: &str) -> Result<PathBuf, OTSError> {
        let path = self.proof_path_for(digest_hex)?;
        let digest: [u8; 32] = decode_hex(digest_hex)
            .map_err(|_| invalid("digest hex"))?
            .try_into()
            .map_err(|_| invalid("digest length"))?;
        parse_proof(proof, Some(&digest))?;
        self.save_proof_to(proof, &path).await
    }
    pub async fn save_proof_to(
        &self,
        proof: &[u8],
        output_path: &Path,
    ) -> Result<PathBuf, OTSError> {
        parse_proof(proof, None)?;
        let bytes = proof.to_vec();
        let path = output_path.to_path_buf();
        tokio::time::timeout(
            self.timeout,
            tokio::task::spawn_blocking(move || publish(&bytes, &path)),
        )
        .await
        .map_err(|_| OTSError::Timeout)?
        .map_err(|e| OTSError::ServiceUnavailable(e.to_string()))?
    }
    pub async fn load_proof(path: &Path) -> Result<Vec<u8>, OTSError> {
        let path = path.to_path_buf();
        tokio::time::timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || read_proof(&path)),
        )
        .await
        .map_err(|_| OTSError::Timeout)?
        .map_err(|e| OTSError::ServiceUnavailable(e.to_string()))?
    }
    /// Validate a cached proof's exact digest without contacting any service.
    pub fn validate_proof(proof: &[u8], expected: &[u8; 32]) -> Result<bool, OTSError> {
        let node = parse_proof(proof, Some(expected))?;
        let mut all = Vec::new();
        attestations(&node, &mut all);
        Ok(!all
            .iter()
            .any(|(_, a)| matches!(a, Attestation::Bitcoin(_))))
    }
}
async fn bounded_response(
    mut response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, OTSError> {
    let status = response.status();
    let budget = if status.is_success() { max } else { 1024 };
    if response.content_length().is_some_and(|n| n > budget as u64) {
        return Err(if status.is_success() {
            invalid("HTTP response byte budget exceeded")
        } else {
            OTSError::ServerStatus {
                status: status.as_u16(),
                body: "error response exceeds byte budget".into(),
            }
        });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > budget - bytes.len() {
            return Err(if status.is_success() {
                invalid("HTTP response byte budget exceeded")
            } else {
                OTSError::ServerStatus {
                    status: status.as_u16(),
                    body: "error response exceeds byte budget".into(),
                }
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(OTSError::ServerStatus {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    Ok(bytes)
}
fn validate_header(header: &[u8], expected_hash: &[u8], message: &[u8]) -> Result<u64, OTSError> {
    if header.len() != 80 || expected_hash.len() != 32 || message.len() != 32 {
        return Err(invalid("Bitcoin header/digest length"));
    }
    let mut hash = Sha256::digest(Sha256::digest(header)).to_vec();
    hash.reverse();
    if hash != expected_hash {
        return Err(OTSError::VerificationFailed(
            "Bitcoin header hash mismatch".into(),
        ));
    }
    if &header[36..68] != message {
        return Err(OTSError::VerificationFailed(
            "Bitcoin merkle commitment mismatch".into(),
        ));
    }
    // Bitcoin compact target, rejecting negative/zero/overflow and above-mainnet targets.
    let bits = u32::from_le_bytes(header[72..76].try_into().map_err(|_| invalid("bits"))?);
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007fffff;
    if bits & 0x00800000 != 0 || mantissa == 0 || exponent > 32 {
        return Err(invalid("Bitcoin difficulty target"));
    }
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        target[28..].copy_from_slice(&value.to_be_bytes());
    } else {
        let start = 32 - exponent;
        target[start..start + 3].copy_from_slice(&mantissa.to_be_bytes()[1..]);
    }
    let mut max_target = [0u8; 32];
    max_target[4] = 0xff;
    max_target[5] = 0xff;
    if target == [0u8; 32] || target > max_target || hash.as_slice() > target.as_slice() {
        return Err(OTSError::VerificationFailed(
            "Bitcoin proof of work invalid".into(),
        ));
    }
    Ok(u64::from(u32::from_le_bytes(
        header[68..72].try_into().map_err(|_| invalid("time"))?,
    )))
}
mod proof_io {
    use super::*;
    use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
    use cap_std::{
        ambient_authority,
        fs::{Dir, OpenOptions},
    };
    use std::ffi::{OsStr, OsString};
    fn directory(path: &Path, create: bool) -> Result<Dir, OTSError> {
        // The configured directory and its acquisition path are trusted.
        // Normal system /tmp and /var aliases are intentionally accepted.
        if create {
            std::fs::create_dir_all(path)?;
        }
        Ok(Dir::open_ambient_dir(path, ambient_authority())?)
    }
    fn parent(path: &Path) -> &Path {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
    }
    fn read_at(dir: &Dir, filename: &OsStr) -> Result<Vec<u8>, OTSError> {
        let before = dir.symlink_metadata(filename)?;
        if !before.is_file() || before.len() > MAX_PROOF_BYTES as u64 {
            return Err(invalid("proof must be a bounded regular file"));
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = dir.open_with(filename, &options)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_PROOF_BYTES as u64 {
            return Err(invalid("proof must be a bounded, single-link regular file"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_PROOF_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        parse_proof(&bytes, None)?;
        Ok(bytes)
    }
    pub(super) fn read(path: &Path) -> Result<Vec<u8>, OTSError> {
        let dir = directory(parent(path), false)?;
        read_at(
            &dir,
            path.file_name().ok_or_else(|| invalid("proof filename"))?,
        )
    }
    struct Temporary<'a> {
        dir: &'a Dir,
        name: OsString,
    }
    impl Drop for Temporary<'_> {
        fn drop(&mut self) {
            let _ = self.dir.remove_file(&self.name);
        }
    }
    pub(super) fn publish(bytes: &[u8], path: &Path) -> Result<PathBuf, OTSError> {
        let dir = directory(parent(path), true)?;
        let filename = path.file_name().ok_or_else(|| invalid("proof filename"))?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut created = None;
        for _ in 0..16 {
            let name = OsString::from(format!(".ots-{:032x}.tmp", rand::random::<u128>()));
            match dir.open_with(&name, &options) {
                Ok(file) => {
                    created = Some((Temporary { dir: &dir, name }, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let (temporary, mut file) = created.ok_or_else(|| {
            OTSError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "cannot reserve proof temporary",
            ))
        })?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // A hard-link publishes a fully written regular file atomically and
        // never replaces or follows an existing final symlink/hardlink/FIFO.
        // cap-std provides this operation on both Unix and Windows.
        match dir.hard_link(&temporary.name, &dir, filename) {
            Ok(()) => Ok(path.to_path_buf()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_at(&dir, filename).is_ok_and(|old| old == bytes) {
                    return Ok(path.to_path_buf());
                }
                let mut alternate = filename.to_os_string();
                alternate.push(format!(
                    ".{}.ots",
                    encode_hex(&OTSClient::compute_sha256_digest(bytes))
                ));
                let alternate_path = parent(path).join(&alternate);
                match dir.hard_link(&temporary.name, &dir, &alternate) {
                    Ok(()) => Ok(alternate_path),
                    Err(other)
                        if other.kind() == std::io::ErrorKind::AlreadyExists
                            && read_at(&dir, &alternate).is_ok_and(|old| old == bytes) =>
                    {
                        Ok(alternate_path)
                    }
                    Err(other) => Err(other.into()),
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}
fn read_proof(path: &Path) -> Result<Vec<u8>, OTSError> {
    proof_io::read(path)
}
fn publish(bytes: &[u8], path: &Path) -> Result<PathBuf, OTSError> {
    proof_io::publish(bytes, path)
}
