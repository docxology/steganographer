//! Command schema shared by the binary, completions, and manual pages.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "steganographer",
    about = "Real-time steganographic watermarking for video and audio streams",
    version,
    propagate_version = true,
    long_about = "Steganographer embeds cryptographic signatures and visible watermarks into \
                   live video/audio streams using LSB steganography, spread-spectrum modulation, \
                   DCT-domain embedding, and text overlays. Supports GStreamer pipelines for \
                   real-time processing and offline file encoding/verification. \
                   BLAKE3/SHA-256/SHA-3 hashing + Ed25519/secp256k1 signing. \
                   Optional ChaCha20-Poly1305 payload encryption, Reed-Solomon error correction, \
                   and multi-frame signature spreading."
)]
pub struct Cli {
    /// Path to configuration file (TOML)
    #[arg(long, short, global = true, default_value = "config/example.toml")]
    pub(crate) config: String,

    /// Log verbosity level
    #[arg(long, short, global = true, default_value = "info")]
    pub(crate) log_level: String,

    /// Suppress all output except final result (for scripting)
    #[arg(long, short, global = true)]
    pub(crate) quiet: bool,

    /// Machine-readable output schema version for --format json/jsonl.
    /// v1 wraps machine payloads in the steganographer.cli/v1 envelope.
    #[arg(long, global = true, default_value = "v1")]
    pub(crate) schema_version: String,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Run live video pipeline: capture → steganography → virtual device
    #[cfg(feature = "gst")]
    Video {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        sink: Option<String>,
        #[arg(long)]
        max_frames: Option<u64>,
        /// Path to signing key file (hex-encoded 32-byte Ed25519 private key).
        /// If omitted, an ephemeral keypair is generated per run.
        #[arg(long)]
        signing_key: Option<String>,
    },

    /// Run live audio pipeline: capture → steganography → virtual device
    #[cfg(feature = "gst")]
    Audio {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        sink: Option<String>,
        #[arg(long)]
        max_buffers: Option<u64>,
        /// Path to signing key file (hex-encoded 32-byte Ed25519 private key).
        /// If omitted, an ephemeral keypair is generated per run.
        #[arg(long)]
        signing_key: Option<String>,
    },

    /// Encode steganographic data into a file (offline)
    Encode {
        #[arg(long, short)]
        input: String,
        #[arg(long, short)]
        output: String,
        /// Type of steganography: "lsb_video", "lsb_audio", "spread_spectrum_video", "dct_video"
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// LSB bits per sample/pixel (1-4)
        #[arg(long, default_value = "1")]
        bits: u8,
        /// Output format: "plain" (human-readable) or "json" (machine-readable)
        #[arg(long, default_value = "plain")]
        format: String,
        /// Input file format: "raw_rgb", "raw_s16le", "png", "wav" (auto-detected if omitted)
        #[arg(long)]
        input_format: Option<String>,
        /// Width for headerless raw RGB input (requires --height)
        #[arg(long)]
        width: Option<u32>,
        /// Height for headerless raw RGB input (requires --width)
        #[arg(long)]
        height: Option<u32>,
        /// Enable payload encryption (ChaCha20-Poly1305)
        #[arg(long)]
        encrypt: bool,
        /// Encryption key (hex-encoded 32 bytes) for payload encryption
        #[arg(long)]
        encryption_key: Option<String>,
        /// Path to encryption key file
        #[arg(long)]
        encryption_key_file: Option<String>,
        /// Password for a password-derived (Argon2id) encryption key;
        /// mutually exclusive with --encryption-key/--encryption-key-file
        #[arg(long, conflicts_with_all = ["encryption_key", "encryption_key_file"])]
        password: Option<String>,
        /// Path to a password file for password-derived encryption;
        /// mutually exclusive with --encryption-key/--encryption-key-file
        #[arg(long, conflicts_with_all = ["encryption_key", "encryption_key_file"])]
        password_file: Option<String>,
        /// Embedding key (hex-encoded, 32 bytes) for keyed audio/spread-spectrum placement
        #[arg(long)]
        embedding_key: Option<String>,
        /// Path to a hex-encoded 32-byte embedding key file
        #[arg(long)]
        embedding_key_file: Option<String>,
        /// Enable Reed-Solomon error correction
        #[arg(long)]
        ecc: bool,
        /// Number of Reed-Solomon parity symbols (default: 4)
        #[arg(long, default_value = "4")]
        ecc_parity: usize,
        /// DEFLATE-compress a generic packet payload before embedding (opt-in)
        #[arg(long)]
        compress: bool,
        /// Multi-frame spreading: spread one signature across N frames (1 = no spreading)
        #[arg(long, default_value = "1")]
        spread: u32,
        /// Hash algorithm: "blake3" (default), "sha256", "sha3-256"
        #[arg(long)]
        hash_algorithm: Option<String>,
        /// Path to signing key file (hex-encoded 32-byte Ed25519 private key)
        #[arg(long)]
        signing_key: Option<String>,
        /// Batch mode: process all files in the input directory
        #[arg(long)]
        dir: bool,
        /// Embed an arbitrary file in the opt-in generic packet v1 alpha
        #[arg(long, conflicts_with = "payload_text")]
        payload_file: Option<String>,
        /// Embed UTF-8 text in the opt-in generic packet v1 alpha
        #[arg(long, conflicts_with = "payload_file")]
        payload_text: Option<String>,
        /// Public MIME type for a generic packet payload
        #[arg(long)]
        mime_type: Option<String>,
        /// Safe display filename for a generic packet payload
        #[arg(long)]
        filename: Option<String>,
        /// Skip the post-write re-read verification of a generic packet carrier
        #[arg(long)]
        no_verify_write: bool,
    },

    /// Decode an opt-in generic packet payload from a carrier
    Decode {
        #[arg(long, short)]
        input: String,
        #[arg(long, short)]
        output: String,
        /// Generic carrier kernel: "lsb_video" or "lsb_audio"
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// LSB bits per unit: "auto" or 1-4
        #[arg(long, default_value = "auto")]
        bits: String,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
        /// Input format: raw_rgb, raw_s16le, png/image, or wav (auto-detected if omitted)
        #[arg(long)]
        input_format: Option<String>,
        /// Replace an existing decoded payload output
        #[arg(long)]
        force: bool,
        /// Decrypt an AEAD-encrypted packet payload (ChaCha20-Poly1305)
        #[arg(long)]
        decrypt: bool,
        /// Decryption key (hex-encoded 32 bytes)
        #[arg(long)]
        decryption_key: Option<String>,
        /// Path to decryption key file
        #[arg(long)]
        decryption_key_file: Option<String>,
        /// Password for a password-derived (Argon2id) decryption key;
        /// mutually exclusive with --decryption-key/--decryption-key-file
        #[arg(long, conflicts_with_all = ["decryption_key", "decryption_key_file"])]
        password: Option<String>,
        /// Path to a password file for password-derived decryption;
        /// mutually exclusive with --decryption-key/--decryption-key-file
        #[arg(long, conflicts_with_all = ["decryption_key", "decryption_key_file"])]
        password_file: Option<String>,
        /// Embedding key (hex-encoded 32 bytes) for keyed placement
        #[arg(long)]
        embedding_key: Option<String>,
        /// Path to embedding key file for keyed placement
        #[arg(long)]
        embedding_key_file: Option<String>,
        /// Require this Ed25519 public key for a signed packet (hex)
        #[arg(long)]
        trusted_signer: Option<String>,
        /// Additional revoked keys JSON; omitted uses keys/revoked.json when present
        #[arg(long)]
        revoked_list: Option<String>,
    },

    /// Verify steganographic signatures in a media file
    Verify {
        #[arg(long, short)]
        input: String,
        /// Public key (hex-encoded) for signature verification
        #[arg(long)]
        public_key: Option<String>,
        /// Type of steganography to verify: "lsb_video", "lsb_audio", "spread_spectrum_video", "dct_video"
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// Embedding key (hex-encoded, 32 bytes) for audio/spread-spectrum extraction
        #[arg(long)]
        embedding_key: Option<String>,
        /// Path to a hex-encoded 32-byte embedding key file
        #[arg(long)]
        embedding_key_file: Option<String>,
        /// LSB bits per sample/pixel: "auto" or 1-4
        #[arg(long, default_value = "auto")]
        bits: String,
        /// Output format: "plain" (human-readable) or "json" (machine-readable)
        #[arg(long, default_value = "plain")]
        format: String,
        /// Input file format: "raw_rgb", "raw_s16le", "png", "wav" (auto-detected if omitted)
        #[arg(long)]
        input_format: Option<String>,
        /// Width for headerless raw RGB input (requires --height)
        #[arg(long)]
        width: Option<u32>,
        /// Height for headerless raw RGB input (requires --width)
        #[arg(long)]
        height: Option<u32>,
        /// Enable payload decryption (ChaCha20-Poly1305)
        #[arg(long)]
        decrypt: bool,
        /// Decryption key (hex-encoded 32 bytes)
        #[arg(long)]
        decryption_key: Option<String>,
        /// Path to decryption key file
        #[arg(long)]
        decryption_key_file: Option<String>,
        /// Enable Reed-Solomon error correction during extraction
        #[arg(long)]
        ecc: bool,
        /// Number of Reed-Solomon parity symbols (default: 4)
        #[arg(long, default_value = "4")]
        ecc_parity: usize,
        /// Multi-frame spreading: signature was spread across N frames
        #[arg(long, default_value = "1")]
        spread: u32,
        /// Hash algorithm: "blake3" (default), "sha256", "sha3-256"
        #[arg(long)]
        hash_algorithm: Option<String>,
        /// Additional revoked keys JSON; omitted uses keys/revoked.json when present
        #[arg(long)]
        revoked_list: Option<String>,
        /// Signed frame/chunk index used by keyed legacy audio extraction
        #[arg(long, default_value = "0")]
        frame_index: u64,
    },

    /// Extract a generic packet payload from a carrier (lsb_video/lsb_audio)
    Extract {
        #[arg(long, short)]
        input: String,
        #[arg(long, short)]
        output: String,
        /// Carrier kernel (WAV infers lsb_audio; raw defaults to lsb_video)
        #[arg(long)]
        stego_type: Option<String>,
        #[arg(long)]
        input_format: Option<String>,
        /// Embedding key for keyed placement (hex)
        #[arg(long)]
        embedding_key: Option<String>,
        #[arg(long)]
        embedding_key_file: Option<String>,
        /// Decryption key for encrypted packets (hex)
        #[arg(long = "decryption-key", value_name = "DECRYPTION_KEY")]
        encryption_key: Option<String>,
        #[arg(long = "decryption-key-file", value_name = "DECRYPTION_KEY_FILE")]
        encryption_key_file: Option<String>,
        /// Require this Ed25519 public key for a signed packet (hex)
        #[arg(long)]
        trusted_signer: Option<String>,
        /// Additional revoked keys JSON; omitted uses keys/revoked.json when present
        #[arg(long)]
        revoked_list: Option<String>,
        /// LSB bits per unit: "auto" or 1-4
        #[arg(long, default_value = "auto")]
        bits: String,
        /// Replace an existing payload output
        #[arg(long)]
        force: bool,
        /// Password for password-derived packet decoding (Argon2id)
        #[arg(long)]
        password: Option<String>,
        /// Path to a password file for password-derived packet decoding
        #[arg(long)]
        password_file: Option<String>,
        /// Output format: "plain" (human-readable) or "json" (envelope-wrapped)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Generate a new Ed25519 signing key pair
    Keygen {
        #[arg(long, short, default_value = "steganographer")]
        output: String,
        /// Output format: "plain" (human-readable) or "json" (envelope-wrapped)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Report steganographic capacity of a media file
    Info {
        #[arg(long, short)]
        input: String,
        /// Type of steganography to report capacity for
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// LSB bits per sample/pixel (1-4)
        #[arg(long, default_value = "1")]
        bits: u8,
        /// Output format: "plain" (human-readable) or "json" (machine-readable)
        #[arg(long, default_value = "plain")]
        format: String,
        /// Width for headerless raw RGB input (requires --height)
        #[arg(long)]
        width: Option<u32>,
        /// Height for headerless raw RGB input (requires --width)
        #[arg(long)]
        height: Option<u32>,
        /// Embedding key (hex-encoded, 32 bytes) to report keyed-placement capacity
        #[arg(long)]
        embedding_key: Option<String>,
    },

    /// Analyze a file for steganographic artifacts
    Analyze {
        #[arg(long, short)]
        input: String,
        /// Analysis type: "combined" (default), "chi_squared", "sample_pairs", or "rs"
        #[arg(long, default_value = "combined")]
        analysis_type: String,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Bounded forensic scan of a file or directory (structural + statistical detectors)
    Scan {
        #[arg(long, short)]
        input: String,
        /// Maximum directory depth (0 = the given directory's files only)
        #[arg(long, default_value = "8")]
        max_depth: u32,
        /// Maximum number of files to scan
        #[arg(long, default_value = "10000")]
        max_files: usize,
        /// Maximum bytes read per file (larger files are truncated)
        #[arg(long, default_value = "67108864")]
        max_bytes: usize,
        /// Output format: "plain", "json", or "jsonl"
        #[arg(long, default_value = "plain")]
        format: String,
        /// Reject the input when it is a symlink (symlinks are never followed
        /// by scan); pass this flag to scan the link target anyway
        #[arg(long)]
        follow_input_symlink: bool,
        /// Apply a named `[profiles.<name>]` profile from the config file
        /// (unknown profiles are a usage error)
        #[arg(long)]
        profile: Option<String>,
    },

    /// Derive keys (signing, encryption, embedding) from a master secret
    /// (high-entropy BLAKE3 KDF) or a human-chosen password (Argon2id)
    Derive {
        /// Master secret (hex-encoded, any length).
        /// WARNING: this is visible in shell history and `ps` output.
        /// Prefer --master-secret-file for interactive use.
        #[arg(long)]
        master_secret: Option<String>,
        /// Read master secret from a file (hex-encoded). Safer than --master-secret.
        #[arg(long)]
        master_secret_file: Option<String>,
        /// Read master secret from stdin (hex-encoded). Use `-` as the value.
        #[arg(long)]
        master_secret_stdin: bool,
        /// Derive from a human-chosen password via Argon2id (memory-hard KDF).
        /// WARNING: visible in shell history and `ps` output.
        /// Prefer --password-file for interactive use.
        #[arg(long)]
        password: Option<String>,
        /// Read the password from a file (raw bytes, trailing newline trimmed).
        #[arg(long)]
        password_file: Option<String>,
        /// Read the password from stdin (raw bytes, trailing newline trimmed).
        #[arg(long)]
        password_stdin: bool,
        /// Hex-encoded Argon2id salt (at least 16 bytes). Generated and printed if omitted.
        #[arg(long)]
        salt: Option<String>,
        /// Argon2id memory cost in KiB (default 19456 = 19 MiB).
        #[arg(long, default_value_t = steganographer_core::password::RECOMMENDED_MEMORY_KIB)]
        argon2_memory: u32,
        /// Argon2id iteration count (default 2).
        #[arg(long, default_value_t = steganographer_core::password::RECOMMENDED_ITERATIONS)]
        argon2_iterations: u32,
        /// Argon2id parallelism / lane count (default 1).
        #[arg(long, default_value_t = 1)]
        argon2_parallelism: u32,
        /// Output directory for derived keys
        #[arg(long, short, default_value = "keys")]
        output: String,
        /// Output format: "plain" (human-readable) or "json" (envelope-wrapped)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Launch the live round-trip verification dashboard (web GUI)
    Dashboard {
        #[arg(long, short, default_value = "8080")]
        port: u16,
        /// Dashboard signing backend: "ed25519" only
        #[arg(long, default_value = "ed25519")]
        backend: String,
        /// Bind address: "127.0.0.1" (default, local-only) or "0.0.0.0" (all interfaces)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Auth token for mutating API endpoints (POST /api/config, POST /api/metrics/reset).
        /// If set, clients must send `Authorization: Bearer <token>`. If omitted, auth is disabled.
        #[arg(long)]
        auth_token: Option<String>,
        /// Transport policy for the dashboard client: "auto" (try WebRTC,
        /// fall back to WebSocket on failure), "websocket", or "webrtc".
        /// The server advertises this default; the browser can still override
        /// per-session via ?transport= and the settings toggle.
        #[arg(long, default_value = "auto")]
        transport: String,
        /// ICE server URL for WebRTC (repeatable), e.g.
        /// "stun:stun.l.google.com:19302" or "turn:user:cred@host:port".
        /// Empty by default (loopback host candidates only). Unsupported
        /// schemes and TURN without credentials are warned and skipped.
        #[arg(long = "ice-server")]
        ice_server: Vec<String>,
    },

    /// Revoke a signing key (add to revoked-keys list)
    Revoke {
        /// Public key to revoke (hex-encoded, 32 bytes)
        #[arg(long)]
        public_key: String,
        /// Path to the revoked-keys file (default: keys/revoked.json)
        #[arg(long, short, default_value = "keys/revoked.json")]
        output: String,
        /// Output format: "plain" (human-readable) or "json" (envelope-wrapped)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Validate a TOML configuration file without running any pipeline
    Config {
        #[arg(default_value = "check")]
        action: String,
        /// Output format: "plain" (human-readable) or "json" (envelope-wrapped)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Standard OpenTimestamps proofs for SHA-256 file commitments
    Ots {
        #[command(subcommand)]
        action: OtsAction,
    },
}

/// Subcommands for `steganographer ots`.
#[derive(Subcommand)]
pub(crate) enum OtsAction {
    /// Submit a nonce-blinded SHA-256 file commitment to a calendar
    Stamp {
        #[arg(long, short)]
        input: String,
        /// Directory for .ots proof files (default: from config or ./ots_proofs/)
        #[arg(long)]
        output_dir: Option<String>,
        /// Attestation method: "bitcoin" only
        #[arg(long)]
        method: Option<String>,
        /// Override the submission rate limit; existing proofs are never overwritten
        #[arg(long)]
        force: bool,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Verify an OpenTimestamps proof for a file
    Verify {
        #[arg(long, short)]
        input: String,
        /// Proof path (default: configured proof directory / SHA256(input).ots)
        #[arg(long)]
        proof: Option<String>,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
    },
}
