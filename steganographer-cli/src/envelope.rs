//! SUR-003: the `steganographer.cli/v1` JSON envelope and the finalized
//! exit-code contract.
//!
//! Every command's `--format json` output is wrapped in a common envelope
//! (see `docs/plans/steganography-platform/04-product-surfaces.md`):
//!
//! ```json
//! {
//!   "schema": "steganographer.cli/v1",
//!   "command": "scan",
//!   "status": "success",
//!   "result": {},
//!   "warnings": [],
//!   "errors": [],
//!   "timing": {},
//!   "tool": { "name": "steganographer", "version": "..." }
//! }
//! ```
//!
//! `status` is `success`, `error`, or `partial` (`partial` = a scan whose
//! result was truncated by a resource limit and is therefore inconclusive).
//! Error `code` values are stable snake_case strings. Secret/key/password
//! values are never serialized — the underlying per-command result structs
//! keep their `skip_serializing` rules and the envelope only wraps them.
//!
//! The finalized exit-code table (supersedes the 2026-09-20 contract):
//!
//! | Code | Meaning |
//! | ---: | --- |
//! | 0 | Success (verify valid/not_verified/extracted; scan clean) |
//! | 1 | User/configuration/format error (unknown args, bad flag values, config errors) |
//! | 2 | Packet not found / decode unavailable |
//! | 3 | Authentication/signature verification failed |
//! | 4 | Scan findings meet the caller-selected failure threshold |
//! | 5 | Resource limit caused an inconclusive scan result (truncated, no findings) |
//! | 6 | Internal/runtime error (unexpected I/O, internal failures) |

use serde::Serialize;
use std::sync::Mutex;

/// Envelope schema identifier for machine-readable output.
pub const SCHEMA: &str = "steganographer.cli/v1";

// ─── Stable error codes ─────────────────────────────────────────────

/// User/configuration/format error (exit 1).
pub const USAGE_ERROR: &str = "usage_error";
/// No valid generic packet or media signature found (exit 2).
pub const PACKET_NOT_FOUND: &str = "packet_not_found";
/// Signature verification failed (exit 3).
pub const VERIFICATION_FAILED: &str = "verification_failed";
/// A per-file error collected during a scan (recorded in the scan report).
pub const SCAN_ERROR: &str = "scan_error";
/// Internal/runtime error (exit 6).
pub const INTERNAL_ERROR: &str = "internal_error";

/// One stable-coded error in the envelope's `errors` array.
#[derive(Debug, Serialize)]
pub struct EnvelopeError {
    pub code: String,
    pub message: String,
}

/// Identity of the producing binary.
#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
}

/// The `steganographer.cli/v1` output envelope.
#[derive(Debug, Serialize)]
pub struct Envelope {
    pub schema: &'static str,
    pub command: String,
    /// `success`, `error`, or `partial` (scan truncated → inconclusive).
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    pub warnings: Vec<String>,
    pub errors: Vec<EnvelopeError>,
    pub timing: serde_json::Value,
    pub tool: ToolInfo,
}

/// Success envelope wrapping the command's existing JSON payload.
pub fn success(command: &str, result: serde_json::Value) -> Envelope {
    Envelope {
        schema: SCHEMA,
        command: command.to_string(),
        status: "success",
        result: Some(result),
        warnings: Vec::new(),
        errors: Vec::new(),
        timing: serde_json::json!({}),
        tool: tool_info(),
    }
}

/// `partial` envelope: the operation completed but is inconclusive
/// (currently only scans truncated by a resource limit).
pub fn partial(command: &str, result: serde_json::Value, warnings: Vec<String>) -> Envelope {
    let mut envelope = success(command, result);
    envelope.status = "partial";
    envelope.warnings = warnings;
    envelope
}

/// Error envelope without a payload.
pub fn error(command: &str, code: &str, message: &str) -> Envelope {
    error_with_result(command, code, message, None)
}

/// Error envelope that still carries the command's result payload
/// (e.g. a `verify` run whose signature status is `invalid`).
pub fn error_with_result(
    command: &str,
    code: &str,
    message: &str,
    result: Option<serde_json::Value>,
) -> Envelope {
    Envelope {
        schema: SCHEMA,
        command: command.to_string(),
        status: "error",
        result,
        warnings: Vec::new(),
        errors: vec![EnvelopeError {
            code: code.to_string(),
            message: message.to_string(),
        }],
        timing: serde_json::json!({}),
        tool: tool_info(),
    }
}

fn tool_info() -> ToolInfo {
    ToolInfo {
        name: "steganographer",
        version: env!("CARGO_PKG_VERSION"),
    }
}

/// Print the envelope as the single pretty JSON payload on stdout.
pub fn print(envelope: &Envelope) {
    match serde_json::to_string_pretty(envelope) {
        Ok(document) => println!("{document}"),
        // Serialization of the envelope cannot fail in practice (plain
        // string/value fields only); fall back to the raw error text.
        Err(e) => eprintln!("Error: envelope serialization failed: {e}"),
    }
}

// ─── JSON-mode context for the central error path ───────────────────

/// The subcommand currently running with `--format json`/`jsonl`, so the
/// central error handler can emit an error envelope on stdout. Commands
/// activate it right before dispatch; it is process-global because the CLI
/// runs exactly one subcommand per process.
static JSON_COMMAND: Mutex<Option<String>> = Mutex::new(None);

/// Record that `command` runs in JSON mode: its failures must surface as an
/// error envelope on stdout, not as bare stderr text.
pub fn activate_json_mode(command: &str) {
    if let Ok(mut slot) = JSON_COMMAND.lock() {
        *slot = Some(command.to_string());
    }
}

/// The command activated for JSON mode, if any.
pub fn current_json_command() -> Option<String> {
    JSON_COMMAND.lock().ok().and_then(|slot| slot.clone())
}

/// Explicit authentication failure, kept typed through anyhow contexts.
#[derive(Debug)]
pub(crate) struct AuthenticationError(pub String);

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AuthenticationError {}

/// Invalid caller input, even when an underlying I/O error is retained.
#[derive(Debug)]
pub(crate) struct UsageError(pub String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

/// The command already emitted an evidence-bearing partial result.
#[derive(Debug)]
pub(crate) struct InconclusiveError;

impl std::fmt::Display for InconclusiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("analysis is inconclusive")
    }
}

impl std::error::Error for InconclusiveError {}
// ─── Exit-code classification ───────────────────────────────────────

/// Classify a terminal error into `(exit code, stable error code)` per the
/// finalized table:
///
/// - the packet-not-found message contract maps to exit 2;
/// - unexpected I/O and internal failures map to exit 6 (`internal_error`);
/// - everything else is a user/configuration/format error (exit 1).
///
/// I/O failures are detected both structurally (`std::io::Error` /
/// `serde_json::Error` in the anyhow chain) and by the stable phrasing of
/// mapped `map_err` messages, so wrapped failures classify identically.
pub fn classify_exit(message: &str, error: Option<&anyhow::Error>) -> (i32, &'static str) {
    if let Some(error) = error {
        if error.downcast_ref::<UsageError>().is_some() {
            return (1, USAGE_ERROR);
        }
        if error.downcast_ref::<AuthenticationError>().is_some() {
            return (3, VERIFICATION_FAILED);
        }
        for cause in error.chain() {
            if cause.downcast_ref::<InconclusiveError>().is_some() {
                return (5, "inconclusive");
            }
            if let Some(ots) = cause.downcast_ref::<steganographer_core::OTSError>() {
                use steganographer_core::OTSError;
                return match ots {
                    OTSError::InvalidProof(_) | OTSError::VerificationFailed(_) => {
                        (3, VERIFICATION_FAILED)
                    }
                    OTSError::Configuration(_) => (1, USAGE_ERROR),
                    _ => (6, INTERNAL_ERROR),
                };
            }
            if cause.downcast_ref::<AuthenticationError>().is_some()
                || cause
                    .downcast_ref::<steganographer_core::revocation::RevokedKey>()
                    .is_some()
            {
                return (3, VERIFICATION_FAILED);
            }
            if let Some(transform) =
                cause.downcast_ref::<steganographer_core::transforms::TransformError>()
            {
                use steganographer_core::transforms::TransformError;
                if matches!(
                    transform,
                    TransformError::SignatureInvalid
                        | TransformError::DecryptionFailed(_)
                        | TransformError::DigestMismatch
                        | TransformError::LengthMismatch { .. }
                        | TransformError::ErrorCorrectionFailed(_)
                ) {
                    return (3, VERIFICATION_FAILED);
                }
            }
            if let Some(packet) = cause.downcast_ref::<steganographer_core::packet::PacketError>() {
                use steganographer_core::packet::PacketError;
                if matches!(
                    packet,
                    PacketError::EnvelopeChecksum
                        | PacketError::DigestMismatch
                        | PacketError::BodyLengthMismatch
                        | PacketError::Truncated { .. }
                        | PacketError::NonCanonicalOrder { .. }
                        | PacketError::DuplicateField { .. }
                        | PacketError::MissingField { .. }
                        | PacketError::InvalidField { .. }
                        | PacketError::InvalidUtf8 { .. }
                ) {
                    return (3, VERIFICATION_FAILED);
                }
            }
        }
    }
    if error.is_some_and(|error| {
        error.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<steganographer_core::CarrierError>(),
                Some(steganographer_core::CarrierError::NoPacket)
            )
        })
    }) {
        return (2, PACKET_NOT_FOUND);
    }
    if is_runtime_failure(message, error) {
        return (6, INTERNAL_ERROR);
    }
    (1, USAGE_ERROR)
}

/// Runtime/internal indicators: I/O errors in the anyhow chain, JSON
/// (de)serialization failures, and the I/O phrasings that survive
/// `map_err`-wrapping.
fn is_runtime_failure(message: &str, error: Option<&anyhow::Error>) -> bool {
    if let Some(error) = error {
        for cause in error.chain() {
            if cause.downcast_ref::<std::io::Error>().is_some()
                || cause.downcast_ref::<serde_json::Error>().is_some()
            {
                return true;
            }
        }
    }
    const RUNTIME_PHRASES: [&str; 4] = [
        "os error",
        "Cannot read ",
        "Cannot write ",
        "Failed to write ",
    ];
    RUNTIME_PHRASES
        .iter()
        .any(|phrase| message.contains(phrase))
}

/// Report an error envelope on stdout (JSON mode) and terminate with the
/// classified exit code.
pub fn fail_json(command: &str, code: &str, message: &str, exit_code: i32) -> ! {
    print(&error(command, code, message));
    eprintln!("Error: {message}");
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_authentication_survives_context() {
        let error =
            anyhow::Error::new(steganographer_core::transforms::TransformError::SignatureInvalid)
                .context("packet decode failed");
        assert_eq!(
            classify_exit(&error.to_string(), Some(&error)),
            (3, VERIFICATION_FAILED)
        );
        let error = anyhow::Error::new(steganographer_core::OTSError::InvalidProof(
            "digest mismatch".into(),
        ))
        .context("timestamp verification");
        assert_eq!(
            classify_exit(&error.to_string(), Some(&error)),
            (3, VERIFICATION_FAILED)
        );
    }

    #[test]
    fn resource_limits_and_runtime_errors_are_not_absence() {
        let error = anyhow::Error::new(steganographer_core::packet::PacketError::LimitExceeded {
            what: "body",
            actual: 2,
            maximum: 1,
        });
        assert_eq!(
            classify_exit(&error.to_string(), Some(&error)),
            (1, USAGE_ERROR)
        );
        let error = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(
            classify_exit(&error.to_string(), Some(&error)),
            (6, INTERNAL_ERROR)
        );
    }
}
