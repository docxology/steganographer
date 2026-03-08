//! Audio buffer types and steganography trait.

use crate::crypto::SignaturePayload;

/// A mutable reference to an audio buffer's raw PCM samples.
pub struct AudioBuffer<'a> {
    /// Number of audio channels (1 = mono, 2 = stereo, etc.)
    pub channels: u16,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Interleaved 16-bit PCM samples
    pub samples: &'a mut [i16],
    /// Frame index (used for keyed embedding)
    pub frame_index: u64,
}

impl<'a> AudioBuffer<'a> {
    /// Total number of samples across all channels.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Duration in seconds.
    pub fn duration_secs(&self) -> f64 {
        if self.sample_rate == 0 || self.channels == 0 {
            return 0.0;
        }
        self.samples.len() as f64 / (self.sample_rate as f64 * self.channels as f64)
    }
}

/// Trait for audio steganography modules.
///
/// Implementors embed data into or extract data from audio buffers.
pub trait AudioStegoModule: Send {
    /// Embed a signature payload into an audio buffer.
    fn embed(
        &mut self,
        buf: &mut AudioBuffer,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()>;

    /// Extract a signature payload from an audio buffer.
    fn extract(&self, buf: &AudioBuffer) -> anyhow::Result<Option<SignaturePayload>>;
}
