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
    /// Validate interleaved S16 sample geometry before processing.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.channels > 0, "Audio channels must be positive");
        anyhow::ensure!(self.sample_rate > 0, "Audio sample rate must be positive");
        anyhow::ensure!(
            self.samples.len().is_multiple_of(self.channels as usize),
            "Audio buffer contains an incomplete interleaved frame"
        );
        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_undefined_audio_geometry_is_rejected() {
        let mut samples = [0; 3];
        let mut buffer = AudioBuffer {
            channels: 2,
            sample_rate: 48000,
            samples: &mut samples,
            frame_index: 0,
        };
        assert!(buffer.validate().is_err());
        buffer.channels = 1;
        assert!(buffer.validate().is_ok());
        buffer.sample_rate = 0;
        assert!(buffer.validate().is_err());
        buffer.sample_rate = 48000;
        buffer.channels = 0;
        assert!(buffer.validate().is_err());
    }
}
