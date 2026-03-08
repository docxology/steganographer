# Platform Guide

## macOS

### Prerequisites

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# GStreamer (via Homebrew — bundles all plugins)
brew install gstreamer
```

### Video Capture

macOS uses AVFoundation for camera access:

```bash
# List available cameras
gst-device-monitor-1.0 Video/Source

# Run with AVFoundation source
steganographer video --source "avfvideosrc ! videoconvert ! video/x-raw,format=RGB"
```

**Note**: macOS requires camera permissions. The first run will trigger a system permission dialog.

#### AVFoundation Internal Threading & Memory

macOS `avfvideosrc` has extraordinary restrictions when bridging into Rust and GStreamer:

- **`NSRunLoop`**: It demands that the application's Main Thread runs an active `[NSApp run]` loop. Steganographer satisfies this by deferring its entire pipeline execution to a GCD background thread using `gstreamer::macos_main()`.
- **Hardware Pool Exhaustion**: Apple limits the active `CVPixelBuffer` pool to ~35 frames. If a Rust background thread pulls frames and drops them without an active `NSAutoreleasePool`, the garbage collection is deferred indefinitely. This manifests as a permanent camera freeze exactly 1 second into recording. Steganographer uniquely prevents this by forcefully injecting `objc_autoreleasePoolPush()` and `Pop()` bindings via an RAII structural `Drop` guard on every single frame.

### Virtual Camera

macOS does not natively support `v4l2loopback`. To route Steganographer to Zoom/Teams/Meet on macOS:

**Method: OBS Window Capture (Recommended)**

1. Run Steganographer with a local preview window (`osxvideosink` or option 1 in the CLI)
2. Open OBS Studio and add a **Window Capture** source
3. Select the Steganographer preview window
4. Click **Start Virtual Camera** in OBS
5. In your video chat application, choose **OBS Virtual Camera** as your webcam

*Note: In the past, writing frames to a raw RGB file and having OBS read them was an option, but Window Capture of `osxvideosink` provides the lowest latency and best sync.*

### Audio

```bash
# Default audio input (built-in mic)
steganographer audio --source "osxaudiosrc" --sink "osxaudiosink"
```

### Known Issues

- `avfvideosrc` may not be available if GStreamer was installed without `plugins-bad`
- Camera permission must be granted in System Preferences > Privacy > Camera

---

## Linux

### Prerequisites

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# GStreamer (Debian/Ubuntu)
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
                 gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
                 gstreamer1.0-tools

# GStreamer (Fedora)
sudo dnf install gstreamer1-devel gstreamer1-plugins-base-devel \
                 gstreamer1-plugins-good gstreamer1-plugins-bad-free
```

### Video Capture (V4L2)

```bash
# List video devices
v4l2-ctl --list-devices

# Run with V4L2 source
steganographer video --source "v4l2src device=/dev/video0 ! videoconvert ! video/x-raw,format=RGB"
```

### Virtual Camera (v4l2loopback)

v4l2loopback creates virtual `/dev/videoX` devices that appear as real cameras to other applications.

```bash
# Install v4l2loopback
sudo apt install v4l2loopback-dkms v4l2loopback-utils

# Load the kernel module
sudo modprobe v4l2loopback devices=1 video_nr=42 card_label="Steganographer" exclusive_caps=1

# Verify the device exists
ls /dev/video42

# Run pipeline: real camera → stego → virtual camera
steganographer video \
    --source "v4l2src device=/dev/video0 ! videoconvert ! video/x-raw,format=RGB" \
    --sink "videoconvert ! v4l2sink device=/dev/video42"
```

Applications like Zoom, Teams, or OBS will see "Steganographer" as a camera option.

#### Persistent v4l2loopback

```bash
# /etc/modules-load.d/v4l2loopback.conf
v4l2loopback

# /etc/modprobe.d/v4l2loopback.conf
options v4l2loopback devices=1 video_nr=42 card_label="Steganographer" exclusive_caps=1
```

### Audio (PulseAudio)

```bash
# List audio sources
pactl list sources short

# Run with PulseAudio
steganographer audio --source "pulsesrc" --sink "pulsesink"
```

### Audio (PipeWire)

```bash
# PipeWire sources
steganographer audio --source "pipewiresrc" --sink "pipewiresink"
```

### Virtual Audio (PulseAudio Null Sink)

```bash
# Create a virtual audio sink
pactl load-module module-null-sink sink_name=stego_sink sink_properties=device.description="Steganographer"

# Route steganographer output to the null sink
# Other apps can use the monitor source: stego_sink.monitor
```

---

## Windows (Experimental)

### Prerequisites

1. Install GStreamer from [gstreamer.freedesktop.org](https://gstreamer.freedesktop.org/download/) (MSVC runtime + development installer)
2. Set environment variables:

   ```powershell
   $env:GSTREAMER_1_0_ROOT_MSVC = "C:\gstreamer\1.0\msvc_x86_64"
   $env:PKG_CONFIG_PATH = "$env:GSTREAMER_1_0_ROOT_MSVC\lib\pkgconfig"
   ```

### Video Capture

```bash
# Kernel Streaming source
steganographer video --source "ksvideosrc ! videoconvert ! video/x-raw,format=RGB"
```

---

## Cross-Platform Summary

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Build | ✅ | ✅ | ✅ (with MSVC GStreamer) |
| V4L2 capture | ✅ | ❌ | ❌ |
| AVFoundation | ❌ | ✅ | ❌ |
| Virtual camera | ✅ (v4l2loopback) | ⚠️ (OBS/DAL) | ⚠️ (OBS) |
| PulseAudio | ✅ | ❌ | ❌ |
| PipeWire | ✅ | ❌ | ❌ |
| Core audio | ❌ | ✅ | ✅ |
| Core tests | ✅ | ✅ | ✅ |

---

## Docker

### Build in Docker (no local GStreamer needed)

```dockerfile
FROM rust:1.94-bookworm

RUN apt-get update && apt-get install -y \
    libgstreamer1.0-dev \
    libgstreamer-plugins-base1.0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --workspace --release
```

```bash
docker build -t steganographer .
docker run --rm steganographer cargo test -p steganographer-core
```

---

## Further Reading

- [Getting Started](getting-started.md) — Installation walkthrough
- [GStreamer Integration](gstreamer.md) — Pipeline construction and troubleshooting
- [Configuration](configuration.md) — TOML config including `[video.pipeline]`
- [CLI Reference](cli-reference.md) — All commands and options
