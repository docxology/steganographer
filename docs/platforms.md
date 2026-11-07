# Platform Guide

## Support boundaries

Rust **1.91** is the workspace minimum. The updated RTC stack uses a standard
networking constructor stabilized in 1.91; OpenH264 is shared at 0.9.8.
Dependency upgrades must pass the locked all-feature MSRV check, not merely
compile on the newest development toolchain.

| Surface | macOS / Linux | Windows | wasm32 |
| --- | --- | --- | --- |
| Core algorithms | Native build/test CI configured | GStreamer-free build/test CI configured | Supported browser subset through WASM facade |
| Offline CLI and dashboard | Supported native targets | GStreamer-free CI subset; dashboard deployment not established by that job | Not a CLI target |
| Native GStreamer | Supported integration targets | Not a supported release target | Not supported |
| WASM facade | Native boundary tests plus generated binding checks | Native GStreamer-free crate tests | Packet/carrier/forensics API |

CI configuration is not a claim that a specific hosted run passed. Physical
camera/microphone devices, OBS/virtual devices and third-party applications
are separate from synthetic/headless tests. Release browser capture/export
validation used fake media inputs; it does not establish physical-hardware
coverage. Startup/demo artifacts and Record exports are sampled PNG frames /
PCM WAV chunks, not continuous signed media.

## GStreamer-free build

```bash
cargo build -p steganographer-cli --no-default-features --locked
```

This omits `video` and `audio`, retaining offline encode/decode/extract/verify,
forensics, dashboard and OTS CLI surfaces. The optional WebRTC feature has its
own native dependencies; do not infer its availability from a GStreamer-free
build. See [Getting Started](getting-started.md).

## macOS

```bash
brew install gstreamer
cargo build --workspace --locked
```

Homebrew plugin availability varies; inspect required elements locally.
AVFoundation camera and CoreAudio microphone examples:

```bash
steganographer --config config/example.toml video \
  --source 'avfvideosrc ! videoconvert ! video/x-raw,format=RGB' \
  --sink 'videoconvert ! autovideosink'
steganographer --config config/example.toml audio \
  --source 'osxaudiosrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100' \
  --sink 'autoaudiosink'
```

Camera/microphone permission is controlled by macOS and the launching
application; these examples are not assertions of exercised physical hardware.

### Main-thread ownership

The CLI dispatches live Video/Audio through `gstreamer::macos_main()` before
creating a Tokio runtime. Cocoa-loop ownership belongs to the application,
not reusable filter/file library calls. Headless file APIs do not start
`NSApplication`; GUI/AVFoundation library callers must arrange the process
main loop themselves. Per-frame native resource/autorelease handling is not a
guarantee that every camera driver behaves identically.

### Virtual camera caveat

macOS has no `v4l2loopback`. OBS window capture + OBS Virtual Camera is an
external presentation route, not an exact signed-byte transport. It can resize,
render or encode frames and destroy invisible watermarks. Neither low latency
nor successful downstream verification is promised for Zoom/Teams/Meet.

## Linux

```bash
# Debian/Ubuntu
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-tools

# Fedora development packages
sudo dnf install gstreamer1-devel gstreamer1-plugins-base-devel
```

Example V4L2 capture (requires a real permitted device):

```bash
steganographer --config config/example.toml video \
  --source 'v4l2src device=/dev/video0 ! videoconvert ! video/x-raw,format=RGB' \
  --sink 'videoconvert ! autovideosink'
```

`v4l2loopback` is an optional external kernel module, not installed by this
project. A typical setup is:

```bash
sudo apt install v4l2loopback-dkms v4l2loopback-utils
sudo modprobe v4l2loopback devices=1 video_nr=42 \
  card_label=Steganographer exclusive_caps=1
steganographer --config config/example.toml video \
  --source 'v4l2src device=/dev/video0 ! videoconvert ! video/x-raw,format=RGB' \
  --sink 'videoconvert ! v4l2sink device=/dev/video42'
```

Module signing, device access, negotiated pixel formats and consuming
applications are deployment-specific. A visible picture does not prove the
consumer preserved signed pixels.

PulseAudio/PipeWire examples require the corresponding GStreamer plugins:

```bash
steganographer --config config/example.toml audio \
  --source 'pulsesrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100' \
  --sink 'pulsesink'
steganographer --config config/example.toml audio \
  --source 'pipewiresrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100' \
  --sink 'pipewiresink'
```

Resampling/mixing/downstream lossy encoding may destroy audio LSB evidence.

## Windows

The repository has a `test-windows` CI job for core, CLI and WASM crates with
`--no-default-features`. This is **not** native GStreamer, WebRTC media,
camera/microphone, dashboard deployment or Unix-permission coverage. No Windows
native pipeline support or physical hardware exercise is claimed for 0.8.

Build the supported subset:

```powershell
cargo build -p steganographer-core -p steganographer-cli -p steganographer-wasm --no-default-features --locked
```

Unix mode 0600 is not a Windows ACL guarantee; protect secret-file directories
with platform-native permissions.

## Exact native files versus previews

Native file signing uses RGB Matroska `.mkv` for video and PCM `.wav` for audio.
Paths are literal file paths, not interpolated launch fragments. RGB row padding
is not signed content. Audio files collect a bounded selection (64 MiB), sign
once at index 0 and honor `max_buffers`; EOS finalization and downstream errors
matter to the delivered artifact.

These contracts do not extend to arbitrary user-provided sinks, H.264/VP9/JPEG,
OBS captures or conferencing codecs. Dashboard H.264 is a lossy preview;
independent verification uses downloaded signed PNG/WAV artifacts with their
manifest metadata. See [GStreamer](gstreamer.md) and [CLI Reference](cli-reference.md).

## WASM

Build the facade for `wasm32-unknown-unknown` and generate matching
`wasm-bindgen` bindings as described in
[the WASM crate guide](../steganographer-wasm/README.md). Native tests alone do
not establish JavaScript ABI behavior. Release validation exercised generated
bindings with Node and real browser sampled-media exports; that is not a
promise for every browser/device.

`steganographer.packet-report.v2` reports every `u64` as an exact decimal string.
Validate original JavaScript numbers before narrowing to byte/word parameters;
callers must handle errors rather than assume wraparound. The facade has no
native GStreamer, live signing pipeline or network OTS implementation.

## Containers

The repository Dockerfile is a deployment starting point, not proof of camera
or host-device passthrough. Browser media requires a suitable secure browser
context; container networking and device access need explicit deployment setup.
Do not describe a container build or synthetic source as physical-hardware
validation.

See [Configuration](configuration.md) and [Compatibility](compatibility.md).
