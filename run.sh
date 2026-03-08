#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Steganographer — Interactive Terminal Menu
# ═══════════════════════════════════════════════════════════════════════════════
#
# Launch with: ./run.sh
# Auto-detects OS (macOS / Linux) and provides platform-specific options.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Theme ──────────────────────────────────────────────────────────────────────
BOLD="\033[1m"
DIM="\033[2m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
MAGENTA="\033[35m"
BLUE="\033[34m"
RESET="\033[0m"

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/steganographer.toml"
CARGO_BIN="steganographer"
KEY_DIR="${SCRIPT_DIR}/keys"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# ── TOML Config Reader ─────────────────────────────────────────────────────────
# Read a simple key = value from the TOML config file.
# Supports: string, integer, and float values.
# Usage: read_toml_value <section> <key> <default>
#   section can be dotted: "video.pipeline"
read_toml_value() {
    local section="$1"
    local key="$2"
    local default="$3"
    local in_section=0
    local result=""

    # Build the [section] header pattern(s)
    # For "video.pipeline" we match [video.pipeline] exactly
    local section_pattern="^\[${section}\]"

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        # Check if we entered the target section
        if [[ "$line" =~ $section_pattern ]]; then
            in_section=1
            continue
        fi

        # Check if we left the section (hit a new section header)
        if [[ $in_section -eq 1 ]] && [[ "$line" =~ ^\[ ]]; then
            break
        fi

        # Extract key = value
        if [[ $in_section -eq 1 ]] && [[ "$line" =~ ^[[:space:]]*${key}[[:space:]]*=[[:space:]]*(.*) ]]; then
            result="${BASH_REMATCH[1]}"
            # Strip quotes and trailing comments
            result="${result%%#*}"
            result="${result#\"}"
            result="${result%\"}"
            result="${result## }"
            result="${result%% }"
            break
        fi
    done < "$CONFIG"

    echo "${result:-$default}"
}

# ── Read Pipeline Configuration ────────────────────────────────────────────────
# Reads all pipeline config values at once, with defaults.
read_pipeline_config() {
    VIDEO_WIDTH=$(read_toml_value "video.pipeline" "width" "640")
    VIDEO_HEIGHT=$(read_toml_value "video.pipeline" "height" "480")
    VIDEO_FPS=$(read_toml_value "video.pipeline" "framerate" "30")
    VIDEO_OPACITY=$(read_toml_value "video.pipeline" "opacity" "1.0")
    PAYLOAD_TYPE=$(read_toml_value "video.pipeline.payload" "type" "signature")
    PAYLOAD_SIZE=$(read_toml_value "video.pipeline.payload" "size" "104")
    LSB_BITS=$(read_toml_value "video.stego.lsb_signature" "bits" "1")
    OVERLAY_TEXT=$(read_toml_value "video.stego.overlay" "text" "CONFIDENTIAL")
    OVERLAY_POS=$(read_toml_value "video.stego.overlay" "position" "bottom-right")
    OVERLAY_FONT=$(read_toml_value "video.stego.overlay" "font_size" "16")
    AUDIO_BITS=$(read_toml_value "audio.stego.lsb_signature" "bits" "1")
    export VIDEO_WIDTH VIDEO_HEIGHT VIDEO_FPS VIDEO_OPACITY
    export PAYLOAD_TYPE PAYLOAD_SIZE LSB_BITS
    export OVERLAY_TEXT OVERLAY_POS OVERLAY_FONT AUDIO_BITS
}

# Print the active pipeline configuration
print_pipeline_config() {
    echo -e "  ${BOLD}Active Configuration${RESET} ${DIM}(from ${CONFIG})${RESET}"
    echo -e "    ${CYAN}Resolution:${RESET}  ${VIDEO_WIDTH}×${VIDEO_HEIGHT}"
    echo -e "    ${CYAN}Framerate:${RESET}   ${VIDEO_FPS} fps"
    echo -e "    ${CYAN}Opacity:${RESET}     ${VIDEO_OPACITY}"
    echo -e "    ${CYAN}LSB Bits:${RESET}    ${LSB_BITS}"
    echo -e "    ${CYAN}Payload:${RESET}     ${PAYLOAD_TYPE} (${PAYLOAD_SIZE} bytes)"
    echo -e "    ${CYAN}Overlay:${RESET}     \"${OVERLAY_TEXT}\" @ ${OVERLAY_POS} (${OVERLAY_FONT}px)"
    echo ""
}

# ── OS Detection ───────────────────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Darwin*)  OS_TYPE="macos" ;;
        Linux*)   OS_TYPE="linux" ;;
        CYGWIN*|MINGW*|MSYS*) OS_TYPE="windows" ;;
        *)        OS_TYPE="unknown" ;;
    esac
    export OS_TYPE
}

# OS-specific video source
get_video_source_default() {
    case "$OS_TYPE" in
        macos)  echo "avfvideosrc" ;;
        linux)  echo "v4l2src device=/dev/video0" ;;
        *)      echo "videotestsrc" ;;
    esac
}

# OS-specific video sink
get_video_sink_default() {
    case "$OS_TYPE" in
        macos)  echo "osxvideosink" ;;
        linux)  echo "autovideosink" ;;
        *)      echo "autovideosink" ;;
    esac
}

# OS-specific audio source
get_audio_source_default() {
    case "$OS_TYPE" in
        macos)  echo "osxaudiosrc" ;;
        linux)  echo "pulsesrc" ;;
        *)      echo "audiotestsrc wave=sine freq=440" ;;
    esac
}

# OS-specific audio sink
get_audio_sink_default() {
    case "$OS_TYPE" in
        macos)  echo "osxaudiosink" ;;
        linux)  echo "autoaudiosink" ;;
        *)      echo "autoaudiosink" ;;
    esac
}

os_label() {
    case "$OS_TYPE" in
        macos)  echo "macOS" ;;
        linux)  echo "Linux" ;;
        windows) echo "Windows" ;;
        *)       echo "Unknown" ;;
    esac
}

# ── Ensure Rust toolchain ──────────────────────────────────────────────────────
setup_path() {
    if ! command -v cargo &>/dev/null; then
        if [ -f "$HOME/.cargo/env" ]; then
            source "$HOME/.cargo/env"
        elif [ -d "$HOME/.rustup/toolchains" ]; then
            TOOLCHAIN=$(ls "$HOME/.rustup/toolchains" | head -1)
            export PATH="$HOME/.rustup/toolchains/$TOOLCHAIN/bin:$PATH"
        fi
    fi
}

# ── Build if needed ────────────────────────────────────────────────────────────
ensure_built() {
    setup_path
    if [ ! -f "${SCRIPT_DIR}/target/debug/steganographer" ] && \
       [ ! -f "${SCRIPT_DIR}/target/release/steganographer" ]; then
        echo -e "${YELLOW}Building steganographer...${RESET}"
        cargo build --workspace --manifest-path "${SCRIPT_DIR}/Cargo.toml" 2>&1
        echo -e "${GREEN}Build complete.${RESET}"
    fi
}

# ── Runner ─────────────────────────────────────────────────────────────────────
run_cli() {
    setup_path
    cargo run -p steganographer-cli --manifest-path "${SCRIPT_DIR}/Cargo.toml" -- \
        --config "$CONFIG" "$@"
}

# ── Utilities ──────────────────────────────────────────────────────────────────
print_header() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════════════════╗"
    echo "  ║              🔒  S T E G A N O G R A P H E R  🔒            ║"
    echo "  ║         Cryptographic Watermarking for Video & Audio         ║"
    echo "  ╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  ${DIM}Config: ${CONFIG}${RESET}"
    echo -e "  ${DIM}OS:     $(os_label) (${OS_TYPE})${RESET}"
    echo ""
}

separator() {
    echo -e "  ${DIM}───────────────────────────────────────────────────────────${RESET}"
}

press_enter() {
    echo ""
    echo -e "  ${DIM}Press Enter to return to menu...${RESET}"
    read -r
}

# ── Menu Actions ───────────────────────────────────────────────────────────────

action_keygen() {
    print_header
    echo -e "  ${BOLD}${GREEN}🔑 Generate Ed25519 Key Pair${RESET}"
    separator
    mkdir -p "$KEY_DIR"

    echo -e "  ${DIM}Output directory: ${KEY_DIR}${RESET}"
    echo ""
    read -rp "  Key name [steganographer]: " key_name
    key_name="${key_name:-steganographer}"

    echo ""
    run_cli keygen --output "${KEY_DIR}/${key_name}"
    echo ""
    echo -e "  ${GREEN}✓ Keys saved:${RESET}"
    echo -e "    Private: ${KEY_DIR}/${key_name}.key"
    echo -e "    Public:  ${KEY_DIR}/${key_name}.pub"
    press_enter
}

action_encode_video() {
    print_header
    echo -e "  ${BOLD}${BLUE}📹 Encode — LSB Video Steganography${RESET}"
    separator

    read -rp "  Input file path: " input_file
    if [ ! -f "$input_file" ]; then
        echo -e "  ${RED}✗ File not found: ${input_file}${RESET}"
        press_enter
        return
    fi

    mkdir -p "$OUTPUT_DIR"
    local basename
    basename=$(basename "$input_file" | sed 's/\.[^.]*$//')
    local output_file="${OUTPUT_DIR}/${basename}_signed.rgb"
    read -rp "  Output file [${output_file}]: " custom_output
    output_file="${custom_output:-$output_file}"

    echo ""
    echo -e "  ${DIM}LSB bits per byte:${RESET}"
    echo "    1 = imperceptible (default)"
    echo "    2 = barely visible"
    echo "    3 = slightly visible"
    echo "    4 = noticeable"
    read -rp "  Bits [1]: " bits
    bits="${bits:-1}"

    echo ""
    echo -e "  ${YELLOW}Encoding...${RESET}"
    run_cli encode --input "$input_file" --output "$output_file" --stego-type lsb_video --bits "$bits"
    echo ""
    echo -e "  ${GREEN}✓ Encoded: ${output_file}${RESET}"
    press_enter
}

action_encode_audio() {
    print_header
    echo -e "  ${BOLD}${MAGENTA}🎵 Encode — LSB Audio Steganography${RESET}"
    separator

    read -rp "  Input file path (raw S16LE PCM): " input_file
    if [ ! -f "$input_file" ]; then
        echo -e "  ${RED}✗ File not found: ${input_file}${RESET}"
        press_enter
        return
    fi

    mkdir -p "$OUTPUT_DIR"
    local basename
    basename=$(basename "$input_file" | sed 's/\.[^.]*$//')
    local output_file="${OUTPUT_DIR}/${basename}_signed.pcm"
    read -rp "  Output file [${output_file}]: " custom_output
    output_file="${custom_output:-$output_file}"

    echo ""
    echo -e "  ${DIM}LSB bits per sample:${RESET}"
    echo "    1 = inaudible (~90 dB SNR, default)"
    echo "    2 = inaudible"
    echo "    3 = faintly audible in silence"
    echo "    4 = slight noise"
    read -rp "  Bits [1]: " bits
    bits="${bits:-1}"

    echo ""
    echo -e "  ${YELLOW}Encoding...${RESET}"
    run_cli encode --input "$input_file" --output "$output_file" --stego-type lsb_audio --bits "$bits"
    echo ""
    echo -e "  ${GREEN}✓ Encoded: ${output_file}${RESET}"
    press_enter
}

action_verify_video() {
    print_header
    echo -e "  ${BOLD}${BLUE}🔍 Verify — Video Signature${RESET}"
    separator

    read -rp "  Input file path: " input_file
    if [ ! -f "$input_file" ]; then
        echo -e "  ${RED}✗ File not found: ${input_file}${RESET}"
        press_enter
        return
    fi

    read -rp "  Public key (hex, or .pub file, or leave empty): " pub_key
    local pk_arg=""
    if [ -n "$pub_key" ]; then
        if [ -f "$pub_key" ]; then
            pub_key=$(cat "$pub_key" | tr -d '[:space:]')
        fi
        pk_arg="--public-key ${pub_key}"
    fi

    echo ""
    echo -e "  ${YELLOW}Verifying...${RESET}"
    # shellcheck disable=SC2086
    run_cli verify --input "$input_file" --stego-type lsb_video $pk_arg
    press_enter
}

action_verify_audio() {
    print_header
    echo -e "  ${BOLD}${MAGENTA}🔍 Verify — Audio Signature${RESET}"
    separator

    read -rp "  Input file path (raw S16LE PCM): " input_file
    if [ ! -f "$input_file" ]; then
        echo -e "  ${RED}✗ File not found: ${input_file}${RESET}"
        press_enter
        return
    fi

    read -rp "  Public key (hex, or .pub file, or leave empty): " pub_key
    local pk_arg=""
    if [ -n "$pub_key" ]; then
        if [ -f "$pub_key" ]; then
            pub_key=$(cat "$pub_key" | tr -d '[:space:]')
        fi
        pk_arg="--public-key ${pub_key}"
    fi

    echo ""
    echo -e "  ${YELLOW}Verifying...${RESET}"
    # shellcheck disable=SC2086
    run_cli verify --input "$input_file" --stego-type lsb_audio $pk_arg
    press_enter
}

action_live_video() {
    print_header
    read_pipeline_config
    echo -e "  ${BOLD}${BLUE}📡 Live Video Pipeline — $(os_label)${RESET}"
    separator
    echo -e "  ${DIM}Captures video from your camera, applies:${RESET}"
    echo -e "  ${DIM}  • LSB steganography (hidden cryptographic signature, ${LSB_BITS} bit)${RESET}"
    echo -e "  ${DIM}  • Info bar overlay (visible: timestamp, barcode, QR, hash)${RESET}"
    echo -e "  ${DIM}  • Payload: ${PAYLOAD_TYPE} (${PAYLOAD_SIZE}B per frame)${RESET}"
    echo -e "  ${DIM}Requires GStreamer installed.${RESET}"
    echo ""
    print_pipeline_config

    local caps="video/x-raw,format=RGB,width=${VIDEO_WIDTH},height=${VIDEO_HEIGHT},framerate=${VIDEO_FPS}/1"
    local source_str
    local sink_str

    case "$OS_TYPE" in
        macos)
            source_str="avfvideosrc ! videoconvert ! ${caps}"
            sink_str="videoconvert ! osxvideosink sync=false"
            ;;
        linux)
            source_str="v4l2src device=/dev/video0 ! videoconvert ! ${caps}"
            sink_str="videoconvert ! autovideosink"
            ;;
        *)
            echo -e "  ${RED}Unsupported OS for live video: ${OS_TYPE}${RESET}"
            source_str="videotestsrc ! videoconvert ! ${caps}"
            sink_str="videoconvert ! autovideosink"
            ;;
    esac

    read -rp "  Max frames (empty = unlimited): " max_frames
    local max_arg=""
    if [ -n "$max_frames" ]; then
        max_arg="--max-frames ${max_frames}"
    fi

    echo ""
    echo -e "  ${YELLOW}Starting live video pipeline...${RESET}"
    echo -e "  ${DIM}Source: ${source_str}${RESET}"
    echo -e "  ${DIM}Sink:   ${sink_str}${RESET}"
    echo -e "  ${DIM}Modules: LSB-${LSB_BITS} steganography + text overlay + info bar${RESET}"
    echo -e "  ${DIM}Payload: ${PAYLOAD_TYPE} (${PAYLOAD_SIZE}B) | Opacity: ${VIDEO_OPACITY}${RESET}"
    echo -e "  ${DIM}Press Ctrl+C to stop${RESET}"
    echo ""
    # shellcheck disable=SC2086
    run_cli video --source "$source_str" --sink "$sink_str" $max_arg || true
    press_enter
}

action_live_audio() {
    print_header
    read_pipeline_config
    echo -e "  ${BOLD}${MAGENTA}📡 Live Audio Pipeline — $(os_label)${RESET}"
    separator
    echo -e "  ${DIM}Captures audio, applies LSB steganography (${AUDIO_BITS} bit).${RESET}"
    echo -e "  ${DIM}Payload: ${PAYLOAD_TYPE} (${PAYLOAD_SIZE}B per buffer)${RESET}"
    echo ""
    echo -e "  ${BOLD}Active Audio Configuration${RESET} ${DIM}(from ${CONFIG})${RESET}"
    echo -e "    ${CYAN}LSB Bits:${RESET}    ${AUDIO_BITS}"
    echo -e "    ${CYAN}Payload:${RESET}     ${PAYLOAD_TYPE} (${PAYLOAD_SIZE} bytes)"
    echo ""

    local source_str
    local sink_str

    case "$OS_TYPE" in
        macos)
            source_str="osxaudiosrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100"
            sink_str="audioconvert ! osxaudiosink"
            ;;
        linux)
            source_str="pulsesrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100"
            sink_str="audioconvert ! pulsesink"
            ;;
        *)
            source_str="audiotestsrc wave=sine freq=440 ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100"
            sink_str="audioconvert ! autoaudiosink"
            ;;
    esac

    read -rp "  Max buffers (empty = unlimited): " max_buffers
    local max_arg=""
    if [ -n "$max_buffers" ]; then
        max_arg="--max-buffers ${max_buffers}"
    fi

    echo ""
    echo -e "  ${YELLOW}Starting live audio pipeline...${RESET}"
    echo -e "  ${DIM}Source: ${source_str}${RESET}"
    echo -e "  ${DIM}Sink:   ${sink_str}${RESET}"
    echo -e "  ${DIM}Modules: LSB-${AUDIO_BITS} steganography${RESET}"
    echo -e "  ${DIM}Press Ctrl+C to stop${RESET}"
    echo ""
    # shellcheck disable=SC2086
    run_cli audio --source "$source_str" --sink "$sink_str" $max_arg || true
    press_enter
}

action_run_tests() {
    print_header
    echo -e "  ${BOLD}${GREEN}🧪 Run Full Test Suite${RESET}"
    separator
    echo ""
    setup_path
    cargo test -p steganographer-core --manifest-path "${SCRIPT_DIR}/Cargo.toml" 2>&1
    press_enter
}

action_dashboard() {
    print_header
    echo -e "  ${BOLD}${GREEN}🖥️  Live Dashboard — Round-Trip Verification${RESET}"
    separator
    echo ""

    setup_path
    read_pipeline_config

    local port=8080
    local backend="ed25519"

    echo -e "  ${CYAN}Dashboard Configuration:${RESET}"
    echo -e "    Port:              ${port}"
    echo -e "    Signing Backend:   ${backend}"
    echo -e "    Resolution:        ${VIDEO_WIDTH}x${VIDEO_HEIGHT}"
    echo ""
    echo -e "  ${YELLOW}Opening http://localhost:${port} ...${RESET}"
    echo ""

    # Build first
    cargo build -p steganographer-cli --manifest-path "${SCRIPT_DIR}/Cargo.toml" 2>&1

    # Launch dashboard
    cargo run --manifest-path "${SCRIPT_DIR}/Cargo.toml" \
        -p steganographer-cli -- \
        --config "${SCRIPT_DIR}/steganographer.toml" \
        dashboard --port "${port}" --backend "${backend}" 2>&1

    press_enter
}

action_run_all() {
    print_header
    echo -e "  ${BOLD}${GREEN}🚀 Run All — Tests + Demo + Dashboard${RESET}"
    separator
    echo ""

    setup_path
    read_pipeline_config

    echo -e "  ${BOLD}Step 1/3: Running Test Suite${RESET}"
    echo -e "  ${DIM}─────────────────────────────${RESET}"
    cargo test -p steganographer-core --manifest-path "${SCRIPT_DIR}/Cargo.toml" 2>&1
    echo ""

    echo -e "  ${BOLD}Step 2/3: Quick Demo (encode → verify round-trip)${RESET}"
    echo -e "  ${DIM}─────────────────────────────${RESET}"
    mkdir -p "$OUTPUT_DIR"
    local test_file="${OUTPUT_DIR}/demo_frame.rgb"
    local signed_file="${OUTPUT_DIR}/demo_frame_signed.rgb"

    dd if=/dev/urandom of="$test_file" bs=30000 count=1 2>/dev/null
    run_cli encode --input "$test_file" --output "$signed_file" --stego-type lsb_video --bits 1 2>&1
    run_cli verify --input "$signed_file" --stego-type lsb_video 2>&1
    echo -e "  ${GREEN}✓ Round-trip demo complete${RESET}"
    echo ""

    echo -e "  ${BOLD}Step 3/3: Launching Dashboard${RESET}"
    echo -e "  ${DIM}─────────────────────────────${RESET}"
    local port=8080
    echo -e "  ${YELLOW}Dashboard at http://localhost:${port}${RESET}"
    echo -e "  ${DIM}Press Ctrl+C to stop the dashboard and return to menu.${RESET}"
    echo ""

    cargo run --manifest-path "${SCRIPT_DIR}/Cargo.toml" \
        -p steganographer-cli -- \
        --config "${SCRIPT_DIR}/steganographer.toml" \
        dashboard --port "${port}" --backend "ed25519" 2>&1

    press_enter
}

action_show_info() {
    print_header
    read_pipeline_config
    echo -e "  ${BOLD}${CYAN}ℹ️  System Information${RESET}"
    separator
    echo ""

    echo -e "  ${BOLD}Platform:${RESET} $(os_label) (${OS_TYPE})"
    echo ""

    setup_path

    echo -e "  ${BOLD}Rust:${RESET}"
    echo -n "    "; rustc --version 2>/dev/null || echo "    Not found"
    echo -n "    "; cargo --version 2>/dev/null || echo "    Not found"
    echo ""

    echo -e "  ${BOLD}GStreamer:${RESET}"
    if command -v gst-launch-1.0 &>/dev/null; then
        echo -n "    "; gst-launch-1.0 --version 2>/dev/null | head -1
    else
        echo -e "    ${RED}Not installed${RESET}"
        case "$OS_TYPE" in
            macos) echo -e "    ${DIM}Install: brew install gstreamer gst-plugins-base gst-plugins-good${RESET}" ;;
            linux) echo -e "    ${DIM}Install: sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev${RESET}" ;;
        esac
    fi
    echo ""

    echo -e "  ${BOLD}Pipeline Configuration:${RESET} ${DIM}(from steganographer.toml)${RESET}"
    print_pipeline_config

    echo -e "  ${BOLD}Video Sources (${OS_TYPE}):${RESET}"
    case "$OS_TYPE" in
        macos)
            echo "    Default: avfvideosrc (MacBook Camera)"
            echo "    Virtual: OBS Virtual Camera (if installed)"
            ;;
        linux)
            echo "    Default: v4l2src (/dev/video0)"
            echo "    Virtual: v4l2loopback (/dev/video42+)"
            if [ -d "/dev" ]; then
                local video_devs
                video_devs=$(ls /dev/video* 2>/dev/null | head -5)
                if [ -n "$video_devs" ]; then
                    echo "    Detected: $video_devs"
                fi
            fi
            ;;
    esac
    echo ""

    echo -e "  ${BOLD}Audio Sources (${OS_TYPE}):${RESET}"
    case "$OS_TYPE" in
        macos) echo "    Default: osxaudiosrc (Built-in Microphone)" ;;
        linux) echo "    Default: pulsesrc / pipewiresrc" ;;
    esac
    echo ""

    echo -e "  ${BOLD}Project:${RESET}"
    echo "    Root:   ${SCRIPT_DIR}"
    echo "    Config: ${CONFIG}"
    echo "    Keys:   ${KEY_DIR}/"
    echo "    Output: ${OUTPUT_DIR}/"
    echo ""

    echo -e "  ${BOLD}Crates:${RESET}"
    echo "    steganographer-core  — Pure algorithms (BLAKE3, Ed25519, LSB, Overlay, InfoBar)"
    echo "    steganographer-gst   — GStreamer integration (AppSink/AppSrc)"
    echo "    steganographer-cli   — CLI binary (Clap, 5 subcommands)"
    echo ""

    echo -e "  ${BOLD}Modules:${RESET}"
    echo "    Esoteric (hidden):   LSB Video (${LSB_BITS}-bit), LSB Audio (keyed PRNG, ${AUDIO_BITS}-bit)"
    echo "    Exoteric (visible):  Text Overlay (\"${OVERLAY_TEXT}\"), Info Bar (timestamp, barcode, QR)"
    echo "    Crypto:              BLAKE3 hash + Ed25519 signature (${PAYLOAD_SIZE}B payload)"

    press_enter
}

action_quick_demo() {
    print_header
    echo -e "  ${BOLD}${GREEN}⚡ Quick Demo — Full Encode → Verify Round-Trip${RESET}"
    separator
    echo ""

    mkdir -p "$OUTPUT_DIR"
    local test_file="${OUTPUT_DIR}/demo_frame.rgb"
    local signed_file="${OUTPUT_DIR}/demo_frame_signed.rgb"

    echo -e "  ${DIM}1. Generating 30KB test RGB frame...${RESET}"
    dd if=/dev/urandom of="$test_file" bs=30000 count=1 2>/dev/null
    echo -e "  ${GREEN}   ✓ ${test_file}${RESET}"
    echo ""

    echo -e "  ${DIM}2. Encoding with LSB video steganography (1 bit)...${RESET}"
    run_cli encode --input "$test_file" --output "$signed_file" --stego-type lsb_video --bits 1
    echo ""

    echo -e "  ${DIM}3. Extracting signature from encoded file...${RESET}"
    run_cli verify --input "$signed_file" --stego-type lsb_video
    echo ""

    echo -e "  ${GREEN}✓ Demo complete!${RESET}"
    echo -e "  ${DIM}Signature found and extracted from watermarked frame.${RESET}"
    echo -e "  ${DIM}To verify authenticity, pass --public-key with the hex key from step 2.${RESET}"

    press_enter
}

# ── Submenus ───────────────────────────────────────────────────────────────────

submenu_cli_tools() {
    while true; do
        print_header
        echo -e "  ${BOLD}CLI Tools${RESET}  ${DIM}— Encode / Verify / Keygen${RESET}"
        echo ""
        echo -e "    ${CYAN}1${RESET})  📹  Encode Video (LSB embed into raw RGB)"
        echo -e "    ${CYAN}2${RESET})  🎵  Encode Audio (LSB embed into raw PCM)"
        echo -e "    ${CYAN}3${RESET})  🔍  Verify Video (extract & check signature)"
        echo -e "    ${CYAN}4${RESET})  🔍  Verify Audio (extract & check signature)"
        echo -e "    ${CYAN}5${RESET})  🔑  Generate Key Pair (Ed25519)"
        echo ""
        separator
        echo -e "    ${CYAN}b${RESET})  ← Back"
        echo ""
        read -rp "  Choose: " sub
        case "$sub" in
            1) action_encode_video ;;
            2) action_encode_audio ;;
            3) action_verify_video ;;
            4) action_verify_audio ;;
            5) action_keygen ;;
            b|B) return ;;
            *) echo -e "  ${RED}Invalid option.${RESET}"; sleep 0.3 ;;
        esac
    done
}

submenu_live_pipelines() {
    while true; do
        print_header
        echo -e "  ${BOLD}Live Pipelines${RESET}  ${DIM}— GStreamer ($(os_label))${RESET}"
        echo -e "  ${DIM}Direct camera/mic → stego → output. Requires GStreamer.${RESET}"
        echo ""
        echo -e "    ${CYAN}1${RESET})  📡  Live Video (capture → stego + overlay → display)"
        echo -e "    ${CYAN}2${RESET})  📡  Live Audio (capture → stego → playback)"
        echo ""
        separator
        echo -e "    ${CYAN}b${RESET})  ← Back"
        echo ""
        read -rp "  Choose: " sub
        case "$sub" in
            1) action_live_video ;;
            2) action_live_audio ;;
            b|B) return ;;
            *) echo -e "  ${RED}Invalid option.${RESET}"; sleep 0.3 ;;
        esac
    done
}

# ── Main Menu ──────────────────────────────────────────────────────────────────

main_menu() {
    detect_os
    ensure_built

    while true; do
        print_header
        echo -e "    ${CYAN}1${RESET})  🖥️   ${BOLD}Dashboard${RESET}  ${DIM}— Web GUI (Video + Audio + Docs)${RESET}"
        echo -e "    ${CYAN}2${RESET})  🔧  CLI Tools  ${DIM}— Encode / Verify / Keygen${RESET}"
        echo -e "    ${CYAN}3${RESET})  📡  Live Pipelines  ${DIM}— GStreamer ($(os_label))${RESET}"
        echo -e "    ${CYAN}4${RESET})  ⚡  Quick Demo  ${DIM}— Encode → Verify round-trip${RESET}"
        echo -e "    ${CYAN}5${RESET})  🧪  Run Tests"
        echo -e "    ${CYAN}6${RESET})  ℹ️   System Info"
        echo ""
        separator
        echo -e "    ${CYAN}q${RESET})  Exit"
        echo ""
        read -rp "  Choose: " choice

        case "$choice" in
            1) action_dashboard ;;
            2) submenu_cli_tools ;;
            3) submenu_live_pipelines ;;
            4) action_quick_demo ;;
            5) action_run_tests ;;
            6) action_show_info ;;
            q|Q) echo -e "\n  ${GREEN}Goodbye.${RESET}\n"; exit 0 ;;
            *) echo -e "  ${RED}Invalid option.${RESET}"; sleep 0.3 ;;
        esac
    done
}

main_menu

