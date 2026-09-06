# fuzz_targets/

cargo-fuzz entry points (each file is one `fuzz_target!` harness) exercising
steganographer-core APIs with random inputs. Run via `cargo fuzz run <name>`
(nightly; unverified — not executed during the doc pass).
