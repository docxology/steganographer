# Methods

The replay runs the core Rust cryptography unit tests with the locked
dependencies and the default network feature disabled. A matching-key
control signs synthetic video and audio bytes and verifies the result
with the corresponding public key. The video-only case exercises the
same operation without audio.

The remaining named controls change one property at a time. One replaces
the video bytes, one changes the artifact index in the signature record,
and one configures the verifier with a different public key. The tests
assert rejection in each case. The replay checks the individual test
results before emitting the measured figure.
