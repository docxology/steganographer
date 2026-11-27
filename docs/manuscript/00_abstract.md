# Abstract

Verifying a signed artifact requires the artifact and a public key accepted
through an independent channel. This paper describes the local media
verification contract in Steganographer and exercises it on synthetic
inputs. The Rust suite accepts a valid signature and rejects changed media,
a changed artifact index, and a verifier configured with a different key.
The result describes cryptographic verification of an individual artifact.
