# Verification model

The Ed25519 signature scheme lets a verifier check a signature with a public
key [@rfc8032]. Steganographer binds a signature to the media content and its
position in the artifact sequence. The hash format separates media fields
so their byte boundaries are represented in the digest. The verifier
recomputes the digest from the supplied data and checks the signature
using its configured public key.

A recording manifest can describe the returned artifacts and their
indices. Establish the public key separately before verifying a recording.
The same rule applies after a signer changes keys. Independent verification
can assess the delivered media under that key without relying on the
dashboard's status indicator.
