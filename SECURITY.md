# Security

## Status And Reporting

This library has not received an independent security audit. It implements one
fixed Noise state machine using Bun's built-in `node:crypto` primitives, with zero
runtime dependencies or native addons. It does not implement X25519 arithmetic,
AES, GCM, hashing, HMAC, HKDF, or random number generation in JavaScript. Primitive
assurances do not automatically extend to this state machine, Bun's bindings, or
the surrounding WebSocket protocol.

Do not include keys, credentials, or private transcripts in a public issue. Use
GitHub's private vulnerability reporting if available; otherwise ask
[@cfal](https://github.com/cfal) to establish a private channel before sharing
exploit details. Only the latest project revision is maintained; there is no
long-term support or response-time guarantee.

## What Is Authenticated

The fixed suite is `Noise_NNpsk0_25519_AESGCM_SHA256`. A connection proves
possession of a shared, randomly generated 32-byte PSK in the application-supplied
context. It does not distinguish two holders of the same key, authenticate a
hostname, or establish controller/worker authorization. Use different keys per
node and preserve application identity/admission checks.

There are no passwords, public-key identities, key negotiation, plaintext
fallbacks, or implicit key conversions. A weak PSK permits offline guessing from
captured handshakes. Generate 32 random bytes with a cryptographically secure RNG
and provision them through a trusted channel. Rotate a suspected compromised key,
close existing connections, and replace it on both endpoints.

The two Noise handshake payloads are empty. Directional encrypted readiness
records prove possession of fresh transport keys before application callbacks.
Replaying an old first handshake can trigger bounded handshake work, but cannot
open the application connection. Every reconnect generates fresh ephemeral keys;
no transport cipher state is resumed. Under the Noise assumptions, later PSK
compromise does not decrypt previously completed passive captures with erased
ephemeral keys, but endpoint compromise or retained process memory is outside
that guarantee.

An intermediary without the PSK cannot decrypt or forge accepted application
records even over unencrypted WS or through a TLS-terminating proxy. It can relay
the connection, delay/drop traffic, observe lengths/timing, and see HTTP upgrade
metadata including URLs and nonsecret node selectors. This is **not relay
prevention**, traffic-flow hiding, or protection for other HTTP endpoints.

Keep outer TLS verified when available. `allowUnverifiedTls` weakens the outer
layer; it does not weaken mandatory Noise authentication. Fingerprint pinning is
deferred pending [Bun #43635](https://github.com/oven-sh/bun/issues/43635).

## Wire And Nonce Boundaries

Wire version 1 binds a binary prologue:
`UTF8("cfal/noise-ws\0") || 0x01 || uint16be(contextBytes.length) || contextBytes`.
The context must be canonical, nonempty, well-formed UTF-8, at most 1024 bytes.
There is no version/suite negotiation; mismatches fail authentication.

Every WebSocket message is binary and contains exactly one Noise message. The
two handshake messages are exactly 48 bytes. After splitting, the initiator sends
encrypted `CLIENT_READY` (type 1), then the responder sends `SERVER_READY` (type 2).
Both consume transport nonce 0. The responder's callback occurs only after its
confirmation is accepted by the transport; the initiator's occurs after verifying
that confirmation. Delivery acknowledgments belong to the application.

Transport plaintext contains one record:

- Type 1, 2, or 3: exactly one byte (`CLIENT_READY`, `SERVER_READY`, `CLOSE`).
- Type 16 or 17: text/binary start, `uint32be(totalBytes)`, followed by payload.
- Type 18: continuation payload for the one currently incomplete message.

Maximum ciphertext is 65,535 bytes, including the 16-byte authentication tag.
Starts carry up to 65,514 payload bytes; continuations carry up to 65,518. Each
fragment must have exactly the smaller of its capacity and the remaining length.
The declared length determines the final fragment. There is no interleaving or
partial delivery. Nested starts, out-of-state controls, malformed UTF-8, overflow,
noncanonical fragments, oversized messages, and incomplete-message timeouts close
the connection. Discarding, duplicating, reordering, reflecting, or splicing
ciphertexts fails authentication when the receiver next attempts that sequence.
Withholding the tail without a later record is indistinguishable from a stalled
connection; use application heartbeats and receipts.

AES-GCM uses a 128-bit tag and the Noise nonce encoding: four zero bytes followed
by the counter as a big-endian uint64. Cipher states check **before every
encrypt/decrypt** and terminate at 2^24 records per direction, far below Noise's
reserved maximum nonce. Readiness and CLOSE consume the same budget. Even full
records remain below 1 TiB of ciphertext per key, conservatively bounding GCM data
volume. There is no nonce reset, ciphertext retry, or rekey. Reconnect with fresh
state at exhaustion; applications may configure a smaller budget. Any cipher
error destroys that state; a socket crypto error destroys both directions.

The public socket API always generates new ephemeral X25519 keys. Deterministic
private-key injection exists only in the internal handshake module for independent
vectors and is not exposed as a socket option. Low-order public keys that fail
X25519 or produce an all-zero shared secret are rejected. Decrypted bytes from
`Decipheriv.update()` are never returned before `final()` validates the tag.

After encryption begins, a write failure is terminal even if only part of a
logical message was handed to the transport. Buffer-budget rejection before
encryption leaves the connection usable. Close records have no sensitive reason;
raw errors and close reasons never enter application messages. An authenticated
CLOSE says nothing about delivery or persistence of preceding application data.

## Resource And Memory Limits

The library bounds individual messages, fragmentation time, native outbound
buffer budget, pending handshakes, and active connections. It does not globally
bound process memory, rate-limit remote IPs, authorize upgrades, protect expensive
credential lookups, or bound asynchronous application callback work. A PSK holder
can consume the configured per-connection budgets. Configure host admission and
timeouts accordingly; do not expose a listener with unlimited upstream admission.

Bun's server `maxPayloadLength` should be 65,535 on a dedicated listener. If a
shared listener raises that global limit for other routes, Bun may allocate an
oversized Noise frame before this library rejects it. The native client likewise
may allocate an oversized frame before delivering its callback. Post-allocation
rejection is not a network-level allocation bound. Use listener/proxy/process
resource limits where untrusted endpoints matter.

PSKs and transport keys are copied; wrapper-owned copies are zeroed on completion
or termination where practical. Ephemeral private keys use native `KeyObject`s;
dropping a reference cannot guarantee immediate native erasure. Caller-owned PSKs
are not erased. JavaScript GC,
temporary native buffers, snapshots, swap, crash dumps, and caller closures make
guaranteed secure erasure impossible here. Do not log key material or application
payloads inadvertently. The library itself performs no logging.

## Independent Evidence

The state machine follows the [Noise specification](https://noiseprotocol.org/noise.html),
particularly sections 4.3 (HKDF), 5 (state), 9.2 (PSK ephemeral mixing), and 12.4
(AES-GCM). The fixed protocol name is exactly 32 bytes: Noise initializes the
handshake hash directly with those bytes, not their digest.

The independent public-domain
[Cacophony vector](https://github.com/centromere/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt#L8716-L8750)
verifies the exact suite, handshake ciphertexts/hash, and alternating transport
ciphertexts. Local tests also cover replay, tampering, direction/session confusion,
framing, timeouts, nonce limits, backpressure, TLS policy, and standalone packaging.
An additional, opt-in Go reference test compares random prologues, keys, handshake
payloads, channel bindings, and bidirectional ciphertexts against
[`flynn/noise` v1.1.0](https://github.com/flynn/noise/tree/4d9f71cd4ba1fe81415efac312664ccc4bc79b46),
including maximum lengths and the nonce 255/256 boundary. Its isolated Go module
is test tooling only, never a runtime dependency or part of the published package.

These checks do not replace a cryptographic implementation audit. Review and rerun
them for protocol changes and Bun upgrades; runtime crypto behavior is part of
the trusted computing base.
