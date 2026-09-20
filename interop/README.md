# Independent Noise Reference

`bun run test:interop` requires Go 1.23+ and compares the Bun implementation with
`github.com/flynn/noise` v1.1.0, commit
[`4d9f71c`](https://github.com/flynn/noise/tree/4d9f71cd4ba1fe81415efac312664ccc4bc79b46).
The Go module and checksums are isolated here; none of these dependencies ship in
the npm package or are required for runtime or the ordinary Bun test suite.

The test generates 20 independent random transcripts and compares both handshake
messages, both final hashes, and 1,508 bidirectional transport ciphertexts. It also
decrypts the reference messages with the Bun implementation. Cases cover empty
and maximum-length handshake payloads and transport records, different prologues,
and counters crossing 255/256 in both directions. Inputs are synthetic test keys,
not application credentials. The first run downloads the pinned Go module graph.

The runner uses one Go build worker, `GOMAXPROCS=1`, and `$HOME/tmp` for build
scratch and its temporary reference executable. No servers are started. A matching
transcript is independent compatibility evidence, not a security audit.
