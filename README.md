# noise-ws

Authenticated, encrypted WebSockets for Bun. Built for controller/execution-node
links in [cfal/garcon](https://github.com/cfal/garcon), including private networks
and TLS-terminating reverse proxies.

Both endpoints must use this library and share a randomly generated, 32-byte key.
The key is never sent. Application messages are encrypted over **both `ws:` and
`wss:`**, independently of TLS. This is a fixed Noise protocol, not a general
Noise framework, browser client, or drop-in wrapper for an ordinary WebSocket peer.

Zero runtime dependencies or native addons. The fixed Noise state machine is
implemented here; X25519, AES-256-GCM, SHA-256, HKDF, and randomness come from
Bun's built-in `node:crypto`, not handwritten cryptographic primitives.

**Security status:** new, unaudited protocol implementation. Independent test
vectors, interoperability checks, and adversarial tests are not a security audit.
Read [SECURITY.md](SECURITY.md) before deployment.

## Install

Requires Bun 1.4.2 or later. Linux x64 is tested here; other Bun platforms have not
been verified by this repository's CI. The transport adapters are Bun-specific,
not Node.js, browser, or edge-runtime adapters.

Until an npm release is published:

```sh
bun add github:cfal/noise-ws
```

Commit the resulting lockfile. The TypeScript source is the package entry point;
no transpilation step is needed with Bun. Prefer a reviewed commit over a moving
Git branch for deployed dependencies.

TypeScript consumers need `@types/bun`. The package exports generated declarations
and does not require `allowImportingTsExtensions` or disabling DOM libraries.
Declarations are checked in so Git installs also work without install hooks.

Generate a separate key per execution node, then provision it through a trusted
channel to both endpoints. Never put the key in a URL or command-line argument.

```sh
umask 077
openssl rand -out node.psk 32
```

## Client And Server

The library does not create an HTTP listener. Mount its adapter in `Bun.serve`:

```ts
import { createNoiseServer } from '@cfal/noise-ws';

const psk = new Uint8Array(await Bun.file(process.env.NOISE_PSK_FILE!).arrayBuffer());
const noise = createNoiseServer();

const server = Bun.serve({
  hostname: '0.0.0.0',
  port: 3000,
  websocket: noise.websocket,
  fetch(request, server) {
    if (new URL(request.url).pathname !== '/noise') {
      return new Response(null, { status: 404 });
    }
    return noise.upgrade(request, server, {
      psk,
      context: 'garcon/execution-node/v1',
      onMessage(socket, message) {
        socket.send(message);
      },
    });
  },
});

// On shutdown: noise.close(); await server.stop(true);
```

Dial with callbacks already installed. `onOpen` and `ready` mean **Noise key
confirmation completed**, not merely that the WebSocket upgraded:

```ts
import { connectNoiseWebSocket } from '@cfal/noise-ws';

const socket = connectNoiseWebSocket('ws://node.internal:3000/noise', {
  psk,
  context: 'garcon/execution-node/v1',
  onMessage(socket, message) {
    // Complete string or Uint8Array; never unauthenticated or partial plaintext.
  },
  onError(socket, error) {
    // Sanitized NoiseError with a stable .code. No raw transport diagnostics.
  },
  onClose(socket, info) {
    // info.authenticated: received the peer's encrypted CLOSE, not a receipt.
  },
});

await socket.ready;
socket.send('application message');
socket.send(new Uint8Array([1, 2, 3]));
socket.close();
await socket.closed;
```

`context` must match exactly: 1-1024 bytes of well-formed UTF-8, supplied by the
application rather than inferred from the URL. It binds keys to a protocol or
deployment. Do not use a rewritten host/path or a node UUID that one peer does
not know yet. The dialer is always the Noise initiator, regardless of which side
is the Garcon controller.

Runnable examples:

```sh
NOISE_PSK_FILE=./node.psk bun examples/server.ts
```

In another terminal:

```sh
NOISE_PSK_FILE=./node.psk bun examples/client.ts ws://localhost:3000/noise
```

## TLS And Proxies

For TLS on the listener, add ordinary Bun `tls: { key, cert }` options to
`Bun.serve`. The example server accepts `TLS_KEY_FILE` and `TLS_CERT_FILE`.
WebSocket-capable reverse proxies can forward ciphertext without possessing the
PSK. Noise remains end-to-end even if a proxy terminates outer TLS.

The client verifies `wss:` certificates and hostnames by default. For a private CA
or self-signed certificate, prefer supplying trust explicitly:

```ts
connectNoiseWebSocket('wss://node.internal/noise', {
  psk,
  context: 'garcon/execution-node/v1',
  tls: { ca: Bun.file('private-ca.pem') },
  onMessage() {},
});
```

`tls.serverName` can explicitly set the TLS server name. Setting
`allowUnverifiedTls: true` disables **outer TLS** certificate verification; it
never disables Noise authentication or permits plaintext fallback. Prefer
verified TLS for defense in depth and protection of HTTP/upgrade metadata.
Certificate fingerprint pinning is not implemented; see
[Bun issue #43635](https://github.com/oven-sh/bun/issues/43635).

An active intermediary may relay, delay, or drop the connection. Neither TLS
verification opt-out nor `ws:` gives that intermediary the PSK or accepted
application plaintext. Noise does not protect other HTTP routes, hide the
destination/path, prevent denial of service, or authenticate a peer's hostname.

## API And Flow Control

`NoiseWebSocket` exposes `ready`, `closed`, `readyState`, `bufferedAmount`,
`send(string | Uint8Array)`, and `close()`. There is no native-socket escape hatch,
late event-listener backlog, automatic reconnect, or application-message queue.
Sending before readiness throws `NOT_OPEN`.

`send()` is synchronous. It copies/encodes the message and writes canonical
encrypted fragments in order. `bufferedAmount` is the native socket's outstanding
wire bytes. Before encryption, the full message must fit the configured buffer
budget (including record/framing overhead). Otherwise `BACKPRESSURE` is thrown
without consuming any nonce and the connection remains usable. The caller may
retry that **application message** after the buffer drains, only while
`readyState === 'open'`.

Once encryption starts, any rejected/failed write is terminal. Never retry a
ciphertext. Native Bun `send() === -1` means accepted with backpressure; `0` means
dropped. The adapter preserves that distinction. There is no internal queue to
wake on `drain`; the host may observe server `drain`, or poll `bufferedAmount` for
client-side scheduling. Retain application data until your own receipt arrives.

The server callback adapter supplies `open`, `message`, and `close`, plus safe
dedicated-listener settings. `upgrade()` returns `undefined` on successful
upgrade, HTTP 400 on failure, or HTTP 503 on admission refusal. `noise.close()`
closes its connections and refuses future upgrades, but does not stop the host
HTTP server. `noise.size` counts its pending and established connections.

For a shared listener, dispatch by `socket.data.kind === 'noise-ws'` to the
adapter; use a distinct data tag for unrelated sockets. Compose the listener's
global payload, compression, idle, and backpressure settings deliberately.
See the type-checked, exercised composition in
[test/adapters.test.ts](test/adapters.test.ts). Do not override `open` or `close`
without forwarding them, or lifecycle/admission cleanup will be lost.

Callbacks are invoked in receive order but not awaited. Promise rejections close
the connection as `HANDLER_ERROR`; callers own bounds and ordering for their async
work. A successful `send()`, normal WebSocket close, or encrypted CLOSE is **not**
evidence that the peer consumed or persisted application data. A raw transport
close is reported as unauthenticated, even with WebSocket status 1000.

Client options additionally accept an `AbortSignal`. Cancellation closes the
physical connection and settles both lifecycle promises. Errors and closure are
reported at most once. The library never logs message/key material or echoes
native failure strings or peer-supplied WebSocket close reasons.

## Limits

Connection `limits` apply in both directions:

| Option | Default | Supported bound |
| --- | --- | --- |
| `handshakeTimeoutMs` | 5,000 | 1 to 2^31 - 1 |
| `messageTimeoutMs` | 30,000 | 1 to 2^31 - 1; total assembly deadline |
| `maxMessageBytes` | 16 MiB | 1 to 16 MiB, UTF-8 bytes for text |
| `maxBufferedBytes` | 32 MiB | 65,535 bytes to 128 MiB |
| `maxRecordsPerDirection` | 2^24 | 2 to 2^24 |

Both peers should use compatible limits. Empty text and binary messages are valid.
Raise the buffer limit above the largest logical message **plus wire overhead**;
an insufficient limit refuses that send without closing the connection.
Assembly timeout starts at the first fragment and is not extended by trickles.
The record ceiling limits each AES-GCM key to less than 1 TiB of ciphertext even
at maximum record size. At exhaustion the connection closes; the application must
reconnect with fresh keys. There is no rekey or nonce-reset API.

The server defaults to 64 total connections and 16 pending handshakes, configurable
through `createNoiseServer({ maxConnections, maxPendingHandshakes })`. These are
not process-wide memory or rate limits. The host must enforce upgrade rate limits,
credential lookup policy, authorization, and aggregate resource budgets.

## Garcon Integration

Use a new encrypted socket for every physical reconnect, in either dialing
direction. Keep `MessageSession` above it: existing logical-session HMAC hello,
node identity checks, heartbeats, receipts, replay, and reconnect continuity all
travel as encrypted application messages. Call Garcon's open handler only from
Noise `onOpen`, not Bun's physical `open`.

A nonsecret route selector may identify the execution node so the listener can
choose **one** PSK before upgrading. Do not trial-decrypt against a key registry.
Use unique random PSKs per node. If existing credentials are encoded random
32-byte keys, decode them strictly at the application boundary; never derive a
PSK by padding, truncating, or hashing a human password.

Map `bufferedAmount` to the transport's buffered-byte projection; retain Garcon's
bounded retry/receipt queues rather than creating a second queue here. The 16 MiB
logical-message ceiling accommodates Garcon frames; messages larger than one
Noise record are reassembled before Garcon sees them. Do not reuse this context
for unrelated protocols or treat shared-key possession as named peer identity.

## Standalone Bun Executables

Plain Bun compilation works without plugins, external addons, or runtime files:

```sh
bun build --compile ./app.ts --outfile ./app
```

Use Bun's normal `--target` for cross-compilation and test the resulting executable
on its target. This repository verifies native Linux x64 execution only.

## Development

```sh
bun install --frozen-lockfile --ignore-scripts
bun run check
bun run build
bun run test
bun run test:compile
bun run bench
```

Tests require OpenSSL for temporary self-signed TLS certificates. The compile test
packs the public package, installs it in isolation, type-checks a downstream
consumer with ordinary DOM-enabled settings, runs its client/server, builds a
standalone executable, deletes the entire build/dependency directory, and runs
that executable again. `bun run build` regenerates the checked-in `types/`.
Temporary files use `$HOME/tmp`, not RAM-backed `/tmp`.

`bun run test:interop` additionally requires Go 1.23+ and compares randomized
handshakes and ciphertexts against pinned `flynn/noise`. Its separate test-only
module is not a production dependency. See [interop/README.md](interop/README.md).

The benchmark measures actual loopback WebSockets, not just cipher operations:
handshake latency, 128-byte echo latency/streaming, and 16 MiB transfers. Treat
results as machine-specific; they are not security or production performance
guarantees.
