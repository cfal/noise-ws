import { afterEach, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createNoiseServer, connectNoiseWebSocket, type NoiseOptions, type NoiseSocketData, type NoiseWebSocket } from '../src/index.ts';
import { context, deadline, psk } from './helpers.ts';

const cleanups: (() => unknown | Promise<unknown>)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });

function fixture(options: Partial<NoiseOptions> = {}, tls?: Bun.TLSOptions) {
  const noise = createNoiseServer();
  const opened = Promise.withResolvers<NoiseWebSocket>();
  const server = Bun.serve<NoiseSocketData>({
    hostname: '0.0.0.0', port: 0,
    ...(tls ? { tls } : {}),
    fetch(request, server) {
      if (new URL(request.url).pathname !== '/node') return new Response(null, { status: 404 });
      return noise.upgrade(request, server, { psk, context, onOpen: (socket) => opened.resolve(socket),
        onMessage: (socket, message) => socket.send(message), ...options });
    },
    websocket: noise.websocket,
  });
  cleanups.push(async () => { noise.close(); await server.stop(true); });
  return { noise, server, url: `${tls ? 'wss' : 'ws'}://localhost:${server.port}/node`, opened: opened.promise };
}

test('Bun client and server exchange 16 MiB, streaming text and immediate onOpen messages over plain WS', async () => {
  const incoming: (string | Uint8Array)[] = [];
  const smallDone = Promise.withResolvers<void>();
  const bigDone = Promise.withResolvers<Uint8Array>();
  const { url } = fixture({ onOpen(socket) { socket.send('server-first'); } });
  const socket = connectNoiseWebSocket(url, {
    psk, context,
    onOpen(socket) { socket.send('client-first'); },
    onMessage(_socket, message) {
      if (typeof message !== 'string') { bigDone.resolve(message); return; }
      incoming.push(message);
      if (incoming.length === 102) smallDone.resolve();
    },
  });
  cleanups.push(() => socket.close());
  await deadline(socket.ready);
  for (let i = 0; i < 100; i++) socket.send(`token-${i}`);
  await deadline(smallDone.promise);
  expect(incoming).toEqual(['server-first', 'client-first', ...Array.from({ length: 100 }, (_, i) => `token-${i}`)]);
  const big = Buffer.alloc(16 * 1024 * 1024, 19);
  socket.send(big);
  expect(Buffer.from(await deadline(bigDone.promise, 5_000)).equals(big)).toBe(true);
});

test('wrong PSK cannot open the real server and does not hold admission', async () => {
  let opens = 0;
  const { url, noise } = fixture({ onOpen() { opens++; } });
  const socket = connectNoiseWebSocket(url, { psk: Buffer.alloc(32, 91), context, onMessage() {} });
  await expect(deadline(socket.ready)).rejects.toBeDefined();
  await deadline(socket.closed);
  expect(opens).toBe(0);
  expect(noise.size).toBe(0);
});

test('failed upgrades release admission and server close rejects future upgrades', async () => {
  const { url, noise } = fixture();
  const response = await fetch(url.replace('ws:', 'http:'));
  expect(response.status).toBe(400);
  expect(noise.size).toBe(0);
  noise.close();
  expect((await fetch(url.replace('ws:', 'http:'))).status).toBe(503);
});

test('stalled raw clients time out and free their copied-key state', async () => {
  const { url, noise } = fixture({ limits: { handshakeTimeoutMs: 30 } });
  const raw = new WebSocket(url);
  const closed = Promise.withResolvers<void>();
  raw.addEventListener('close', () => closed.resolve());
  await deadline(closed.promise);
  expect(noise.size).toBe(0);
});

test('plaintext protocol downgrade and oversized binary frames fail closed', async () => {
  for (const data of ['{"type":"hello"}', Buffer.alloc(65_536)]) {
    const { url, noise } = fixture();
    const raw = new WebSocket(url);
    const closed = Promise.withResolvers<void>();
    raw.addEventListener('open', () => raw.send(data));
    raw.addEventListener('close', () => closed.resolve());
    await deadline(closed.promise);
    expect(noise.size).toBe(0);
  }
});

test('abort, already-aborted signals and refusal settle both promises', async () => {
  const { url } = fixture();
  const signal = new AbortController();
  const socket = connectNoiseWebSocket(url, { psk, context, signal: signal.signal, onMessage() {} });
  await deadline(socket.ready);
  signal.abort();
  expect((await deadline(socket.closed)).error?.code).toBe('CLOSED');
  const already = connectNoiseWebSocket(url, { psk, context, signal: signal.signal, onMessage() {} });
  await expect(already.ready).rejects.toBeDefined();
  expect(already.readyState).toBe('closed');
  const refused = connectNoiseWebSocket('ws://127.0.0.1:1/', { psk, context, onMessage() {} });
  await expect(deadline(refused.ready)).rejects.toBeDefined();
  await deadline(refused.closed);
});

test.each(['localhost', '127.0.0.1'])('TLS verifies the URL host %s; trusted CA or unverified TLS still requires the correct PSK', async (host) => {
  await mkdir(join(homedir(), 'tmp'), { recursive: true });
  const root = await mkdtemp(join(homedir(), 'tmp/noise-ws-tls-'));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  const subjectAlternativeName = host === 'localhost' ? `DNS:${host}` : `IP:${host}`;
  const proc = Bun.spawn(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', join(root, 'key.pem'), '-out', join(root, 'cert.pem'), '-days', '1', '-subj', `/CN=${host}`,
    '-addext', `subjectAltName=${subjectAlternativeName}`], { stdout: 'ignore', stderr: 'pipe' });
  const stderr = new Response(proc.stderr).text();
  if (await proc.exited !== 0) throw new Error(await stderr);
  await stderr;
  const cert = Bun.file(join(root, 'cert.pem'));
  const { url: fixtureUrl } = fixture({}, { cert, key: Bun.file(join(root, 'key.pem')) });
  const url = new URL(fixtureUrl);
  url.hostname = host;
  const untrusted = connectNoiseWebSocket(url, { psk, context, onMessage() {} });
  await expect(deadline(untrusted.ready)).rejects.toBeDefined();
  const wrongUrl = new URL(url);
  wrongUrl.hostname = host === 'localhost' ? '127.0.0.1' : 'localhost';
  const wrongHost = connectNoiseWebSocket(wrongUrl, { psk, context, tls: { ca: cert }, onMessage() {} });
  await expect(deadline(wrongHost.ready)).rejects.toBeDefined();
  for (const options of [{ tls: { ca: cert } }, { allowUnverifiedTls: true }]) {
    const socket = connectNoiseWebSocket(url, { psk, context, onMessage() {}, ...options });
    cleanups.push(() => socket.close());
    await deadline(socket.ready);
    const wrong = connectNoiseWebSocket(url, { psk: Buffer.alloc(32, 99), context, onMessage() {}, ...options });
    await expect(deadline(wrong.ready)).rejects.toBeDefined();
  }
});

test('rejects credentials in URLs without echoing them', () => {
  for (const url of ['wss://host/#secret=sensitive', 'wss://user:sensitive@host/', 'sensitive', 'http://host/']) {
    let failure: unknown;
    try { connectNoiseWebSocket(url, { psk, context, onMessage() {} }); } catch (error) { failure = error; }
    expect(failure).toBeInstanceOf(TypeError);
    expect(String(failure)).not.toContain('sensitive');
  }
});
