import { afterEach, expect, test } from 'bun:test';
import { connectNoiseWebSocket, createNoiseServer, type NoiseSocketData } from '../src/index.ts';
import { context, deadline, psk } from './helpers.ts';

const cleanups: (() => unknown | Promise<unknown>)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });

test('Noise composes with unrelated HTTP and WebSocket routes on one listener', async () => {
  const noise = createNoiseServer();
  type Data = NoiseSocketData | { kind: 'ordinary' };
  const server = Bun.serve<Data>({
    hostname: '0.0.0.0', port: 0,
    fetch(request, server) {
      const path = new URL(request.url).pathname;
      if (path === '/noise') return noise.upgrade(request, server, { psk, context, onMessage: (socket, data) => socket.send(data) });
      if (path === '/ordinary' && server.upgrade(request, { data: { kind: 'ordinary' } })) return;
      return new Response('healthy');
    },
    websocket: {
      ...noise.websocket,
      open(socket) {
        if (socket.data.kind === 'noise-ws') {
          socket.binaryType = 'blob';
          noise.websocket.open!(socket as Bun.ServerWebSocket<NoiseSocketData>);
          expect(String(socket.binaryType)).toBe('nodebuffer');
        }
        else socket.send('ordinary hello');
      },
      message(socket, data) {
        if (socket.data.kind === 'noise-ws') noise.websocket.message(socket as Bun.ServerWebSocket<NoiseSocketData>, data);
        else socket.send(data);
      },
      close(socket, code, reason) {
        if (socket.data.kind === 'noise-ws') noise.websocket.close!(socket as Bun.ServerWebSocket<NoiseSocketData>, code, reason);
      },
    },
  });
  cleanups.push(async () => { noise.close(); await server.stop(true); });
  expect(await (await fetch(`http://localhost:${server.port}/health`)).text()).toBe('healthy');
  const ordinary = new WebSocket(`ws://localhost:${server.port}/ordinary`);
  cleanups.push(() => ordinary.terminate());
  const ordinaryMessages: string[] = [];
  const ordinaryDone = Promise.withResolvers<void>();
  ordinary.onmessage = (event) => {
    ordinaryMessages.push(event.data);
    if (ordinaryMessages.length === 1) ordinary.send('ordinary echo');
    else ordinaryDone.resolve();
  };
  const encryptedDone = Promise.withResolvers<string | Uint8Array>();
  const encrypted = connectNoiseWebSocket(`ws://localhost:${server.port}/noise`, {
    psk, context, onOpen(socket) { socket.send('encrypted echo'); },
    onMessage(_, message) { encryptedDone.resolve(message); },
  });
  cleanups.push(() => encrypted.close());
  expect(await deadline(encryptedDone.promise)).toBe('encrypted echo');
  await deadline(ordinaryDone.promise);
  expect(ordinaryMessages).toEqual(['ordinary hello', 'ordinary echo']);
  expect(noise.size).toBe(1);
});

test('pending and total connection limits recover after timeout and close', async () => {
  const noise = createNoiseServer({ maxConnections: 2, maxPendingHandshakes: 1 });
  const server = Bun.serve({
    hostname: '0.0.0.0', port: 0, websocket: noise.websocket,
    fetch(request, server) { return noise.upgrade(request, server, { psk, context, limits: { handshakeTimeoutMs: 150 }, onMessage() {} }); },
  });
  cleanups.push(async () => { noise.close(); await server.stop(true); });
  const url = `ws://localhost:${server.port}/`;
  const raw = new WebSocket(url);
  cleanups.push(() => raw.terminate());
  const rawOpen = Promise.withResolvers<void>();
  const rawClosed = Promise.withResolvers<void>();
  raw.onopen = () => rawOpen.resolve();
  raw.onclose = () => rawClosed.resolve();
  await deadline(rawOpen.promise);
  expect(noise.size).toBe(1);
  expect((await fetch(url.replace('ws:', 'http:'))).status).toBe(503);
  await deadline(rawClosed.promise);
  expect(noise.size).toBe(0);
  for (let i = 0; i < 2; i++) {
    const socket = connectNoiseWebSocket(url, { psk, context, onMessage() {} });
    cleanups.push(() => socket.close());
    await deadline(socket.ready);
  }
  expect(noise.size).toBe(2);
  expect((await fetch(url.replace('ws:', 'http:'))).status).toBe(503);
  noise.close();
  expect(noise.size).toBe(0);
});

test('Bun accepted-but-backpressured writes are never retried and drain without corrupting nonces', async () => {
  const noise = createNoiseServer();
  const statuses: number[] = [];
  const drained = Promise.withResolvers<void>();
  const payload = Buffer.alloc(16 * 1024 * 1024, 73);
  const server = Bun.serve({
    hostname: '0.0.0.0', port: 0,
    fetch(request, server) {
      return noise.upgrade(request, server, {
        psk, context, onMessage() {}, onOpen(socket) { socket.send(payload); socket.send('after pressure'); },
      });
    },
    websocket: {
      ...noise.websocket,
      open(socket) {
        const send = socket.send.bind(socket);
        socket.send = (...args) => { const result = send(...args); statuses.push(result); return result; };
        noise.websocket.open!(socket);
      },
      drain() { drained.resolve(); },
    },
  });
  cleanups.push(async () => { noise.close(); await server.stop(true); });
  const messages: (string | Uint8Array)[] = [];
  const done = Promise.withResolvers<void>();
  const socket = connectNoiseWebSocket(`ws://localhost:${server.port}/`, {
    psk, context, onMessage(_, message) { messages.push(message); if (messages.length === 2) done.resolve(); },
  });
  cleanups.push(() => socket.close());
  await deadline(done.promise, 5_000);
  expect(statuses).toContain(-1);
  expect(statuses).not.toContain(0);
  await deadline(drained.promise);
  expect(messages[0]).toEqual(payload);
  expect(messages[1]).toBe('after pressure');
  expect(socket.readyState).toBe('open');
});

test('a relay without the PSK only sees ciphertext; mutation terminates the encrypted connection', async () => {
  const noise = createNoiseServer();
  const delivered: (string | Uint8Array)[] = [];
  const backend = Bun.serve({
    hostname: '0.0.0.0', port: 0, websocket: noise.websocket,
    fetch(request, server) {
      return noise.upgrade(request, server, { psk, context, onMessage(socket, message) { delivered.push(message); socket.send(message); } });
    },
  });
  cleanups.push(async () => { noise.close(); await backend.stop(true); });
  const captures: Buffer[] = [];
  let tamper = false;
  type RelayData = { upstream?: WebSocket; pending: Buffer[] };
  const relay = Bun.serve<RelayData>({
    hostname: '0.0.0.0', port: 0,
    fetch(request, server) {
      if (server.upgrade(request, { data: { pending: [] } })) return;
      return new Response(null, { status: 400 });
    },
    websocket: {
      open(socket) {
        const upstream = new WebSocket(`ws://localhost:${backend.port}/`);
        socket.data.upstream = upstream;
        upstream.binaryType = 'arraybuffer';
        upstream.onopen = () => { for (const frame of socket.data.pending.splice(0)) upstream.send(frame); };
        upstream.onmessage = (event) => { captures.push(Buffer.from(event.data)); socket.send(event.data); };
        upstream.onclose = () => socket.terminate();
        upstream.onerror = () => socket.terminate();
      },
      message(socket, message) {
        const frame = Buffer.from(message);
        captures.push(Buffer.from(frame));
        if (tamper) frame[frame.length - 1]! ^= 1;
        if (socket.data.upstream?.readyState === WebSocket.OPEN) socket.data.upstream.send(frame);
        else socket.data.pending.push(frame);
      },
      close(socket) { socket.data.upstream?.terminate(); },
    },
  });
  cleanups.push(() => relay.stop(true));
  const echoed = Promise.withResolvers<string | Uint8Array>();
  const socket = connectNoiseWebSocket(`ws://localhost:${relay.port}/`, { psk, context, onMessage(_, message) { echoed.resolve(message); } });
  cleanups.push(() => socket.close());
  await deadline(socket.ready);
  socket.send('private application payload');
  expect(await deadline(echoed.promise)).toBe('private application payload');
  for (const frame of captures) {
    expect(frame.includes(psk)).toBe(false);
    expect(frame.includes(Buffer.from('private application payload'))).toBe(false);
    expect(frame.includes(Buffer.from(context))).toBe(false);
  }
  tamper = true;
  socket.send('must not arrive');
  await deadline(socket.closed);
  expect(delivered).toEqual(['private application payload']);
});
