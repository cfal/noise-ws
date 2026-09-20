import { randomBytes } from 'node:crypto';
import { connectNoiseWebSocket, createNoiseServer } from '@cfal/noise-ws';

const psk = randomBytes(32);
const context = 'noise-ws-package-smoke/v1';
const noise = createNoiseServer();
const server = Bun.serve({
  hostname: '0.0.0.0', port: 0, websocket: noise.websocket,
  fetch(request, server) { return noise.upgrade(request, server, { psk, context, onMessage: (socket, message) => socket.send(message) }); },
});
const done = Promise.withResolvers<void>();
const payloads = ['packaged echo', Buffer.alloc(100_000, 71)];
let index = 0;
const socket = connectNoiseWebSocket(`ws://127.0.0.1:${server.port}/`, {
  psk, context,
  onMessage(socket, message) {
    const expected = payloads[index++]!;
    if (typeof message === 'string' ? message !== expected : !Buffer.from(message).equals(expected as Buffer)) {
      done.reject(new Error('Echo mismatch'));
      return;
    }
    if (index === payloads.length) done.resolve();
    else socket.send(payloads[index]!);
  },
  onError(_, error) { done.reject(error); },
});
const timer = setTimeout(() => done.reject(new Error('Smoke deadline exceeded')), 5_000);
try {
  await socket.ready;
  socket.send(payloads[0]!);
  await done.promise;
  console.log('Encrypted text and fragmented binary echo passed.');
} finally {
  clearTimeout(timer);
  socket.close();
  noise.close();
  await server.stop(true);
}
