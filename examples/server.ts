import { createNoiseServer } from '../src/index.ts';
import { loadKey } from './key.ts';

const psk = await loadKey();
const key = process.env.TLS_KEY_FILE;
const cert = process.env.TLS_CERT_FILE;
if (Boolean(key) !== Boolean(cert)) throw new Error('TLS_KEY_FILE and TLS_CERT_FILE must be set together');
const noise = createNoiseServer();
const server = Bun.serve({
  hostname: '0.0.0.0', port: Number(process.env.PORT ?? 3000),
  ...(key && cert ? { tls: { key: Bun.file(key), cert: Bun.file(cert) } } : {}),
  websocket: noise.websocket,
  fetch(request, server) {
    const path = new URL(request.url).pathname;
    if (path === '/health') return new Response('ok');
    if (path !== '/noise') return new Response(null, { status: 404 });
    return noise.upgrade(request, server, {
      psk, context: 'noise-ws-echo/v1', onMessage: (socket, message) => socket.send(message),
    });
  },
});
console.log(`Listening on ${cert ? 'https' : 'http'}://0.0.0.0:${server.port}; Noise route /noise`);
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, async () => {
  noise.close();
  await server.stop(true);
});
