import { connectNoiseWebSocket } from '../src/index.ts';
import { loadKey } from './key.ts';

const address = process.argv[2];
if (!address) throw new Error('Usage: bun examples/client.ts ws[s]://host:port/noise');
const done = Promise.withResolvers<void>();
const socket = connectNoiseWebSocket(address, {
  psk: await loadKey(), context: 'noise-ws-echo/v1',
  ...(process.env.TLS_CA_FILE ? { tls: { ca: Bun.file(process.env.TLS_CA_FILE) } } : {}),
  onOpen(socket) { socket.send('hello over Noise'); },
  onMessage(_socket, message) {
    if (message === 'hello over Noise') { console.log('Authenticated encrypted echo received.'); done.resolve(); }
    else done.reject(new Error('Unexpected echo'));
  },
  onError(_socket, error) { done.reject(error); },
});
const timer = setTimeout(() => done.reject(new Error('Echo deadline exceeded')), 5_000);
try { await done.promise; }
finally { clearTimeout(timer); socket.close(); }
