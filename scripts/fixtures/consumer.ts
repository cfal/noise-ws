import { connectNoiseWebSocket, createNoiseServer, type NoiseClientOptions, type NoiseSocketData, type NoiseWebSocket } from '@cfal/noise-ws';

const options = { psk: new Uint8Array(32), context: 'types-only', onMessage(_socket: NoiseWebSocket, _message: string | Uint8Array) {} };
const noise = createNoiseServer();
const socket: NoiseWebSocket = connectNoiseWebSocket('wss://example.invalid/', { ...options, tls: { ca: Bun.file('ca.pem') } });
const handler: Bun.WebSocketHandler<NoiseSocketData> = noise.websocket;
socket.send('typed');
void handler;

const unsupportedTls: NoiseClientOptions['tls'] = {
  ca: Bun.file('ca.pem'),
  // @ts-expect-error Bun WebSocket ignores serverName; hostname overrides are not supported.
  serverName: 'example.invalid',
};
void unsupportedTls;
