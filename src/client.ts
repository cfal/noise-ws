import { NoiseConnection, type NoiseWebSocket } from './connection.ts';
import type { NoiseOptions } from './options.ts';

export interface NoiseClientOptions extends NoiseOptions {
  readonly tls?: Pick<Bun.TLSOptions, 'ca' | 'serverName'>;
  /** Opt-in for an unverified outer TLS layer. Noise authentication remains mandatory. */
  readonly allowUnverifiedTls?: boolean;
  readonly signal?: AbortSignal;
}

export function connectNoiseWebSocket(address: string | URL, options: NoiseClientOptions): NoiseWebSocket {
  let url: URL;
  try { url = new URL(address); }
  catch { throw new TypeError('Invalid encrypted WebSocket URL'); }
  if (!['ws:', 'wss:'].includes(url.protocol) || url.hash || url.username || url.password) {
    throw new TypeError('Expected ws: or wss: without URL credentials or a fragment');
  }
  let socket: WebSocket | undefined;
  const signal = options.signal;
  const abort = () => {
    connection.fail('CLOSED');
    socket?.terminate();
  };
  const connection = new NoiseConnection(true, options, () => {
    signal?.removeEventListener('abort', abort);
    if (socket?.readyState === WebSocket.CONNECTING) socket.terminate();
  });
  if (signal?.aborted) { connection.fail('CLOSED'); return connection; }
  try {
    // Pinning can be reconsidered after https://github.com/oven-sh/bun/issues/43635.
    socket = new WebSocket(url, { perMessageDeflate: false, tls: { ...options.tls, rejectUnauthorized: options.allowUnverifiedTls !== true } });
    socket.binaryType = 'arraybuffer';
    const transport = socket;
    socket.addEventListener('open', () => connection.attach({
      get bufferedAmount() { return transport.bufferedAmount; },
      write(frame) {
        if (transport.readyState !== WebSocket.OPEN) throw new Error('Socket is not open');
        transport.send(frame);
      },
      close: () => transport.close(1000),
      abort: () => transport.terminate(),
    }));
    socket.addEventListener('message', (event) => {
      if (event.data instanceof ArrayBuffer || typeof event.data === 'string') connection.receive(event.data);
      else connection.fail('PROTOCOL_ERROR');
    });
    socket.addEventListener('error', () => connection.fail());
    socket.addEventListener('close', () => connection.fail('TRANSPORT_CLOSED'));
    signal?.addEventListener('abort', abort, { once: true });
  } catch { connection.fail(); }
  return connection;
}
