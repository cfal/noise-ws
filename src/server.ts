import { NoiseConnection } from './connection.ts';
import { MAX_FRAME_BYTES, type NoiseOptions } from './options.ts';

export interface NoiseSocketData {
  readonly kind: 'noise-ws';
  readonly connection: NoiseConnection;
}

export interface NoiseServerOptions {
  readonly maxConnections?: number;
  readonly maxPendingHandshakes?: number;
}

/** Owns admission and encrypted sockets, not the HTTP listener, routes, or PSK registry. */
export function createNoiseServer(options: NoiseServerOptions = {}) {
  const maxConnections = options.maxConnections ?? 64;
  const maxPending = options.maxPendingHandshakes ?? 16;
  for (const limit of [maxConnections, maxPending]) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new TypeError('Invalid Noise server admission limit');
  }
  const connections = new Set<NoiseConnection>();
  let disposed = false;
  const websocket: Bun.WebSocketHandler<NoiseSocketData> = {
    maxPayloadLength: MAX_FRAME_BYTES,
    perMessageDeflate: false,
    idleTimeout: 0,
    sendPings: false,
    backpressureLimit: 128 * 1024 * 1024,
    closeOnBackpressureLimit: true,
    open(socket) {
      socket.binaryType = 'nodebuffer';
      socket.data.connection.attach({
        get bufferedAmount() { return socket.getBufferedAmount(); },
        write(frame) {
          if (socket.send(frame, false) === 0) throw new Error('Socket dropped frame');
        },
        close: () => socket.close(1000),
        abort: () => socket.terminate(),
      });
    },
    message(socket, message) { socket.data.connection.receive(message); },
    close(socket) { socket.data.connection.fail('TRANSPORT_CLOSED'); },
  };

  return {
    websocket,
    get size(): number { return connections.size; },
    upgrade(
      request: Request,
      server: Pick<Bun.Server<NoiseSocketData>, 'upgrade'>,
      connectionOptions: NoiseOptions,
    ): Response | undefined {
      const pending = [...connections].filter((connection) => connection.readyState !== 'open').length;
      if (disposed || connections.size >= maxConnections || pending >= maxPending) {
        return new Response(null, { status: 503 });
      }
      const connection = new NoiseConnection(false, connectionOptions, () => {
        connections.delete(connection);
      });
      connections.add(connection);
      try {
        if (server.upgrade(request, { data: { kind: 'noise-ws', connection } })) return;
      } catch {
        // Failed upgrades release their admission and copied credentials.
      }
      connection.fail('TRANSPORT_ERROR');
      return new Response(null, { status: 400 });
    },
    close(): void {
      disposed = true;
      for (const connection of connections) connection.close();
    },
  };
}
