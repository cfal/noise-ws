import { NoiseConnection } from './connection.ts';
import { type NoiseOptions } from './options.ts';
export interface NoiseSocketData {
    readonly kind: 'noise-ws';
    readonly connection: NoiseConnection;
}
export interface NoiseServerOptions {
    readonly maxConnections?: number;
    readonly maxPendingHandshakes?: number;
}
/** Owns admission and encrypted sockets, not the HTTP listener, routes, or PSK registry. */
export declare function createNoiseServer(options?: NoiseServerOptions): {
    websocket: Bun.WebSocketHandler<NoiseSocketData>;
    readonly size: number;
    upgrade(request: Request, server: Pick<Bun.Server<NoiseSocketData>, "upgrade">, connectionOptions: NoiseOptions): Response | undefined;
    close(): void;
};
