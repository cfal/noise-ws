import { type NoiseWebSocket } from './connection.ts';
import type { NoiseOptions } from './options.ts';
export interface NoiseClientOptions extends NoiseOptions {
    readonly tls?: Pick<Bun.TLSOptions, 'ca' | 'serverName'>;
    /** Opt-in for an unverified outer TLS layer. Noise authentication remains mandatory. */
    readonly allowUnverifiedTls?: boolean;
    readonly signal?: AbortSignal;
}
export declare function connectNoiseWebSocket(address: string | URL, options: NoiseClientOptions): NoiseWebSocket;
