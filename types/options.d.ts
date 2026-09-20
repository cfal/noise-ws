import type { NoiseWebSocket } from './connection.ts';
import type { NoiseError } from './errors.ts';
export declare const NOISE_PROTOCOL = "Noise_NNpsk0_25519_AESGCM_SHA256";
export declare const MAX_FRAME_BYTES = 65535;
export declare const MAX_MESSAGE_BYTES: number;
export declare const MAX_RECORDS_PER_DIRECTION: number;
export interface NoiseCloseInfo {
    /** True only when the peer's encrypted close record was received. Not a delivery receipt. */
    readonly authenticated: boolean;
    readonly error: NoiseError | null;
}
export interface NoiseLimits {
    readonly handshakeTimeoutMs?: number;
    readonly messageTimeoutMs?: number;
    readonly maxMessageBytes?: number;
    readonly maxBufferedBytes?: number;
    readonly maxRecordsPerDirection?: number;
}
export interface NoiseOptions {
    /** Exactly 32 cryptographically random bytes, provisioned out of band. Not a password. */
    readonly psk: Uint8Array;
    /** Must match on both peers. Bind this connection to its application/protocol. */
    readonly context: string;
    readonly limits?: NoiseLimits;
    readonly onMessage: (socket: NoiseWebSocket, message: string | Uint8Array) => void;
    readonly onOpen?: (socket: NoiseWebSocket) => void;
    readonly onError?: (socket: NoiseWebSocket, error: NoiseError) => void;
    readonly onClose?: (socket: NoiseWebSocket, info: NoiseCloseInfo) => void;
}
export declare function resolveLimits(limits?: NoiseLimits): Required<NoiseLimits>;
export declare function connectionPrologue(context: string): Buffer;
