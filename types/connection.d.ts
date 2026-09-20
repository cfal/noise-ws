import { type NoiseErrorCode } from './errors.ts';
import { type NoiseCloseInfo, type NoiseOptions } from './options.ts';
export type NoiseReadyState = 'connecting' | 'handshaking' | 'confirming' | 'open' | 'closed';
/** Internal adapter contract. A successful write includes queued bytes, never a dropped frame. */
export interface NoiseTransport {
    readonly bufferedAmount: number;
    write(frame: Buffer): void;
    close(): void;
    abort(): void;
}
export interface NoiseWebSocket {
    readonly ready: Promise<void>;
    readonly closed: Promise<NoiseCloseInfo>;
    readonly readyState: NoiseReadyState;
    readonly bufferedAmount: number;
    send(message: string | Uint8Array): void;
    close(): void;
}
export declare class NoiseConnection implements NoiseWebSocket {
    #private;
    readonly ready: Promise<void>;
    readonly closed: Promise<NoiseCloseInfo>;
    /** Use connectNoiseWebSocket or createNoiseServer rather than constructing a socket directly. */
    constructor(initiator: boolean, options: NoiseOptions, onFinish?: () => void);
    get readyState(): NoiseReadyState;
    get bufferedAmount(): number;
    send(message: string | Uint8Array): void;
    close(): void;
    /** Adapter lifecycle: invoked exactly once after the physical WebSocket opens. */
    attach(transport: NoiseTransport): void;
    /** Adapter lifecycle: raw, complete binary WebSocket messages only. */
    receive(frame: unknown): void;
    /** Adapter lifecycle: raw errors and close reasons must never be trusted as Noise messages. */
    fail(code?: NoiseErrorCode): void;
}
