import { type KeyObject } from 'node:crypto';
/** Fixed NNpsk0 only: -> psk,e; <- e,ee. No pattern interpreter or negotiation. */
export declare class NoiseHandshake {
    #private;
    private readonly initiator;
    constructor(initiator: boolean, psk: Uint8Array, prologue: Buffer, ephemeral?: KeyObject);
    get complete(): boolean;
    write(payload?: Buffer): Buffer;
    read(message: Buffer): Buffer;
    finish(): {
        tx: Buffer;
        rx: Buffer;
        hash: Buffer;
    };
    destroy(): void;
}
