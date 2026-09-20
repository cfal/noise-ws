export declare class NoiseCrypto {
    #private;
    private readonly recordLimit;
    constructor(initiator: boolean, psk: Uint8Array, prologue: Buffer, recordLimit: number);
    get sendRemaining(): number;
    sendHandshake(): Buffer;
    receiveHandshake(frame: Buffer): void;
    encrypt(plaintext: Buffer): Buffer;
    decrypt(ciphertext: Buffer): Buffer;
    destroy(): void;
}
