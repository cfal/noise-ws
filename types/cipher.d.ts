/** Noise AESGCM: 32 zero bits followed by a big-endian 64-bit counter. */
export declare class NoiseCipher {
    #private;
    private readonly limit;
    constructor(key: Uint8Array, limit?: number);
    get remaining(): number;
    encrypt(plaintext: Buffer, additionalData?: Buffer): Buffer;
    decrypt(ciphertext: Buffer, additionalData?: Buffer): Buffer;
    destroy(): void;
}
