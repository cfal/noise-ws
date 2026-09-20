export declare const CLIENT_READY = 1;
export declare const SERVER_READY = 2;
export declare const CLOSE = 3;
export declare function recordCount(length: number): number;
export declare function encodedBytes(length: number): number;
export declare function messageRecords(payload: Buffer, text: boolean): Generator<Buffer>;
export declare class MessageAssembler {
    #private;
    get active(): boolean;
    receive(record: Buffer, maxBytes: number): string | Uint8Array | null;
    clear(): void;
}
