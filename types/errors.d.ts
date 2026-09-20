declare const messages: {
    readonly AUTHENTICATION_FAILED: "Noise authentication failed";
    readonly PROTOCOL_ERROR: "Invalid encrypted WebSocket protocol message";
    readonly HANDSHAKE_TIMEOUT: "Noise handshake timed out";
    readonly MESSAGE_TIMEOUT: "Encrypted message assembly timed out";
    readonly MESSAGE_TOO_LARGE: "Message exceeds the configured size limit";
    readonly BACKPRESSURE: "Encrypted WebSocket buffer limit exceeded";
    readonly RECORD_LIMIT: "Noise record limit reached; reconnect with fresh keys";
    readonly TRANSPORT_ERROR: "WebSocket transport failed";
    readonly TRANSPORT_CLOSED: "WebSocket closed without an authenticated close record";
    readonly HANDLER_ERROR: "Encrypted WebSocket handler failed";
    readonly NOT_OPEN: "Encrypted WebSocket is not open";
    readonly CLOSED: "Encrypted WebSocket is closed";
};
export type NoiseErrorCode = keyof typeof messages;
export declare class NoiseError extends Error {
    readonly code: NoiseErrorCode;
    readonly name = "NoiseError";
    constructor(code: NoiseErrorCode);
}
export {};
