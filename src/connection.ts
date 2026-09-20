import { NoiseCrypto } from './crypto.ts';
import { NoiseError, type NoiseErrorCode } from './errors.ts';
import { connectionPrologue, MAX_FRAME_BYTES, resolveLimits, type NoiseCloseInfo, type NoiseOptions } from './options.ts';
import { CLIENT_READY, SERVER_READY, CLOSE, MessageAssembler, encodedBytes, messageRecords, recordCount } from './records.ts';

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

export class NoiseConnection implements NoiseWebSocket {
  readonly ready: Promise<void>;
  readonly closed: Promise<NoiseCloseInfo>;
  #ready = Promise.withResolvers<void>();
  #closed = Promise.withResolvers<NoiseCloseInfo>();
  #crypto: NoiseCrypto;
  #transport: NoiseTransport | null = null;
  #status: NoiseReadyState = 'connecting';
  #options: NoiseOptions;
  #limits: ReturnType<typeof resolveLimits>;
  #assembler = new MessageAssembler();
  #handshakeTimer: ReturnType<typeof setTimeout>;
  #messageTimer: ReturnType<typeof setTimeout> | null = null;
  #onFinish: () => void;
  #initiator: boolean;

  /** Use connectNoiseWebSocket or createNoiseServer rather than constructing a socket directly. */
  constructor(initiator: boolean, options: NoiseOptions, onFinish: () => void = () => {}) {
    if (typeof options.onMessage !== 'function') throw new TypeError('An onMessage handler is required');
    this.#limits = resolveLimits(options.limits);
    this.#crypto = new NoiseCrypto(initiator, options.psk, connectionPrologue(options.context), this.#limits.maxRecordsPerDirection);
    // Does not retain the caller's key after the crypto engine has copied it.
    this.#options = { ...options, psk: new Uint8Array(0) };
    this.#initiator = initiator;
    this.#onFinish = onFinish;
    this.ready = this.#ready.promise;
    this.closed = this.#closed.promise;
    void this.ready.catch(() => {});
    this.#handshakeTimer = setTimeout(() => this.fail('HANDSHAKE_TIMEOUT'), this.#limits.handshakeTimeoutMs);
    this.#handshakeTimer.unref();
  }

  get readyState(): NoiseReadyState { return this.#status; }
  get bufferedAmount(): number { return this.#transport?.bufferedAmount ?? 0; }

  send(message: string | Uint8Array): void {
    if (this.#status !== 'open') throw new NoiseError('NOT_OPEN');
    if (typeof message !== 'string' && !(message instanceof Uint8Array)) {
      throw new TypeError('Messages must be strings or Uint8Arrays');
    }
    const length = typeof message === 'string' ? Buffer.byteLength(message) : message.byteLength;
    if (length > this.#limits.maxMessageBytes) throw new NoiseError('MESSAGE_TOO_LARGE');
    if (this.bufferedAmount + encodedBytes(length) > this.#limits.maxBufferedBytes) throw new NoiseError('BACKPRESSURE');
    try {
      if (recordCount(length) > this.#crypto.sendRemaining) throw new NoiseError('RECORD_LIMIT');
      const payload = Buffer.from(message);
      for (const record of messageRecords(payload, typeof message === 'string')) {
        this.#write(this.#crypto.encrypt(record));
      }
    } catch (error) {
      const failure = error instanceof NoiseError ? error : new NoiseError('TRANSPORT_ERROR');
      this.#finish(false, failure);
      throw failure;
    }
  }

  close(): void {
    if (this.#status === 'closed') return;
    if (this.#status !== 'open') {
      this.#finish(false, new NoiseError('CLOSED'));
      return;
    }
    try {
      this.#write(this.#crypto.encrypt(Buffer.from([CLOSE])));
    } catch (error) {
      this.#finish(false, error instanceof NoiseError ? error : new NoiseError('TRANSPORT_ERROR'));
      return;
    }
    this.#finish(false, null);
  }

  /** Adapter lifecycle: invoked exactly once after the physical WebSocket opens. */
  attach(transport: NoiseTransport): void {
    if (this.#status === 'closed') {
      transport.abort();
      return;
    }
    if (this.#transport) {
      transport.abort();
      this.fail('PROTOCOL_ERROR');
      return;
    }
    this.#transport = transport;
    this.#status = 'handshaking';
    if (this.#initiator) {
      try {
        this.#write(this.#crypto.sendHandshake());
      } catch {
        this.fail('TRANSPORT_ERROR');
      }
    }
  }

  /** Adapter lifecycle: raw, complete binary WebSocket messages only. */
  receive(frame: unknown): void {
    if (this.#status === 'closed') return;
    try {
      if (!(frame instanceof ArrayBuffer) && !(frame instanceof Uint8Array)) {
        throw new NoiseError('PROTOCOL_ERROR');
      }
      const bytes = frame instanceof ArrayBuffer
        ? Buffer.from(frame)
        : Buffer.from(frame.buffer, frame.byteOffset, frame.byteLength);
      if (bytes.length > MAX_FRAME_BYTES || bytes.length < 17) throw new NoiseError('PROTOCOL_ERROR');

      if (this.#status === 'handshaking') {
        if (bytes.length !== 48) throw new NoiseError('PROTOCOL_ERROR');
        this.#crypto.receiveHandshake(bytes);
        this.#status = 'confirming';
        if (this.#initiator) {
          this.#write(this.#crypto.encrypt(Buffer.from([CLIENT_READY])));
        } else {
          this.#write(this.#crypto.sendHandshake());
        }
        return;
      }

      const record = this.#crypto.decrypt(bytes);
      if (this.#status === 'confirming') {
        const expectedConfirmation = this.#initiator ? SERVER_READY : CLIENT_READY;
        if (record.length !== 1 || record[0] !== expectedConfirmation) {
          throw new NoiseError('PROTOCOL_ERROR');
        }
        if (!this.#initiator) {
          this.#write(this.#crypto.encrypt(Buffer.from([SERVER_READY])));
        }
        this.#status = 'open';
        clearTimeout(this.#handshakeTimer);
        this.#ready.resolve();
        this.#invoke(() => this.#options.onOpen?.(this));
        return;
      }

      if (this.#status !== 'open') throw new NoiseError('PROTOCOL_ERROR');
      if (record[0] === CLOSE) {
        if (record.length !== 1 || this.#assembler.active) throw new NoiseError('PROTOCOL_ERROR');
        this.#finish(true, null);
        return;
      }

      const message = this.#assembler.receive(record, this.#limits.maxMessageBytes);
      if (message !== null) {
        if (this.#messageTimer) clearTimeout(this.#messageTimer);
        this.#messageTimer = null;
        this.#invoke(() => this.#options.onMessage(this, message));
      } else if (!this.#messageTimer) {
        this.#messageTimer = setTimeout(() => this.fail('MESSAGE_TIMEOUT'), this.#limits.messageTimeoutMs);
        this.#messageTimer.unref();
      }
    } catch (error) {
      this.#finish(false, error instanceof NoiseError ? error : new NoiseError('AUTHENTICATION_FAILED'));
    }
  }

  /** Adapter lifecycle: raw errors and close reasons must never be trusted as Noise messages. */
  fail(code: NoiseErrorCode = 'TRANSPORT_ERROR'): void { this.#finish(false, new NoiseError(code)); }

  #write(frame: Buffer): void {
    if (this.#status === 'closed' || !this.#transport) throw new NoiseError('CLOSED');
    if (this.bufferedAmount + frame.length + 14 > this.#limits.maxBufferedBytes) throw new NoiseError('BACKPRESSURE');
    try {
      this.#transport.write(frame);
    } catch {
      throw new NoiseError('TRANSPORT_ERROR');
    }
  }

  #invoke(callback: () => unknown): void {
    try {
      const result = callback();
      // Invocation is ordered; callers own any asynchronous work and its queue bounds.
      if (result && typeof (result as PromiseLike<unknown>).then === 'function') {
        void Promise.resolve(result).catch(() => this.fail('HANDLER_ERROR'));
      }
    } catch {
      this.fail('HANDLER_ERROR');
    }
  }

  #finish(authenticated: boolean, error: NoiseError | null): void {
    if (this.#status === 'closed') return;
    this.#status = 'closed';
    clearTimeout(this.#handshakeTimer);
    if (this.#messageTimer) clearTimeout(this.#messageTimer);
    this.#messageTimer = null;
    this.#assembler.clear();
    this.#crypto.destroy();
    this.#ready.reject(error ?? new NoiseError('CLOSED'));
    const info = { authenticated, error };
    this.#closed.resolve(info);
    try {
      if (error) {
        this.#transport?.abort();
      } else {
        this.#transport?.close();
      }
    } catch {
      // Transport teardown cannot prevent key cleanup or settlement.
    }
    this.#transport = null;
    this.#onFinish();
    if (error) this.#invoke(() => this.#options.onError?.(this, error));
    this.#invoke(() => this.#options.onClose?.(this, info));
  }
}
