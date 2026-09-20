import { expect, test } from 'bun:test';
import { NoiseCipher } from '../src/cipher.ts';
import { NoiseCrypto } from '../src/crypto.ts';
import { NoiseConnection as NoiseWebSocket } from '../src/connection.ts';
import { MAX_RECORDS_PER_DIRECTION, connectionPrologue, resolveLimits } from '../src/options.ts';
import { MessageAssembler, messageRecords, recordCount } from '../src/records.ts';
import { context, deadline, pair, psk } from './helpers.ts';

test.each([0, 1, 65_513, 65_514, 65_515, 131_032, 131_033, 16 * 1024 * 1024])('canonical fragmentation round-trips %d bytes', (size) => {
  const payload = Buffer.alloc(size, 37);
  const records = [...messageRecords(payload, false)];
  expect(records.length).toBe(recordCount(size));
  expect(records.every((record) => record.length <= 65_519)).toBe(true);
  const assembler = new MessageAssembler();
  for (let i = 0; i < records.length; i++) {
    const message = assembler.receive(records[i]!, 16 * 1024 * 1024);
    if (i === records.length - 1) expect(Buffer.from(message as Uint8Array).equals(payload)).toBe(true);
    else expect(message).toBeNull();
  }
});

test('receiver record limit prevents extra decryption and clears the connection', async () => {
  const fixture = pair({}, { limits: { maxRecordsPerDirection: 2 } });
  fixture.start();
  await fixture.ready();
  fixture.left.send('last valid nonce');
  fixture.left.send('exhausted');
  expect((await deadline(fixture.right.closed)).error?.code).toBe('RECORD_LIMIT');
  expect(fixture.rightMessages).toEqual(['last valid nonce']);
  fixture.close();
});

test('message requiring too many records is rejected before any fragment is encrypted', async () => {
  const fixture = pair({ limits: { maxRecordsPerDirection: 2 } });
  fixture.start();
  await fixture.ready();
  const frames = fixture.leftFrames.length;
  expect(() => fixture.left.send(Buffer.alloc(65_515))).toThrow('record limit');
  expect(fixture.leftFrames.length).toBe(frames);
  expect((await fixture.left.closed).error?.code).toBe('RECORD_LIMIT');
  fixture.close();
});

test('cipher exhaustion is terminal in both directions, with no reset or retry', () => {
  const left = new NoiseCipher(psk, 2);
  const right = new NoiseCipher(psk, 2);
  expect(right.decrypt(left.encrypt(Buffer.from('first'))).toString()).toBe('first');
  expect(right.decrypt(left.encrypt(Buffer.from('last'))).toString()).toBe('last');
  expect(left.remaining).toBe(0);
  expect(() => left.encrypt(Buffer.alloc(1))).toThrow('record limit');
  expect(() => right.decrypt(Buffer.alloc(17))).toThrow('record limit');
  expect(() => left.encrypt(Buffer.alloc(1))).toThrow('closed');
  expect(() => right.decrypt(Buffer.alloc(17))).toThrow('closed');
  expect(MAX_RECORDS_PER_DIRECTION).toBe(2 ** 24);
});

test('sending the maximum message plus one fails before copying or writing', async () => {
  const fixture = pair();
  fixture.start();
  await fixture.ready();
  expect(() => fixture.left.send(Buffer.alloc(16 * 1024 * 1024 + 1))).toThrow('size limit');
  expect(fixture.left.readyState).toBe('open');
  expect(fixture.leftFrames.length).toBe(2);
  fixture.close();
});

test.each([0, 1, 2, 3])('write failure on handshake flight %d is terminal with no early callback', async (failedFlight) => {
  let opens = 0;
  let flight = 0;
  const fixture = pair({ onOpen() { opens++; } }, { onOpen() { opens++; } });
  fixture.filter = (frame) => {
    if (flight++ === failedFlight) throw new Error('Synthetic write failure');
    return frame;
  };
  fixture.start();
  await deadline(Promise.all([fixture.left.closed, fixture.right.closed]));
  expect(opens).toBe(0);
  fixture.close();
});

test('middle fragment write failure never delivers a partial application message', async () => {
  const fixture = pair();
  fixture.start();
  await fixture.ready();
  let count = 0;
  fixture.filter = (frame, from) => {
    if (from === 'left' && count++ === 1) throw new Error('Synthetic mid-message write failure');
    return frame;
  };
  expect(() => fixture.left.send(Buffer.alloc(200_000))).toThrow('transport failed');
  await deadline(fixture.right.closed);
  expect(fixture.rightMessages).toEqual([]);
  fixture.close();
});

test.each(['mutation', 'truncation', 'extension', 'reflection'])('rejects handshake %s', async (attack) => {
  const fixture = pair();
  fixture.filter = (frame, from) => {
    if (from !== 'left') return frame;
    if (attack === 'truncation') return frame.subarray(0, frame.length - 1);
    if (attack === 'extension') return Buffer.concat([frame, Buffer.alloc(1)]);
    if (attack === 'reflection') { queueMicrotask(() => fixture.left.receive(frame)); return null; }
    frame[frame.length - 1]! ^= 1;
    return frame;
  };
  fixture.start();
  await deadline(Promise.all([fixture.left.closed, fixture.right.closed]));
  expect(fixture.rightMessages).toEqual([]);
  fixture.close();
});

test('invalid keys, contexts and limits fail before opening a transport', () => {
  for (const key of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33)]) {
    expect(() => new NoiseCrypto(true, key, Buffer.alloc(0), MAX_RECORDS_PER_DIRECTION)).toThrow('exactly 32');
  }
  for (const invalid of ['', 'a'.repeat(1025), '\ud800']) expect(() => connectionPrologue(invalid)).toThrow();
  for (const limits of [{ maxMessageBytes: 0 }, { maxBufferedBytes: 65_534 }, { handshakeTimeoutMs: Infinity },
    { maxRecordsPerDirection: 2 ** 32 }, { maxRecordsPerDirection: 1 },
    { maxMessageBytes: 16 * 1024 * 1024 + 1 }]) expect(() => resolveLimits(limits)).toThrow();
  const socket = new NoiseWebSocket(true, { psk, context, onMessage() {} });
  socket.close();
  expect(socket.readyState).toBe('closed');
});
