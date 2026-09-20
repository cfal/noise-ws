import { expect, test } from 'bun:test';
import { createPrivateKey } from 'node:crypto';
import { NoiseHandshake } from '../src/handshake.ts';
import { NoiseCipher } from '../src/cipher.ts';
import { NOISE_PROTOCOL } from '../src/options.ts';
import vector from './fixtures/cacophony.json';

// Public-domain vector from the independent Haskell Noise implementation.
// https://github.com/centromere/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt#L8716-L8750
test('matches the published Cacophony NNpsk0 handshake hash and every transport ciphertext', () => {
  expect(vector.protocol_name).toBe(NOISE_PROTOCOL);
  const key = (hex: string) => createPrivateKey({ key: Buffer.from('302e020100300506032b656e04220420' + hex, 'hex'), format: 'der', type: 'pkcs8' });
  const left = new NoiseHandshake(true, Buffer.from(vector.init_psks[0]!, 'hex'), Buffer.from(vector.init_prologue, 'hex'), key(vector.init_ephemeral));
  const right = new NoiseHandshake(false, Buffer.from(vector.resp_psks[0]!, 'hex'), Buffer.from(vector.resp_prologue, 'hex'), key(vector.resp_ephemeral));
  for (let i = 0; i < 2; i++) {
    const message = vector.messages[i]!;
    const [sender, receiver] = i === 0 ? [left, right] : [right, left];
    const ciphertext = sender.write(Buffer.from(message.payload, 'hex'));
    expect(ciphertext.toString('hex')).toBe(message.ciphertext);
    expect(receiver.read(Buffer.from(ciphertext)).toString('hex')).toBe(message.payload);
  }
  const a = left.finish();
  const b = right.finish();
  expect(a.hash.toString('hex')).toBe(vector.handshake_hash);
  expect(b.hash.toString('hex')).toBe(vector.handshake_hash);
  const senders = [new NoiseCipher(a.tx), new NoiseCipher(b.tx)];
  const receivers = [new NoiseCipher(b.rx), new NoiseCipher(a.rx)];
  for (let i = 2; i < vector.messages.length; i++) {
    const message = vector.messages[i]!;
    const ciphertext = senders[i % 2]!.encrypt(Buffer.from(message.payload, 'hex'));
    expect(ciphertext.toString('hex')).toBe(message.ciphertext);
    expect(receivers[i % 2]!.decrypt(ciphertext).toString('hex')).toBe(message.payload);
  }
});
