import assert from 'node:assert/strict';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { NoiseHandshake } from '../src/handshake.ts';
import { NoiseCipher } from '../src/cipher.ts';

const temporary = join(homedir(), 'tmp');
await mkdir(temporary, { recursive: true });
const root = await mkdtemp(join(temporary, 'noise-ws-interop-'));
const binary = join(root, process.platform === 'win32' ? 'reference.exe' : 'reference');
const hex = (length: number) => randomBytes(length).toString('hex');
const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1024, 65_519];
const cases = Array.from({ length: 20 }, (_, index) => ({
  psk: hex(32), prologue: hex(index * 53), initiator: hex(32), responder: hex(32),
  payloads: [hex(index === 0 ? 65_487 : index), hex(index === 1 ? 65_487 : index * 7),
    ...Array.from({ length: index < 2 ? 520 : sizes.length * 2 }, (_, i) => hex(sizes[i % sizes.length]!))],
}));

try {
  const build = Bun.spawn(['go', 'build', '-p', '1', '-o', binary, '.'], {
    cwd: join(import.meta.dir, '../interop'), env: { ...process.env, GOMAXPROCS: '1', GOTMPDIR: root }, stderr: 'pipe', stdout: 'ignore',
  });
  const diagnostics = new Response(build.stderr).text();
  const buildDeadline = setTimeout(() => build.kill(), 120_000);
  try { assert.equal(await build.exited, 0, await diagnostics); }
  finally { clearTimeout(buildDeadline); }
  const reference = Bun.spawn([binary], { stdin: new Blob([cases.map((value) => JSON.stringify(value)).join('\n')]), stdout: 'pipe', stderr: 'pipe' });
  const result = new Response(reference.stdout).text();
  const errors = new Response(reference.stderr).text();
  const deadline = setTimeout(() => reference.kill(), 30_000);
  let answers: { hash: string; messages: string[] }[];
  try {
    assert.equal(await reference.exited, 0, await errors);
    answers = (await result).trim().split('\n').map((line) => JSON.parse(line));
  } finally { clearTimeout(deadline); }
  assert.equal(answers.length, cases.length);
  let records = 0;
  for (const [index, input] of cases.entries()) {
    const expected = answers[index]!;
    const key = (value: string) => createPrivateKey({ key: Buffer.from('302e020100300506032b656e04220420' + value, 'hex'), format: 'der', type: 'pkcs8' });
    const a = new NoiseHandshake(true, Buffer.from(input.psk, 'hex'), Buffer.from(input.prologue, 'hex'), key(input.initiator));
    const b = new NoiseHandshake(false, Buffer.from(input.psk, 'hex'), Buffer.from(input.prologue, 'hex'), key(input.responder));
    for (let i = 0; i < 2; i++) {
      const [sender, receiver] = i === 0 ? [a, b] : [b, a];
      assert.equal(sender.write(Buffer.from(input.payloads[i]!, 'hex')).toString('hex'), expected.messages[i]);
      assert.equal(receiver.read(Buffer.from(expected.messages[i]!, 'hex')).toString('hex'), input.payloads[i]);
    }
    const left = a.finish(), right = b.finish();
    assert.equal(left.hash.toString('hex'), expected.hash);
    assert.equal(right.hash.toString('hex'), expected.hash);
    const senders = [new NoiseCipher(left.tx), new NoiseCipher(right.tx)];
    const receivers = [new NoiseCipher(right.rx), new NoiseCipher(left.rx)];
    for (let i = 2; i < input.payloads.length; i++) {
      assert.equal(senders[i % 2]!.encrypt(Buffer.from(input.payloads[i]!, 'hex')).toString('hex'), expected.messages[i]);
      assert.equal(receivers[i % 2]!.decrypt(Buffer.from(expected.messages[i]!, 'hex')).toString('hex'), input.payloads[i]);
      records++;
    }
    for (const cipher of [...senders, ...receivers]) cipher.destroy();
    for (const keys of [left, right]) { keys.tx.fill(0); keys.rx.fill(0); }
  }
  console.log(`flynn/noise v1.1.0: ${cases.length} randomized handshakes, ${records} matching bidirectional records, including nonce 256 and maximum lengths.`);
} finally { await rm(root, { recursive: true, force: true }); }
