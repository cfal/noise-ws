export async function loadKey(): Promise<Uint8Array> {
  const path = process.env.NOISE_PSK_FILE;
  if (!path) throw new Error('Set NOISE_PSK_FILE to a protected, 32-byte binary key file');
  const key = new Uint8Array(await Bun.file(path).arrayBuffer());
  if (key.byteLength !== 32) throw new Error('The PSK file must contain exactly 32 random bytes');
  return key;
}
