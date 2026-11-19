import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

/** Create a throwaway project. Secrets are assembled at runtime so this repo never contains a real-looking key. */
export async function makeProject(files) {
  const root = await mkdtemp(path.join(tmpdir(), 'tameng-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) };
}

export const fake = {
  aws: () => 'AKIA' + 'IOSFODNN7EXAMPLE',
  stripe: () => 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc',
  github: () => 'ghp_' + 'a'.repeat(36),
  privateKey: () => '-----BEGIN ' + 'RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----',
};

export const ids = (findings) => findings.map((f) => f.id);
