import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { basename, isAbsolute, join } from 'node:path';

/** Use Cargo's artifact path, including configured target directories/triples. */
export function prepareNativeArtifact(messages, destination) {
  const executables = new Set();
  for (const line of messages.split(/\r?\n/)) {
    let artifact;
    try { artifact = JSON.parse(line); } catch { continue; }
    if (artifact?.reason === 'compiler-artifact'
        && artifact.target?.name === 'pm'
        && artifact.target.kind?.includes('bin')
        && artifact.profile?.test !== true
        && typeof artifact.executable === 'string') {
      executables.add(artifact.executable);
    }
  }
  if (executables.size !== 1) throw new Error('Cargo did not report one native pm.exe artifact.');
  const [source] = executables;
  if (!isAbsolute(source) || basename(source).toLowerCase() !== 'pm.exe' || !existsSync(source)) {
    throw new Error('Native pm.exe was not produced at the Cargo artifact path.');
  }
  mkdirSync(destination, { recursive: true });
  copyFileSync(source, join(destination, 'pm.exe'));
}
