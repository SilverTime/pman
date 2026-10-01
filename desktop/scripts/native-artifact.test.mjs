import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { prepareNativeArtifact } from './native-artifact.mjs';

function fixture(run) {
  const prefix = 'pman-artifact-test-';
  const tempBase = resolve(tmpdir());
  const root = mkdtempSync(join(tempBase, prefix));
  try { run(root); } finally {
    const target = resolve(root);
    if (dirname(target) !== tempBase || !basename(target).startsWith(prefix)) {
      throw new Error('Refusing to clean up outside the test fixture directory.');
    }
    rmSync(target, { recursive: true, force: true });
  }
}

function message(executable, extra = {}) {
  return JSON.stringify({ reason: 'compiler-artifact', target: { name: 'pm', kind: ['bin'] },
    profile: { test: false }, executable, ...extra });
}

test('installer copies Cargo output from default, custom and target-triple directories', () => {
  fixture(root => {
    for (const directory of ['rust/target/release', 'custom output/release', 'custom output/x86_64-pc-windows-msvc/release']) {
      const sourceDir = join(root, directory);
      mkdirSync(sourceDir, { recursive: true });
      const source = join(sourceDir, 'pm.exe');
      writeFileSync(source, directory);
      const destination = join(root, 'bundle');
      prepareNativeArtifact(message(source, { fresh: true }), destination);
      assert.equal(readFileSync(join(destination, 'pm.exe'), 'utf8'), directory);
    }
  });
});

test('unrelated Cargo messages and non-JSON output cannot select an installer binary', () => {
  fixture(root => {
    const source = join(root, 'pm.exe');
    writeFileSync(source, 'synthetic-native-cli');
    const messages = ['build output', 'null', message(null),
      message(source, { target: { name: 'build-script-build', kind: ['custom-build'] } }),
      message(source, { profile: { test: true } }), message(source)].join('\n');
    prepareNativeArtifact(messages, join(root, 'bundle'));
    assert.equal(readFileSync(join(root, 'bundle/pm.exe'), 'utf8'), 'synthetic-native-cli');
  });
});

test('missing, ambiguous or unavailable artifacts never replace an existing installer binary', () => {
  fixture(root => {
    const destination = join(root, 'bundle');
    mkdirSync(destination);
    const bundled = join(destination, 'pm.exe');
    writeFileSync(bundled, 'existing-synthetic-artifact');
    for (const messages of ['', message(join(root, 'missing/pm.exe')),
      [message(join(root, 'one/pm.exe')), message(join(root, 'two/pm.exe'))].join('\n'),
      message('relative/pm.exe'), message(join(root, 'other.exe'))]) {
      assert.throws(() => prepareNativeArtifact(messages, destination));
      assert.equal(readFileSync(bundled, 'utf8'), 'existing-synthetic-artifact');
    }
  });
});
