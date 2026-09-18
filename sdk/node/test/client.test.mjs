import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readFile, access, mkdtemp, writeFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createPmanClient, PmanError } from '../index.mjs';

const peer = fileURLToPath(new URL('./fake-pm.mjs', import.meta.url));
const options = { executable: process.execPath, executableArgs: [peer], clientId: 'fixture',
  site: 'e10-i18n', expectedOrigin: 'https://www.e-cology.com.cn' };

test('SDK requires a real paired client identity and never guesses a display name', () => {
  const previous=process.env.PMAN_CLIENT_ID;
  delete process.env.PMAN_CLIENT_ID;
  try { assert.throws(() => createPmanClient({ site:'e10-i18n' }), error => error.code === 'pairing_required'); }
  finally { if (previous !== undefined) process.env.PMAN_CLIENT_ID=previous; }
});

test('metadata is allowlisted, and request body uses the stdin pman/2 bridge', async () => {
  const client = createPmanClient(options);
  const context = await client.getActiveContext();
  assert.equal(context.origin, options.expectedOrigin);
  assert.equal(context.user_id, 'user-fixture');
  assert.equal(context.cookie, undefined);
  assert.ok(!JSON.stringify(context).includes('synthetic-secret'));
  const response = await client.request({ method: 'POST', path: '/api/read', form: { chinese: '合成词条', code: 'x' } });
  assert.deepEqual(response.body_json.received, { site: 'e10-i18n', method: 'POST', path: '/api/read', form: { chinese: '合成词条', code: 'x' } });
});

test('scenario resolution fails closed and capability is forwarded to the native policy boundary', async () => {
  const client = createPmanClient(options);
  await assert.rejects(() => client.resolveScenario('e10.i18n', {}), error => error.code === 'scenario_ambiguous');
  const matched = await client.resolveScenario('e10.i18n', { environment: 'test' });
  assert.equal(matched.site, 'e10-i18n');
  assert.equal(matched.capability, 'e10.i18n.test');
  const response = await client.request({
    method: 'POST', path: '/api/read', capability: matched.capability, form: { code: 'x' },
  });
  assert.equal(response.body_json.received.capability, 'e10.i18n.test');
});

test('wrong origin fails before an HTTP operation', async () => {
  await assert.rejects(createPmanClient({ ...options, clientId: 'wrong-origin' }).request({ path: '/api/read' }),
    error => error.code === 'origin_mismatch');
});

test('approval is a typed failure with request id, without unsafe broker text', async () => {
  await assert.rejects(createPmanClient(options).request({ path: '/pending' }), error => {
    assert.ok(error instanceof PmanError);
    assert.equal(error.code, 'pending_approval');
    assert.equal(error.reqId, 'approval-fixture');
    assert.ok(!error.message.includes('synthetic-secret'));
    return true;
  });
});

test('invalid CLI stdout is never included in errors', async () => {
  await assert.rejects(createPmanClient({ ...options, clientId: 'broken-json' }).getActiveContext(), error => {
    assert.equal(error.code, 'invalid_response');
    assert.ok(!error.message.includes('synthetic-untrusted-output'));
    return true;
  });
});

test('caller cannot supply remote URLs, headers, another site, or mixed bodies', async () => {
  const client = createPmanClient(options);
  for (const input of [{ path: '//evil.example/api' }, { path: '/api', headers: {} },
    { path: '/api', site: 'other' }, { path: '/api', json_body: {}, form: {} }, { path: '/api#fragment' }]) {
    await assert.rejects(client.request(input), error => error.code === 'invalid_request');
  }
});

const skillScript = process.env.PMAN_I18N_SCRIPT || 'C:/Users/bvzgo/.agents/skills/e10-i18n/scripts/e10-i18n.mjs';
let installedSkill = true;
try { await access(skillScript); } catch { installedSkill = false; }

test('installed i18n auth-check traverses Node SDK and synthetic native bridge only', { skip: !installedSkill }, () => {
  const fixture = fileURLToPath(new URL('./i18n-client-fixture.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [skillScript, '--auth-check', '--no-log'], {
    env: { ...process.env, PMAN_SDK_PATH: fixture }, encoding: 'utf8', windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /pman and I18n API authentication check passed/);
  assert.ok(!result.stdout.includes('synthetic-secret'));
  assert.ok(!result.stderr.includes('synthetic-secret'));
});

test('installed i18n request adapter preserves form parameters and failure contracts', { skip: !installedSkill }, async () => {
  const { callAPI } = await import(pathToFileURL(skillScript));
  const result = await callAPI('/api/read', { taskId: '0000000', chinese: '合成词条' }, { client: createPmanClient(options) });
  assert.equal(result.code, 200);
  assert.deepEqual(result.received.query, { sf_request_type: 'ajax' });
  assert.deepEqual(result.received.form, { taskId: '0000000', chinese: '合成词条' });
  const pending = await callAPI('/pending', {}, { client: createPmanClient(options) });
  assert.equal(pending._fail, true);
  assert.equal(pending.detail.req_id, 'approval-fixture');
});

test('confirmed i18n entries traverse translation, SQL export, mock commit and local replacement', { skip: !installedSkill }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'pman-i18n-fixture-'));
  try {
    await writeFile(join(temporary, 'package.json'), JSON.stringify({ name: '@weapp/ebdfpage' }));
    await writeFile(join(temporary, 'sample.ts'), "export const label = '合成词条';\n");
    const fixture = fileURLToPath(new URL('./i18n-client-fixture.mjs', import.meta.url));
    const result = spawnSync(process.execPath, [skillScript, '--entries', JSON.stringify([
      { file: 'sample.ts', line: 1, chinese: '合成词条', textType: '2001' },
    ]), '--task-id', '0000000', '--task-note', 'no.0000000 synthetic fixture', '--no-log'], {
      cwd: temporary, env: { ...process.env, PMAN_SDK_PATH: fixture }, encoding: 'utf8', windowsHide: true,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /SQL scripts generated successfully/);
    assert.match(result.stdout, /Batch 1 committed successfully/);
    assert.match(await readFile(join(temporary, 'sample.ts'), 'utf8'), /getLabel\('12345678',\s*'合成词条'\)/);
    assert.ok(!result.stdout.includes('synthetic-secret'));
  } finally {
    const actual = await realpath(temporary);
    const parent = await realpath(tmpdir());
    assert.ok(actual.toLowerCase().startsWith(join(parent, 'pman-i18n-fixture-').toLowerCase()));
    await rm(actual, { recursive: true, force: true });
  }
});

test('installed SDK copy matches source and migrated script has no legacy auth reads', { skip: !installedSkill }, async () => {
  const source = await readFile(new URL('../index.mjs', import.meta.url), 'utf8');
  const installed = await readFile(new URL('./pman-client.mjs', pathToFileURL(skillScript)), 'utf8');
  assert.equal(installed, source);
  const script = await readFile(skillScript, 'utf8');
  assert.doesNotMatch(script, /AuthSession|E10_LOGIN_HOME|cookieHeader|node:https|node:http/);
});
