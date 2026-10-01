import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createPmanClient, PmanError } from '../index.mjs';

const peer = fileURLToPath(new URL('./fake-pm.mjs', import.meta.url));
const options = { executable: process.execPath, executableArgs: [peer], clientId: 'fixture',
  site: 'office-api', expectedOrigin: 'https://office.example.test' };

test('SDK requires a real paired client identity and never guesses a display name', () => {
  const previous=process.env.PMAN_CLIENT_ID;
  delete process.env.PMAN_CLIENT_ID;
  try { assert.throws(() => createPmanClient({ site:'office-api' }), error => error.code === 'pairing_required'); }
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
  assert.deepEqual(response.body_json.received, { site: 'office-api', method: 'POST', path: '/api/read', form: { chinese: '合成词条', code: 'x' } });
});

test('scenario resolution fails closed and capability is forwarded to the native policy boundary', async () => {
  const client = createPmanClient(options);
  await assert.rejects(() => client.resolveScenario('office.api', {}), error => error.code === 'scenario_ambiguous');
  const matched = await client.resolveScenario('office.api', { environment: 'test' });
  assert.equal(matched.site, 'office-api');
  assert.equal(matched.capability, 'office.api.test');
  const response = await client.request({
    method: 'POST', path: '/api/read', capability: matched.capability, form: { code: 'x' },
  });
  assert.equal(response.body_json.received.capability, 'office.api.test');
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

test('SDK requires an explicit connection and has no service fallback', () => {
  const previous = process.env.PMAN_SITE;
  delete process.env.PMAN_SITE;
  try { assert.throws(() => createPmanClient({ executable: process.execPath, clientId: 'fixture' }), error => error.code === 'invalid_request'); }
  finally { if (previous !== undefined) process.env.PMAN_SITE = previous; }
});

test('non-JSON request bodies fail safely before launching the CLI', async () => {
  const cyclic = {};
  cyclic.self = cyclic;
  const throwing = { toJSON() { throw new Error('synthetic-secret-from-serializer'); } };
  // This executable cannot start: invalid data must be rejected before spawn.
  const client = createPmanClient({
    ...options, executable: 'pman-test-missing-executable', expectedOrigin: undefined,
  });
  for (const form of [cyclic, { number: 1n }, throwing]) {
    await assert.rejects(client.request({ method: 'POST', path: '/api/write', form }), error => {
      assert.ok(error instanceof PmanError);
      assert.equal(error.code, 'invalid_request');
      assert.ok(!error.message.includes('synthetic-secret'));
      return true;
    });
  }
});
