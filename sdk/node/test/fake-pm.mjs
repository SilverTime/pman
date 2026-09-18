// Synthetic protocol peer. No vault, credentials, or network are accessed.
let input = '';
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
const clientId = process.argv[process.argv.indexOf('--client') + 1];
const envelope = { protocol: 'pman', protocol_version: 2, ok: true, error_code: 'ok' };
let response;
if (clientId === 'broken-json') {
  process.stdout.write('synthetic-untrusted-output');
  process.exit(1);
}
if (request.operation === 'active_context') {
  response = { ...envelope, context: {
    origin: clientId === 'wrong-origin' ? 'https://wrong.example' : 'https://www.e-cology.com.cn',
    auth_type: 'e10', status: 'connected', account_id: 'account-fixture',
    cookie: 'synthetic-secret-not-metadata', user_id: 'user-fixture',
  } };
} else if (request.operation === 'resolve_scenario') {
  response = request.context?.environment === 'test'
    ? { ...envelope, status: 'resolved', match: { site: 'e10-i18n', capability: 'e10.i18n.test', environment: 'test', account: 'fixture' } }
    : { ...envelope, ok: false, error_code: 'scenario_ambiguous', status: 'ambiguous', matches: [{ environment: 'test' }, { environment: 'baseline' }] };
} else if (request.operation === 'http') {
  if (request.request.path === '/pending') {
    response = { ...envelope, ok: false, error_code: 'pending_approval', req_id: 'approval-fixture', error: 'synthetic-secret-in-unsafe-error' };
  } else if (request.expected_origin !== 'https://www.e-cology.com.cn') {
    response = { ...envelope, ok: false, error_code: 'origin_mismatch' };
  } else {
    const endpoint = request.request.path.split('/').pop();
    const dataByEndpoint = {
      getModuleCodes: { list: [{ id: 'ebuilder', content: 'Synthetic module' }] },
      getFrontSecModule: { list: [{ id: 'ebdfpage', content: 'Synthetic page' }] },
      batchTrans: { ids: '12345678', list: "getLabel('12345678', '合成词条')" },
      exportLabelSql2: { data: { mysql: '-- synthetic SQL only' } },
      getE10LabelListDataKey: { displayData: [] },
      commitSQLFileToGit: { success: true },
    };
    response = { ...envelope, status_code: 200, body_json: {
      code: 200, status: true, data: dataByEndpoint[endpoint] || [{ code: 'test-module' }], received: request.request,
    }, headers: {}, redactions: 0, truncated: false };
  }
} else {
  response = { ...envelope, ok: false, error_code: 'invalid_request' };
}
process.stdout.write(JSON.stringify(response));
if (!response.ok) process.exitCode = 1;
