// End-to-end tests on a single WordPress site (Playground) with the reference
// service. Run with: npm run test:e2e (first run downloads WordPress).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { startWordPress, startService, Browser, formFields, notices, waitFor, ROOT } from './helpers.mjs';
import { signedFetch } from '../../bin/lib/client.mjs';
import { signRequest } from '../../bin/lib/protocol.mjs';

const ALL_SCOPES = ['core', 'plugins', 'themes', 'server', 'database', 'content', 'users_counts'];
const SETTINGS = '/wp-admin/options-general.php?page=ctrlweb-site-portrait';

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const schema = (name) => ajv.compile(JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/schema', name), 'utf8')));
const validatePortrait = schema('portrait-v1.schema.json');

let wp;
let svc;
let admin;
let pairing;

async function pair(scopes = ALL_SCOPES) {
  let page = await admin.request(SETTINGS);
  let f = formFields(page.text, 'discover');
  page = await admin.request(f.action, { method: 'POST', form: { ...f.fields, service_url: svc.url } });
  assert.match(page.text, /Connect to Site Portrait reference service\?/);
  assert.match(page.text, /Database size drives storage/, 'scope reason from discovery is shown');

  f = formFields(page.text, 'connect');
  const form = new URLSearchParams(f.fields);
  for (const s of scopes) form.append('scopes[]', s);
  page = await admin.request(f.action, { method: 'POST', form });
  assert.ok(notices(page.text).some((n) => n.startsWith('success')), notices(page.text).join('\n'));

  return waitFor(() => Object.values(svc.state.load().pairings).find((p) => p.confirmed));
}

async function adminPost(action, extra = {}) {
  const page = await admin.request(SETTINGS);
  const f = formFields(page.text, action);
  const form = new URLSearchParams(f.fields);
  for (const [k, v] of Object.entries(extra)) {
    for (const value of [].concat(v)) form.append(k, value);
  }
  return admin.request(f.action, { method: 'POST', form });
}

const call = (endpoint, opts) => signedFetch(svc.state, pairing, endpoint, opts);

before(async () => {
  wp = await startWordPress({ port: 9411 });
  svc = await startService();
  admin = new Browser(wp.url);
  await admin.login();
});

after(async () => {
  await svc?.stop();
  await wp?.stop();
});

test('REST routes do not exist before pairing', async () => {
  const res = await fetch(`${wp.url}/wp-json/site-portrait/v1/status`);
  assert.equal(res.status, 404);
  assert.equal((await res.json()).code, 'rest_no_route');
});

test('administrator pairs the site and the service confirms it', async () => {
  pairing = await pair();
  assert.equal(pairing.mode, 'single');
  assert.deepEqual(pairing.scopes, ALL_SCOPES);
  const page = await admin.request(SETTINGS);
  assert.match(page.text, new RegExp(pairing.pairing_id));
  assert.doesNotMatch(page.text, /waiting for the service to confirm/);
});

test('status is signed and reports the grant', async () => {
  const r = await call('status');
  assert.equal(r.status, 200);
  assert.ok(r.kid, 'response signature verified');
  assert.equal(r.headers['site-portrait-protocol'], '1');
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.equal(r.json.pairing_id, pairing.pairing_id);
  assert.deepEqual(r.json.scopes_granted, ALL_SCOPES);
  assert.ok(Math.abs(r.json.server_time - Date.now() / 1000) < 60);
});

test('portrait matches the JSON schema and contains no sensitive data', async () => {
  const r = await call('portrait');
  assert.equal(r.status, 200);
  assert.ok(r.kid);
  assert.ok(validatePortrait(r.json), JSON.stringify(validatePortrait.errors, null, 2));
  assert.deepEqual(r.json.scopes_returned, ALL_SCOPES);
  assert.deepEqual(Object.keys(r.json.data), ALL_SCOPES);

  const text = r.text;
  assert.doesNotMatch(text, /\/wordpress\//, 'no absolute paths');
  assert.doesNotMatch(text, /@localhost|admin@/, 'no e-mail addresses');
  assert.doesNotMatch(text, /"(user_login|user_email|display_name|post_title|post_content|option_value)"/);
  assert.doesNotMatch(text, /DB_PASSWORD|AUTH_KEY|SECURE_AUTH|NONCE_SALT/);
  const plugin = r.json.data.plugins.items.find((p) => p.slug === 'ctrlweb-site-portrait');
  assert.equal(plugin.active, true);
  assert.equal(r.json.data.users_counts.by_role.administrator, 1);
});

test('unsigned requests are rejected, with a signed error response', async () => {
  const res = await fetch(pairing.endpoints.status);
  assert.equal(res.status, 401);
  assert.equal((await res.json()).code, 'site_portrait_signature_missing');
  assert.match(res.headers.get('signature-input'), /^sp=\("@status" "content-type" "content-digest"\)/);
});

test('replayed requests are rejected', async () => {
  const first = await call('status');
  assert.equal(first.status, 200);
  const replay = await call('status', { replayHeaders: first.sent });
  assert.equal(replay.status, 401);
  assert.equal(replay.json.code, 'site_portrait_replay');
});

test('a request whose query was altered is rejected', async () => {
  const key = svc.state.signingKey();
  const signed = signRequest('GET', `${pairing.endpoints.portrait}?scopes=core`, {}, key);
  const res = await fetch(`${pairing.endpoints.portrait}?scopes=core,database`, {
    headers: { 'Signature-Input': signed['Signature-Input'], Signature: signed.Signature },
  });
  assert.equal(res.status, 401);
  assert.equal((await res.json()).code, 'site_portrait_signature_invalid');
});

test('invalid parameters', async () => {
  let r = await call('portrait', { query: { scopes: 'core,passwords' } });
  assert.equal(r.status, 400);
  assert.equal(r.json.code, 'site_portrait_invalid_scope');
  r = await call('portrait', { query: { site_id: 2 } });
  assert.equal(r.status, 400);
  assert.equal(r.json.code, 'site_portrait_invalid_param');
  const res = await fetch(`${wp.url}/wp-json/site-portrait/v1/sites`);
  assert.equal(res.status, 404, '/sites does not exist in single mode');
});

test('administrator narrows the scopes', async () => {
  await adminPost('save', { 'scopes[]': ['core'] });
  let r = await call('portrait');
  assert.deepEqual(r.json.scopes_returned, ['core']);
  r = await call('portrait', { query: { scopes: 'core,plugins' } });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.scopes_denied, ['plugins']);
  r = await call('portrait', { query: { scopes: 'plugins' } });
  assert.equal(r.status, 403);
  assert.equal(r.json.code, 'site_portrait_scope_denied');
  await adminPost('save', { 'scopes[]': ALL_SCOPES });
  r = await call('status');
  assert.deepEqual(r.json.scopes_granted, ALL_SCOPES);
});

test('IP allow-list', async () => {
  await adminPost('save', { 'scopes[]': ALL_SCOPES, ip_allowlist: '203.0.113.7\n198.51.100.0/24' });
  let r = await call('status');
  assert.equal(r.status, 403);
  assert.equal(r.json.code, 'site_portrait_ip_not_allowed');
  await adminPost('save', { 'scopes[]': ALL_SCOPES, ip_allowlist: '127.0.0.1\n::1' });
  r = await call('status');
  assert.equal(r.status, 200);
  await adminPost('save', { 'scopes[]': ALL_SCOPES, ip_allowlist: '' });
});

test('site key rotation is picked up through the endorsement', async () => {
  const before = pairing.site_jwks[0].kid;
  await adminPost('rotate');
  const r = await call('portrait', { query: { scopes: 'core' } });
  assert.equal(r.status, 200);
  assert.notEqual(r.kid, before);
  assert.equal(pairing.site_jwks[0].kid, r.kid);
});

test('service key rotation is picked up from discovery', async () => {
  const newKid = svc.state.rotateKey();
  const r = await call('status');
  assert.equal(r.status, 200);
  const page = await admin.request(SETTINGS);
  assert.match(page.text, new RegExp(newKid));
});

test('access log lists the requests', async () => {
  const page = await admin.request(SETTINGS);
  assert.match(page.text, /Access log/);
  assert.match(page.text, /GET \/portrait/);
  assert.match(page.text, /site_portrait_replay/);
});

test('failed requests are limited per IP without locking out the service', async () => {
  let res;
  for (let i = 0; i < 40; i++) {
    res = await fetch(pairing.endpoints.status);
    if (res.status === 429) break;
  }
  assert.equal(res.status, 429);
  assert.equal((await res.json()).code, 'site_portrait_rate_limited');
  const r = await call('status');
  assert.equal(r.status, 200, 'a valid signature from the same IP still works');
});

test('service-initiated revocation removes the routes', async () => {
  const r = await call('revoke', { method: 'POST', body: { pairing_id: pairing.pairing_id, reason: 'account_closed' } });
  assert.equal(r.status, 200);
  assert.ok(r.kid, 'revocation response signed with the discarded site key');
  assert.deepEqual(r.json, { revoked: true });
  const after = await call('status', { verify: false });
  assert.equal(after.status, 404);
  svc.state.deletePairing(pairing.pairing_id);
});

test('administrator disconnects and the service is notified', async () => {
  pairing = await pair(['core']);
  const page = await adminPost('disconnect');
  assert.ok(notices(page.text).some((n) => n.startsWith('success') && n.includes('notified')), notices(page.text).join('\n'));
  assert.equal(svc.state.pairing(pairing.pairing_id), null);
  assert.ok(svc.logs.some((l) => l.includes('revoked_by_site')));
  const after = await call('status', { verify: false });
  assert.equal(after.status, 404);
});

test('rate limit answers 429 with Retry-After', async () => {
  pairing = await pair(['core']);
  let r;
  for (let i = 0; i < 80; i++) {
    r = await call('status');
    if (r.status === 429) break;
  }
  assert.equal(r.status, 429);
  assert.equal(r.json.code, 'site_portrait_rate_limited');
  assert.equal(r.json.message, 'Rate limit exceeded.', 'the per-pairing limit, not the failure limit');
  assert.ok(Number(r.headers['retry-after']) > 0);
});
