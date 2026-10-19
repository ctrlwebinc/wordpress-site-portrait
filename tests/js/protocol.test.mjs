// Checks bin/lib/protocol.mjs against the test vectors in docs/PROTOCOL.md §15
// and round trips. Run with: npm test
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as sp from '../../bin/lib/protocol.mjs';

const seedKey = (byte) => {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, byte)]);
  return sp.keyFromPkcs8(der.toString('base64'));
};
const service = seedKey(1);
const site = seedKey(2);
const REQ_SIG = 'BCOf82rkgP/WyuEMhL+8EJn9P9Z8Z0quKfLY2ghLzkiuICoNAMWZVBhJYbbelfkE/zEbDgzBXlqyFAwD50oNBA==';

test('key vectors', () => {
  assert.equal(service.x, 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w');
  assert.equal(service.kid, 'UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4');
  assert.equal(site.kid, 'aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU');
  assert.equal(sp.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('request vector', () => {
  const h = sp.signRequest('GET', 'https://example.com/wp-json/site-portrait/v1/portrait?scopes=core,plugins', {}, service, {
    now: 1792400000,
    nonce: 'bWFkZS1mb3ItdGVzdGluZw',
  });
  assert.equal(h.Signature, `sp=:${REQ_SIG}:`);
  const ok = sp.verifyRequest(
    { method: 'GET', url: 'https://example.com/wp-json/site-portrait/v1/portrait?scopes=core,plugins', headers: { 'Signature-Input': h['Signature-Input'], Signature: h.Signature } },
    (kid) => (kid === service.kid ? sp.publicJwk(service) : null),
    1792400100,
  );
  assert.equal(ok.nonce, 'bWFkZS1mb3ItdGVzdGluZw');
});

test('response vector', () => {
  const h = sp.signResponse(200, 'application/json; charset=UTF-8', '{"ok":true}', Buffer.from(REQ_SIG, 'base64'), site, 1792400001);
  assert.equal(h.Signature, 'sp=:RB+R308P9gAS41M/lWK4oVEiAGNAuSReP3aOzmo55wNQIbGs9V7R2G10u9kagVAP8WMv2Q3vAa1UBGetZtQZDQ==:');
  const kid = sp.verifyResponse(200, { ...h, 'Content-Type': 'application/json; charset=UTF-8' }, '{"ok":true}', Buffer.from(REQ_SIG, 'base64'), () => sp.publicJwk(site));
  assert.equal(kid, site.kid);
  const headers = { ...h, 'Content-Type': 'application/json; charset=UTF-8' };
  const reqSig = Buffer.from(REQ_SIG, 'base64');
  assert.throws(() => sp.verifyResponse(200, headers, '{"ok":false}', reqSig, () => sp.publicJwk(site)), { code: 'site_portrait_digest_mismatch' });
  // A response to a signed request must be bound to it.
  const unbound = { ...sp.signResponse(200, 'application/json; charset=UTF-8', '{"ok":true}', null, site), 'Content-Type': 'application/json; charset=UTF-8' };
  assert.throws(() => sp.verifyResponse(200, unbound, '{"ok":true}', reqSig, () => sp.publicJwk(site)), { code: 'site_portrait_signature_malformed' });
  assert.equal(sp.verifyResponse(200, unbound, '{"ok":true}', null, () => sp.publicJwk(site)), site.kid);
});

test('endorsement vector', () => {
  const next = seedKey(3);
  const e = sp.endorse(next.kid, service);
  assert.equal(e.sig, '2whhMLNOI50wh8SQIwO-ka3zfQUduDeJYsuolyt7xJfMEsjlwPwEatNVosebORX9LcMcoGiCOvfF6qI8QJQfBA');
  assert.ok(sp.isEndorsed({ ...sp.publicJwk(next), endorsements: [e] }, new Map([[service.kid, sp.publicJwk(service)]])));
  assert.ok(!sp.isEndorsed({ ...sp.publicJwk(next), endorsements: [e] }, new Map([[site.kid, sp.publicJwk(site)]])));
});

test('POST round trip and tampering', () => {
  const key = sp.generateKey();
  const body = JSON.stringify({ a: 1 });
  const base = { 'Content-Type': 'application/json', 'Content-Digest': sp.contentDigest(body) };
  const url = 'https://svc.example/token';
  const h = sp.signRequest('POST', url, base, key);
  const lookup = (kid) => (kid === key.kid ? sp.publicJwk(key) : null);
  const req = { method: 'POST', url, headers: { ...base, ...h }, body };
  assert.equal(sp.verifyRequest(req, lookup).kid, key.kid);
  assert.throws(() => sp.verifyRequest({ ...req, body: '{"a":2}' }, lookup), { code: 'site_portrait_digest_mismatch' });
  assert.throws(() => sp.verifyRequest({ ...req, url: 'https://other.example/token' }, lookup), { code: 'site_portrait_signature_invalid' });
  assert.throws(() => sp.verifyRequest(req, () => null), { code: 'site_portrait_unknown_key' });
  assert.throws(() => sp.verifyRequest(req, lookup, Math.floor(Date.now() / 1000) + 400), { code: 'site_portrait_signature_expired' });
});

test('structured field parsing errors', () => {
  for (const bad of ['sp=("a"', 'sp=1,', 'Sp=1', 'sp=:!!:']) {
    assert.throws(() => sp.parseDictionary(bad), { code: 'site_portrait_signature_malformed' });
  }
  assert.equal(crypto.getHashes().includes('sha256'), true);
});
