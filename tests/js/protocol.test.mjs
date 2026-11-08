// Checks bin/lib/protocol.mjs against the machine-readable test vectors
// (docs/test-vectors.json, PROTOCOL.md §15) and round trips. Run with: npm test
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import * as sp from '../../bin/lib/protocol.mjs';

const V = JSON.parse(fs.readFileSync(new URL('../../docs/test-vectors.json', import.meta.url), 'utf8'));

const seedKey = (name) => {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(V.keys[name].seed_hex, 'hex')]);
  return sp.keyFromPkcs8(der.toString('base64'));
};
const sfBytes = (header) => Buffer.from(/^sp=:([^:]*):$/.exec(header)[1], 'base64');
// Checks that the published signature base is exactly what was signed.
const baseVerifies = (base, header, key) => crypto.verify(null, Buffer.from(base), sp.publicKeyFromJwk(sp.publicJwk(key)), sfBytes(header));

const service = seedKey('service');
const site = seedKey('site');
const REQ = V.request;
const RES = V.response;
const reqSig = sfBytes(REQ.headers.Signature);

test('key vectors', () => {
  for (const name of Object.keys(V.keys)) {
    const key = seedKey(name);
    assert.equal(key.x, V.keys[name].x, name);
    assert.equal(key.kid, V.keys[name].kid, name);
  }
  assert.equal(sp.pkceChallenge(V.pkce.code_verifier), V.pkce.code_challenge);
});

test('request vector', () => {
  assert.ok(baseVerifies(REQ.signature_base, REQ.headers.Signature, service));
  const h = sp.signRequest(REQ.method, REQ.url, {}, service, { now: REQ.created, nonce: REQ.nonce });
  assert.equal(h['Signature-Input'], REQ.headers['Signature-Input']);
  assert.equal(h.Signature, REQ.headers.Signature);
  const ok = sp.verifyRequest({ method: REQ.method, url: REQ.url, headers: REQ.headers }, (kid) => (kid === service.kid ? sp.publicJwk(service) : null), REQ.verify_at);
  assert.equal(ok.nonce, REQ.nonce);
});

test('response vector', () => {
  assert.ok(baseVerifies(RES.signature_base, RES.headers.Signature, site));
  assert.equal(sp.contentDigest(RES.body), RES.headers['Content-Digest']);
  const h = sp.signResponse(RES.status, RES.content_type, RES.body, reqSig, site, RES.created);
  assert.equal(h['Signature-Input'], RES.headers['Signature-Input']);
  assert.equal(h.Signature, RES.headers.Signature);
  const headers = { ...RES.headers, 'Content-Type': RES.content_type };
  assert.equal(sp.verifyResponse(RES.status, headers, RES.body, reqSig, () => sp.publicJwk(site)), site.kid);
  assert.throws(() => sp.verifyResponse(200, headers, '{"ok":false}', reqSig, () => sp.publicJwk(site)), { code: 'site_portrait_digest_mismatch' });
  // A response to a signed request must be bound to it.
  const unbound = { ...sp.signResponse(200, RES.content_type, RES.body, null, site), 'Content-Type': RES.content_type };
  assert.throws(() => sp.verifyResponse(200, unbound, RES.body, reqSig, () => sp.publicJwk(site)), { code: 'site_portrait_signature_malformed' });
  assert.equal(sp.verifyResponse(200, unbound, RES.body, null, () => sp.publicJwk(site)), site.kid);
});

test('endorsement vector', () => {
  const signer = seedKey(V.endorsement.signer);
  const next = seedKey(V.endorsement.endorsed);
  assert.equal(V.endorsement.message, sp.ENDORSEMENT_PREFIX + next.kid);
  const e = sp.endorse(next.kid, signer);
  assert.equal(e.sig, V.endorsement.sig);
  assert.ok(sp.isEndorsed({ ...sp.publicJwk(next), endorsements: [e] }, new Map([[signer.kid, sp.publicJwk(signer)]])));
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
