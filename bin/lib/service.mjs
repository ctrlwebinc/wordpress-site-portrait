// Minimal reference implementation of the service side of the protocol
// (PROTOCOL.md §3, §4, §10.1, §13). For testing and as a starting point:
// it keeps state in a JSON file and has no user accounts.
import http from 'node:http';
import { randomToken, pkceChallenge, thumbprint, publicKeyFromJwk, verifyRequest, SignatureError } from './protocol.mjs';
import { signedFetch } from './client.mjs';

const SCOPES = ['core', 'plugins', 'themes', 'server', 'database', 'content', 'users_counts'];
const CODE_TTL_MS = 10 * 60 * 1000;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const origin = (u) => new URL(u).origin;

/**
 * Creates the HTTP server.
 * options: { state, publicUrl, autoApprove, name, log }
 */
export function createService({ state, publicUrl, autoApprove = false, name = 'Site Portrait reference service', log = () => {} }) {
  const codes = new Map();
  const confirmations = new Map();

  const discovery = () => ({
    protocol: 'site-portrait',
    protocol_versions: ['1'],
    service: {
      name,
      description: 'Reference implementation used for testing the Site Portrait protocol.',
      homepage: `${publicUrl}/`,
      privacy_policy_url: `${publicUrl}/privacy`,
    },
    authorization_endpoint: `${publicUrl}/authorize`,
    token_endpoint: `${publicUrl}/token`,
    revocation_endpoint: `${publicUrl}/revoke`,
    scopes_supported: SCOPES,
    scopes_requested: SCOPES,
    scope_reasons: { database: 'Database size drives storage and memory sizing.' },
    jwks: state.jwks(),
  });

  const json = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(body));
  };
  const oauthError = (res, status, error, description) => json(res, status, { error, error_description: description });

  const readBody = (req) =>
    new Promise((resolve, reject) => {
      let data = '';
      req.setEncoding('utf8');
      req.on('data', (c) => {
        data += c;
        if (data.length > 1_000_000) reject(new Error('Body too large'));
      });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });

  // §4.2: validates the authorization request; returns an error string or the parsed request.
  function parseAuthorize(params) {
    const get = (k) => params.get(k) ?? '';
    if (get('response_type') !== 'code') return 'response_type must be code';
    if (get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(get('code_challenge'))) return 'invalid PKCE challenge';
    if (!/^[A-Za-z0-9_-]{43}$/.test(get('site_key_thumbprint'))) return 'invalid site_key_thumbprint';
    let clientId;
    let redirect;
    try {
      clientId = origin(get('client_id'));
      redirect = new URL(get('redirect_uri'));
    } catch {
      return 'invalid client_id or redirect_uri';
    }
    if (clientId !== get('client_id') || redirect.host !== new URL(clientId).host) return 'redirect_uri must be on the site host';
    const scopes = get('scope').split(' ').filter(Boolean);
    if (!scopes.length || scopes.some((s) => !SCOPES.includes(s))) return 'invalid scope';
    return {
      client_id: clientId,
      redirect_uri: get('redirect_uri'),
      state: get('state'),
      code_challenge: get('code_challenge'),
      site_key_thumbprint: get('site_key_thumbprint'),
      scopes,
      site_name: get('site_name'),
    };
  }

  function redirectBack(res, authz, params) {
    const target = new URL(authz.redirect_uri);
    for (const [k, v] of Object.entries(params)) target.searchParams.set(k, v);
    target.searchParams.set('state', authz.state);
    res.writeHead(302, { Location: target.toString() });
    res.end();
  }

  function approve(res, authz) {
    const code = randomToken(24);
    codes.set(code, { ...authz, expires: Date.now() + CODE_TTL_MS });
    log(`authorize: approved ${authz.client_id} scopes=${authz.scopes.join(',')}`);
    redirectBack(res, authz, { code });
  }

  function approvalPage(res, authz, raw) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><meta charset="utf-8"><title>${esc(name)}</title>
<h1>Connect ${esc(authz.site_name || authz.client_id)}?</h1>
<p>Site: <code>${esc(authz.client_id)}</code></p>
<p>Requested data: ${authz.scopes.map(esc).join(', ')}</p>
<form method="post" action="/authorize"><input type="hidden" name="raw" value="${esc(raw)}">
<button name="decision" value="approve">Approve</button> <button name="decision" value="deny">Deny</button></form>`);
  }

  // §4.4: code exchange.
  async function token(req, res) {
    const body = await readBody(req);
    let data;
    try {
      data = JSON.parse(body);
    } catch {
      return oauthError(res, 400, 'invalid_request', 'Body is not JSON.');
    }
    const authz = codes.get(data.code);
    codes.delete(data.code);
    if (!authz || authz.expires < Date.now()) return oauthError(res, 400, 'invalid_grant', 'Unknown or expired code.');
    if (data.client_id !== authz.client_id || data.redirect_uri !== authz.redirect_uri) return oauthError(res, 400, 'invalid_grant', 'client_id or redirect_uri mismatch.');
    if (typeof data.code_verifier !== 'string' || pkceChallenge(data.code_verifier) !== authz.code_challenge) return oauthError(res, 400, 'invalid_grant', 'PKCE verification failed.');
    if (!publicKeyFromJwk(data.site_jwk) || thumbprint(data.site_jwk.x) !== authz.site_key_thumbprint) return oauthError(res, 400, 'invalid_grant', 'Site key does not match the authorization request.');
    try {
      verifyRequest({ method: 'POST', url: publicUrl + req.url, headers: req.headers, body }, (kid) => (kid === authz.site_key_thumbprint ? data.site_jwk : null));
    } catch (e) {
      return oauthError(res, 400, 'invalid_grant', `Signature: ${e.message}`);
    }
    const endpoints = data.endpoints ?? {};
    const allowedHosts = new Set([new URL(authz.client_id).host, new URL(authz.redirect_uri).host]);
    for (const required of ['status', 'portrait', 'revoke']) {
      if (typeof endpoints[required] !== 'string') return oauthError(res, 400, 'invalid_request', `Missing endpoint ${required}.`);
    }
    for (const url of Object.values(endpoints)) {
      if (!allowedHosts.has(new URL(url).host)) return oauthError(res, 400, 'invalid_request', 'Endpoint outside the site origin.');
    }

    const scopes = (Array.isArray(data.scopes) ? data.scopes : []).filter((s) => authz.scopes.includes(s));
    const pairing = {
      pairing_id: crypto.randomUUID(),
      client_id: authz.client_id,
      mode: data.mode === 'network' ? 'network' : 'single',
      site_jwks: [{ kty: 'OKP', crv: 'Ed25519', x: data.site_jwk.x, kid: thumbprint(data.site_jwk.x) }],
      endpoints,
      scopes,
      confirmed: false,
      created_at: Date.now(),
    };
    state.savePairing(pairing);
    log(`token: pairing ${pairing.pairing_id} created for ${pairing.client_id}`);
    json(res, 200, { pairing_id: pairing.pairing_id, scopes, jwks: state.jwks(), account_hint: 'Reference client' });
    confirmations.set(pairing.pairing_id, confirm(pairing.pairing_id));
  }

  // §4.5: confirmation through a signed /status call, with retries.
  async function confirm(pairingId) {
    for (let attempt = 0; attempt < 30; attempt++) {
      await new Promise((r) => setTimeout(r, 1000));
      const pairing = state.pairing(pairingId);
      if (!pairing) return false;
      try {
        const r = await signedFetch(state, pairing, 'status');
        if (r.status === 200 && r.kid && r.json?.pairing_id === pairingId) {
          state.savePairing({ ...state.pairing(pairingId), confirmed: true });
          log(`confirm: pairing ${pairingId} confirmed`);
          return true;
        }
      } catch (e) {
        log(`confirm: attempt ${attempt + 1} failed: ${e.message}`);
      }
    }
    log(`confirm: pairing ${pairingId} not confirmed, discarding`);
    state.deletePairing(pairingId);
    return false;
  }

  // §10.1: revocation notice from the site.
  async function revoke(req, res) {
    const body = await readBody(req);
    let data;
    try {
      data = JSON.parse(body);
    } catch {
      return oauthError(res, 400, 'invalid_request', 'Body is not JSON.');
    }
    const pairing = state.pairing(data.pairing_id);
    if (!pairing) return oauthError(res, 400, 'invalid_request', 'Unknown pairing.');
    try {
      verifyRequest({ method: 'POST', url: publicUrl + req.url, headers: req.headers, body }, (kid) => pairing.site_jwks.find((k) => k.kid === kid) ?? null);
    } catch (e) {
      return oauthError(res, 400, 'invalid_signature', e.message);
    }
    state.deletePairing(pairing.pairing_id);
    log(`revoke: pairing ${pairing.pairing_id} revoked by site (${data.reason})`);
    json(res, 200, { revoked: true });
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, publicUrl);
    try {
      if (req.method === 'GET' && url.pathname === '/.well-known/site-portrait') return json(res, 200, discovery());
      if (req.method === 'GET' && url.pathname === '/privacy') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('Test service: data is stored in a local file and never shared.');
      }
      if (req.method === 'GET' && url.pathname === '/authorize') {
        const authz = parseAuthorize(url.searchParams);
        if (typeof authz === 'string') return oauthError(res, 400, 'invalid_request', authz);
        return autoApprove ? approve(res, authz) : approvalPage(res, authz, url.search);
      }
      if (req.method === 'POST' && url.pathname === '/authorize') {
        const form = new URLSearchParams(await readBody(req));
        const authz = parseAuthorize(new URLSearchParams(form.get('raw') ?? ''));
        if (typeof authz === 'string') return oauthError(res, 400, 'invalid_request', authz);
        if (form.get('decision') === 'approve') return approve(res, authz);
        return redirectBack(res, authz, { error: 'access_denied', error_description: 'The user declined.' });
      }
      if (req.method === 'POST' && url.pathname === '/token') return await token(req, res);
      if (req.method === 'POST' && url.pathname === '/revoke') return await revoke(req, res);
      json(res, 404, { error: 'not_found' });
    } catch (e) {
      log(`error: ${e instanceof SignatureError ? e.code : ''} ${e.stack}`);
      if (!res.headersSent) oauthError(res, 500, 'server_error', 'Internal error.');
    }
  });

  return { server, confirmations };
}
