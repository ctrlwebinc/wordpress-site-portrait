// SPDX-License-Identifier: Apache-2.0
// Signed calls from the service to a paired site (PROTOCOL.md §5–6), with
// response verification and site key rotation handling (§11.2).
import {
  signRequest, verifyResponse, responseKeyId, isEndorsed, contentDigest, publicKeyFromJwk, SignatureError,
} from './protocol.mjs';

/** Appends a query string to an endpoint that may already contain one (?rest_route=). */
export function withQuery(endpoint, params = {}) {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!entries.length) return endpoint;
  const qs = entries.map(([k, v]) => `${encodeURIComponent(k)}=${String(v).split(',').map(encodeURIComponent).join(',')}`).join('&');
  return endpoint + (endpoint.includes('?') ? '&' : '?') + qs;
}

/**
 * Performs a signed request.
 * Returns { status, json, text, headers, kid, url, sent } where sent holds the
 * signature headers (to test replays).
 */
export async function signedFetch(state, pairing, endpoint, { method = 'GET', query, body, replayHeaders, verify = true } = {}) {
  const key = state.signingKey();
  const url = withQuery(pairing.endpoints[endpoint], query);
  const headers = { Accept: 'application/json' };
  let payload;
  if (body !== undefined) {
    payload = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
    headers['Content-Digest'] = contentDigest(payload);
  }
  const signed = replayHeaders ?? signRequest(method, url, headers, key);
  const res = await fetch(url, {
    method,
    headers: { ...headers, 'Signature-Input': signed['Signature-Input'], Signature: signed.Signature },
    body: payload,
    redirect: 'manual',
  });
  const text = await res.text();
  const resHeaders = Object.fromEntries(res.headers);
  const result = { status: res.status, text, headers: resHeaders, url, sent: signed, kid: null };
  try {
    result.json = JSON.parse(text);
  } catch {
    result.json = null;
  }
  if (verify && resHeaders.signature) {
    result.kid = await verifySiteResponse(state, pairing, result, signed.rawSignature);
  }
  return result;
}

/**
 * Verifies a response with the site keys known for the pairing. When the site
 * rotated its key, learns the new key from the /status body (if this is the
 * status response) or by calling /status, accepting only endorsed keys.
 */
async function verifySiteResponse(state, pairing, result, requestSignature) {
  const lookup = (kid) => pairing.site_jwks.find((k) => k.kid === kid) ?? null;
  const kid = responseKeyId(result.headers);
  if (kid && !lookup(kid)) {
    const jwks = Array.isArray(result.json?.site_jwks?.keys) ? result.json.site_jwks.keys : (await signedFetch(state, pairing, 'status', { verify: false })).json?.site_jwks?.keys ?? [];
    const trusted = new Map(pairing.site_jwks.map((k) => [k.kid, k]));
    const accepted = jwks.filter((k) => publicKeyFromJwk(k) && isEndorsed(k, trusted));
    if (!accepted.length) {
      throw new SignatureError('site_portrait_unknown_key', `Response signed with unknown, unendorsed key ${kid}.`);
    }
    pairing.site_jwks = [...accepted.map(({ kty, crv, x, kid: k }) => ({ kty, crv, x, kid: k })), ...pairing.site_jwks];
    state.savePairing(pairing);
  }
  return verifyResponse(result.status, result.headers, result.text, requestSignature, lookup);
}
