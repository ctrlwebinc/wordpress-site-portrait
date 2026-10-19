// Site Portrait protocol primitives for Node.js (>= 20), without dependencies.
// Reference implementation of docs/PROTOCOL.md §2 and §5, used by the
// reference client and the tests. Licensed GPL-2.0-or-later.

import crypto from 'node:crypto';

export const LABEL = 'sp';
export const TAG = 'site-portrait/1';
export const MAX_SKEW = 300;
export const GET_LIST = ['@method', '@authority', '@path', '@query'];
export const POST_LIST = [...GET_LIST, 'content-type', 'content-digest'];
export const RESP_LIST = ['@status', 'content-type', 'content-digest'];
export const ENDORSEMENT_PREFIX = 'site-portrait/1 key-endorsement ';

export class SignatureError extends Error {
  constructor(code, message, status = 401) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

// ---------------------------------------------------------------- keys

export const b64url = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64url = (s) => Buffer.from(s, 'base64url');

export function thumbprint(x) {
  return b64url(crypto.createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest());
}

/** Generates a key pair: { kid, x, privateKey (KeyObject), pkcs8 (base64) }. */
export function generateKey() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  return keyFromPkcs8(privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'));
}

export function keyFromPkcs8(pkcs8) {
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(pkcs8, 'base64'), format: 'der', type: 'pkcs8' });
  const { x } = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
  return { kid: thumbprint(x), x, privateKey, pkcs8 };
}

export function publicKeyFromJwk(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return null;
  if (fromB64url(jwk.x).length !== 32) return null;
  if (jwk.kid !== undefined && jwk.kid !== thumbprint(jwk.x)) return null;
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
}

export const publicJwk = (key) => ({ kty: 'OKP', crv: 'Ed25519', x: key.x, kid: key.kid });

export function endorse(newKid, signer) {
  return { kid: signer.kid, sig: b64url(crypto.sign(null, Buffer.from(ENDORSEMENT_PREFIX + newKid), signer.privateKey)) };
}

/** True if jwk carries an endorsement by one of trusted (Map kid => JWK). */
export function isEndorsed(jwk, trusted) {
  if (!publicKeyFromJwk(jwk) || !Array.isArray(jwk.endorsements)) return false;
  const message = Buffer.from(ENDORSEMENT_PREFIX + thumbprint(jwk.x));
  return jwk.endorsements.some((e) => {
    const signer = trusted.get(e?.kid);
    if (!signer || typeof e.sig !== 'string') return false;
    try {
      return crypto.verify(null, message, publicKeyFromJwk(signer), fromB64url(e.sig));
    } catch {
      return false;
    }
  });
}

export const pkceChallenge = (verifier) => b64url(crypto.createHash('sha256').update(verifier).digest());
export const contentDigest = (body) => `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`;
export const randomToken = (bytes = 32) => b64url(crypto.randomBytes(bytes));

// ---------------------------------------------------- structured fields

const KEY_RE = /^[a-z*][a-z0-9_.*-]*/;

/** Parses an RFC 8941 dictionary. Returns a Map or throws SignatureError. */
export function parseDictionary(input) {
  let pos = 0;
  const s = String(input ?? '').trim();
  const fail = () => {
    throw new SignatureError('site_portrait_signature_malformed', 'Invalid structured field.');
  };
  const peek = () => s[pos] ?? '';
  const key = () => {
    const m = KEY_RE.exec(s.slice(pos));
    if (!m) fail();
    pos += m[0].length;
    return m[0];
  };
  const bare = () => {
    const c = peek();
    const rest = s.slice(pos);
    if (c === '"') {
      let out = '';
      pos++;
      while (pos < s.length) {
        const ch = s[pos++];
        if (ch === '\\') {
          const n = s[pos++];
          if (n !== '\\' && n !== '"') fail();
          out += n;
        } else if (ch === '"') {
          return { type: 'string', value: out };
        } else if (ch < ' ' || ch > '~') {
          fail();
        } else {
          out += ch;
        }
      }
      fail();
    }
    if (c === ':') {
      const m = /^:([A-Za-z0-9+/=]*):/.exec(rest);
      if (!m) fail();
      pos += m[0].length;
      return { type: 'bytes', value: Buffer.from(m[1], 'base64') };
    }
    if (c === '?') {
      if (rest[1] !== '0' && rest[1] !== '1') fail();
      pos += 2;
      return { type: 'boolean', value: rest[1] === '1' };
    }
    let m = /^-?\d{1,15}(\.\d{1,3})?/.exec(rest);
    if (m) {
      pos += m[0].length;
      return m[1] ? { type: 'decimal', value: Number(m[0]) } : { type: 'integer', value: Number(m[0]) };
    }
    m = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*/.exec(rest);
    if (m) {
      pos += m[0].length;
      return { type: 'token', value: m[0] };
    }
    fail();
  };
  const params = () => {
    const p = new Map();
    while (peek() === ';') {
      pos++;
      while (peek() === ' ') pos++;
      const k = key();
      if (peek() === '=') {
        pos++;
        p.set(k, bare());
      } else {
        p.set(k, { type: 'boolean', value: true });
      }
    }
    return p;
  };
  const item = () => ({ ...bare(), params: params() });
  const innerList = () => {
    pos++;
    const items = [];
    while (pos < s.length) {
      while (peek() === ' ') pos++;
      if (peek() === ')') {
        pos++;
        return { type: 'inner_list', value: items, params: params() };
      }
      items.push(item());
      if (peek() !== ' ' && peek() !== ')') fail();
    }
    fail();
  };

  const dict = new Map();
  while (pos < s.length) {
    const k = key();
    if (peek() === '=') {
      pos++;
      dict.set(k, peek() === '(' ? innerList() : item());
    } else {
      dict.set(k, { type: 'boolean', value: true, params: params() });
    }
    while (peek() === ' ' || peek() === '\t') pos++;
    if (pos >= s.length) break;
    if (peek() !== ',') fail();
    pos++;
    while (peek() === ' ' || peek() === '\t') pos++;
    if (pos >= s.length) fail();
  }
  return dict;
}

function serializeBare({ type, value }) {
  switch (type) {
    case 'integer':
      return String(value);
    case 'string':
      return `"${value.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
    case 'bytes':
      return `:${Buffer.from(value).toString('base64')}:`;
    case 'boolean':
      return value ? '?1' : '?0';
    case 'token':
      return value;
    default:
      throw new Error(`Unsupported type ${type}`);
  }
}

function serializeParams(params) {
  let out = '';
  for (const [k, v] of params) {
    out += `;${k}`;
    if (!(v.type === 'boolean' && v.value === true)) out += `=${serializeBare(v)}`;
  }
  return out;
}

const serializeInnerList = (items, params) =>
  `(${items.map((i) => serializeBare(i) + serializeParams(i.params ?? new Map())).join(' ')})${serializeParams(params)}`;

const str = (value, params = new Map()) => ({ type: 'string', value, params });

// ---------------------------------------------------------- signatures

export function authority(url) {
  const u = new URL(url);
  return u.host.toLowerCase(); // URL omits default ports.
}

function requestContext(method, url, headers) {
  const u = new URL(url);
  return {
    '@method': method.toUpperCase(),
    '@authority': authority(url),
    '@path': u.pathname || '/',
    '@query': u.search === '' ? '?' : u.search,
    headers: lowerKeys(headers),
  };
}

export const lowerKeys = (headers) =>
  Object.fromEntries(Object.entries(headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)]));

function signatureBase(items, params, context, requestSignature) {
  const lines = [];
  for (const it of items) {
    const id = serializeBare(it) + serializeParams(it.params ?? new Map());
    const name = it.value.toLowerCase();
    let value;
    if (it.params?.has('req')) {
      if (name !== 'signature' || !requestSignature) return null;
      value = serializeBare({ type: 'bytes', value: requestSignature });
    } else if (name.startsWith('@')) {
      value = context[name];
    } else {
      value = context.headers[name]?.trim();
    }
    if (value === undefined) return null;
    lines.push(`${id}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeInnerList(items, params)}`);
  return lines.join('\n');
}

/**
 * Signs a request. headers must include content-type and content-digest when
 * a body is sent. Returns { 'Signature-Input', Signature, rawSignature (Buffer) }.
 */
export function signRequest(method, url, headers, key, { now = Math.floor(Date.now() / 1000), nonce = randomToken(24) } = {}) {
  const list = ['GET', 'HEAD'].includes(method.toUpperCase()) ? GET_LIST : POST_LIST;
  const items = list.map((n) => str(n));
  const params = new Map([
    ['created', { type: 'integer', value: now }],
    ['expires', { type: 'integer', value: now + 300 }],
    ['nonce', { type: 'string', value: nonce }],
    ['keyid', { type: 'string', value: key.kid }],
    ['alg', { type: 'string', value: 'ed25519' }],
    ['tag', { type: 'string', value: TAG }],
  ]);
  const base = signatureBase(items, params, requestContext(method, url, headers), null);
  if (base === null) throw new Error('Missing covered component');
  const signature = crypto.sign(null, Buffer.from(base), key.privateKey);
  return {
    'Signature-Input': `${LABEL}=${serializeInnerList(items, params)}`,
    Signature: `${LABEL}=${serializeBare({ type: 'bytes', value: signature })}`,
    rawSignature: signature,
  };
}

/**
 * Verifies a signed request (service side: token and revocation requests).
 * request: { method, url, headers, body }. lookup(kid) returns a JWK or null.
 */
export function verifyRequest(request, lookup, now = Math.floor(Date.now() / 1000)) {
  const headers = lowerKeys(request.headers);
  const method = request.method.toUpperCase();
  if (!headers['signature-input'] || !headers.signature) {
    throw new SignatureError('site_portrait_signature_missing', 'The request is not signed.');
  }
  const input = parseDictionary(headers['signature-input']).get(LABEL);
  const sig = parseDictionary(headers.signature).get(LABEL);
  if (!input || !sig) throw new SignatureError('site_portrait_signature_missing', 'No sp signature.');
  if (input.type !== 'inner_list' || sig.type !== 'bytes') {
    throw new SignatureError('site_portrait_signature_malformed', 'Unexpected field types.');
  }
  const expected = ['GET', 'HEAD'].includes(method) ? GET_LIST : POST_LIST;
  const covered = input.value.map((i) => i.value);
  if (JSON.stringify(covered) !== JSON.stringify(expected) || input.value.some((i) => i.params.size)) {
    throw new SignatureError('site_portrait_signature_malformed', 'Unexpected covered components.');
  }
  const p = Object.fromEntries([...input.params].map(([k, v]) => [k, v.value]));
  if (p.alg !== 'ed25519' || p.tag !== TAG || !/^[A-Za-z0-9_-]{16,64}$/.test(p.nonce ?? '')) {
    throw new SignatureError('site_portrait_signature_malformed', 'Invalid parameters.');
  }
  if (!Number.isInteger(p.created) || !Number.isInteger(p.expires) || Math.abs(now - p.created) > MAX_SKEW ||
      p.expires <= p.created || p.expires > p.created + 300 || now >= p.expires) {
    throw new SignatureError('site_portrait_signature_expired', 'Signature outside its validity window.');
  }
  if (expected === POST_LIST && headers['content-digest'] !== contentDigest(request.body ?? '')) {
    throw new SignatureError('site_portrait_digest_mismatch', 'Content-Digest mismatch.', 400);
  }
  const jwk = lookup(p.keyid);
  const pub = jwk && publicKeyFromJwk(jwk);
  if (!pub) throw new SignatureError('site_portrait_unknown_key', 'Unknown key id.');
  const base = signatureBase(input.value, input.params, requestContext(method, request.url, headers), null);
  if (base === null || !crypto.verify(null, Buffer.from(base), pub, sig.value)) {
    throw new SignatureError('site_portrait_signature_invalid', 'Signature verification failed.');
  }
  return { kid: p.keyid, nonce: p.nonce, expires: p.expires, signature: sig.value };
}

/** Returns the keyid of a signed response without verifying it. */
export function responseKeyId(headers) {
  try {
    return parseDictionary(lowerKeys(headers)['signature-input']).get(LABEL)?.params.get('keyid')?.value ?? null;
  } catch {
    return null;
  }
}

/** Signs a response (used by test doubles). */
export function signResponse(status, contentType, body, requestSignature, key, now = Math.floor(Date.now() / 1000)) {
  const items = RESP_LIST.map((n) => str(n));
  if (requestSignature) {
    items.push(str('signature', new Map([['req', { type: 'boolean', value: true }], ['key', { type: 'string', value: LABEL }]])));
  }
  const params = new Map([
    ['created', { type: 'integer', value: now }],
    ['keyid', { type: 'string', value: key.kid }],
    ['alg', { type: 'string', value: 'ed25519' }],
    ['tag', { type: 'string', value: TAG }],
  ]);
  const digest = contentDigest(body);
  const context = { '@status': String(status), headers: { 'content-type': contentType, 'content-digest': digest } };
  const base = signatureBase(items, params, context, requestSignature);
  return {
    'Content-Digest': digest,
    'Signature-Input': `${LABEL}=${serializeInnerList(items, params)}`,
    Signature: `${LABEL}=${serializeBare({ type: 'bytes', value: crypto.sign(null, Buffer.from(base), key.privateKey) })}`,
  };
}

/** Verifies a response signature and digest. lookup(kid) returns a JWK or null. */
export function verifyResponse(status, headers, body, requestSignature, lookup) {
  const h = lowerKeys(headers);
  const input = parseDictionary(h['signature-input'] ?? '').get(LABEL);
  const sig = parseDictionary(h.signature ?? '').get(LABEL);
  if (!input || !sig || input.type !== 'inner_list' || sig.type !== 'bytes') {
    throw new SignatureError('site_portrait_signature_missing', 'The response is not signed.');
  }
  // Exactly the §5.2 list, plus the request binding when the request was signed.
  const covered = input.value.map((i) => i.value + [...i.params].map(([k, v]) => `;${k}=${v.value}`).join(''));
  // Error responses to unauthenticated requests are not bound (§5.2).
  const bound = JSON.stringify([...RESP_LIST, 'signature;req=true;key=sp']);
  const unbound = JSON.stringify(RESP_LIST);
  const allowed = !requestSignature ? [unbound] : status >= 200 && status < 300 ? [bound] : [bound, unbound];
  if (!allowed.includes(JSON.stringify(covered))) {
    throw new SignatureError('site_portrait_signature_malformed', `Unexpected covered components: ${covered.join(' ')}.`);
  }
  if (h['content-digest'] !== contentDigest(body)) {
    throw new SignatureError('site_portrait_digest_mismatch', 'Content-Digest mismatch.', 400);
  }
  const kid = input.params.get('keyid')?.value;
  const jwk = lookup(kid);
  const pub = jwk && publicKeyFromJwk(jwk);
  if (!pub) throw new SignatureError('site_portrait_unknown_key', `Unknown response key ${kid}.`);
  const base = signatureBase(input.value, input.params, { '@status': String(status), headers: h }, covered.length > 3 ? requestSignature : null);
  if (base === null || !crypto.verify(null, Buffer.from(base), pub, sig.value)) {
    throw new SignatureError('site_portrait_signature_invalid', 'Response signature verification failed.');
  }
  return kid;
}
