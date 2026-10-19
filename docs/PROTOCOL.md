# Site Portrait Protocol — version 1

Status: **draft** (protocol version `1`, portrait schema `1.0.0`)

This document specifies how a WordPress site running the *Site Portrait* plugin
and an external service chosen by the site administrator ("the service") pair
with each other, and how the service then retrieves a read-only, privacy-minimised
technical portrait of the site (software versions, server capacity, database
size, content volumes…), typically to recommend suitable hosting.

The plugin is **not tied to any particular service**. Anyone may implement a
compatible service by following this document. The key words MUST, MUST NOT,
SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

---

## Table of contents

1. [Overview](#1-overview)
2. [Conventions and primitives](#2-conventions-and-primitives)
3. [Discovery](#3-discovery)
4. [Pairing (authorization code + PKCE)](#4-pairing)
5. [HTTP message signatures](#5-http-message-signatures)
6. [Site REST endpoints](#6-site-rest-endpoints)
7. [Scopes](#7-scopes)
8. [The portrait document](#8-the-portrait-document)
9. [Errors](#9-errors)
10. [Revocation](#10-revocation)
11. [Key rotation](#11-key-rotation)
12. [Site-side policies (rate limit, IP allow-list, logging)](#12-site-side-policies)
13. [What a service must implement (checklist)](#13-service-implementation-checklist)
14. [Security considerations](#14-security-considerations)
15. [Test vectors](#15-test-vectors)
16. [Comparison with Application Passwords](#16-comparison-with-application-passwords)

---

## 1. Overview

```
 Admin's browser            WordPress site (plugin)                Service
 ───────────────            ───────────────────────                ───────
 1. enters service URL ───▶ GET {service}/.well-known/site-portrait ──▶
                       ◀─── shows name, privacy policy, scopes
 2. ticks scopes, confirms
                            generates site key pair, state, PKCE
 3. ◀── 302 to authorize_endpoint ───────────────────────────────────────▶
        (admin logs in at the service and approves)
 4. ◀── 302 back to wp-admin callback with code + state ─────────────────
                            POST token_endpoint (code, code_verifier,
                            site public key), signed with site key ───▶
                       ◀─── pairing_id + service public keys (pinned)
 5.                                                  ◀── GET /status (signed)
                                                         confirms pairing
 6.                         ◀── GET /portrait?scopes=… (signed by service)
                            ──▶ JSON portrait (signed by site)
```

Properties:

* **Opt-in.** The plugin makes no outbound request until an administrator types
  a service URL and asks to connect. It is disabled by default.
* **No shared secret.** Both parties hold their own Ed25519 private key and only
  know the other's public key. A leak of the site database does not let anyone
  impersonate the service, and a leak of the service database does not grant
  administrator access to the site (at worst, read access to the scopes the
  administrator granted).
* **Read-only.** The data endpoints never modify the site. The only state they
  touch is the plugin's own bookkeeping (replay nonces, access log, and the
  pairing itself on revocation).
* **Scoped and minimised.** The administrator chooses which data categories may
  be read and can change that choice at any time. No secrets, e-mail addresses,
  user names, content bodies or absolute file-system paths are ever returned.

## 2. Conventions and primitives

| Item | Value |
|---|---|
| Transport | HTTPS (TLS) for every request, both directions. See §14.6 for the development exception. |
| Signature algorithm | Ed25519 (RFC 8032), `alg="ed25519"` in RFC 9421 terms. |
| Key format | JWK (RFC 7517 / RFC 8037): `{"kty":"OKP","crv":"Ed25519","x":"<base64url>"}`. |
| Key identifier (`kid`) | JWK SHA-256 thumbprint (RFC 7638), base64url without padding. For an Ed25519 JWK the hashed input is exactly `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`. Using thumbprints makes key ids collision-free across services. |
| base64url | RFC 4648 §5, **without** padding. |
| base64 (in structured fields) | RFC 4648 §4, **with** padding (as required by RFC 8941 byte sequences). |
| Timestamps | Integers are Unix seconds (UTC); strings are RFC 3339 in UTC (`2026-10-19T14:00:00Z`). |
| Sizes | Integers, in bytes. |
| JSON | UTF-8, `Content-Type: application/json`. Unknown members MUST be ignored by receivers. |
| Protocol version | The string `"1"`. Carried in discovery, in the REST namespace (`site-portrait/v1`), in the `tag` signature parameter (`site-portrait/1`) and in the `Site-Portrait-Protocol` response header. |

### 2.1 Deployment modes

A WordPress installation pairs with **at most one service** at a time, in one
of two modes:

| Mode | When | Who pairs | Settings live in | Portrait covers |
|---|---|---|---|---|
| `single` | Regular (non-multisite) installation. | A user with `manage_options`. | Site options. | The site. |
| `network` | Multisite installation, plugin **network-activated**. | A super admin (`manage_network_options`), from the Network Admin. | Network options (`sitemeta`). | The whole network; per-site details on demand (§6.3, §6.5). |

On a multisite installation where the plugin is activated on individual sites
only, the plugin offers no pairing and registers no routes: a subsite
administrator must not be able to disclose server- and database-level data that
belongs to the whole network. The settings page explains how to network-activate
the plugin instead.

In `network` mode the REST routes are served by the **main site** of the
network only; `@authority` (§5.1) is compared with the main site's host.

## 3. Discovery

The administrator enters the **service base URL** (for example
`https://commandes.ctrlweb.ca`). The plugin normalises it to its origin
(scheme + host + optional port) and fetches:

```
GET https://{service-host}/.well-known/site-portrait
Accept: application/json
```

Rules for the site:

* The URL MUST use `https` (see §14.6).
* Redirects MUST NOT be followed. Non-200 responses abort the flow.
* The response MUST be at most 64 KiB and valid JSON matching
  [`schema/discovery-v1.schema.json`](schema/discovery-v1.schema.json).
* All endpoint URLs in the document MUST be `https` and MUST share the origin
  of the discovery URL.
* The request uses `wp_safe_remote_get()` (rejects private/reserved IP ranges)
  except in development mode.

### 3.1 Discovery document

```json
{
  "protocol": "site-portrait",
  "protocol_versions": ["1"],
  "service": {
    "name": "Ctrlweb — hosting assessment",
    "description": "Recommends a hosting plan suited to your site.",
    "homepage": "https://commandes.ctrlweb.ca/",
    "privacy_policy_url": "https://commandes.ctrlweb.ca/privacy",
    "terms_url": "https://commandes.ctrlweb.ca/terms",
    "contact": "support@example.com"
  },
  "authorization_endpoint": "https://commandes.ctrlweb.ca/site-portrait/authorize",
  "token_endpoint": "https://commandes.ctrlweb.ca/site-portrait/token",
  "revocation_endpoint": "https://commandes.ctrlweb.ca/site-portrait/revoke",
  "scopes_supported": ["core", "plugins", "themes", "server", "database", "content", "users_counts"],
  "scopes_requested": ["core", "plugins", "themes", "server", "database", "content", "users_counts"],
  "scope_reasons": {
    "database": "Database size drives storage and memory sizing."
  },
  "jwks": {
    "keys": [
      {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
        "kid": "UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4",
        "use": "sig",
        "alg": "Ed25519"
      }
    ]
  }
}
```

| Member | Req. | Description |
|---|---|---|
| `protocol` | yes | Constant `"site-portrait"`. |
| `protocol_versions` | yes | Versions the service speaks. Must contain `"1"`. |
| `service.name` | yes | Display name shown to the administrator (plain text, ≤ 100 chars). |
| `service.privacy_policy_url` | yes | Shown before consent. Pairing is refused without it. |
| `service.description`, `homepage`, `terms_url`, `contact` | no | Shown when present. |
| `authorization_endpoint` | yes | Browser endpoint (§4.2). |
| `token_endpoint` | yes | Server-to-server code exchange (§4.4). |
| `revocation_endpoint` | yes | Receives revocation notices from sites (§10.1). |
| `scopes_supported` | yes | Scopes the service understands. |
| `scopes_requested` | no | Scopes pre-ticked in the consent screen (default: all supported). |
| `scope_reasons` | no | Map scope → short plain-text justification shown next to the checkbox. |
| `jwks.keys` | yes | The service's current Ed25519 signing keys. `kid` MUST equal the RFC 7638 thumbprint. May carry `endorsements` (§11). |

The plugin escapes every displayed string; services MUST NOT expect HTML to be
rendered.

## 4. Pairing

Pairing is OAuth 2.0 "authorization code" (RFC 6749 §4.1) with PKCE S256
(RFC 7636), where the WordPress site is the client and is not pre-registered.
Its output is not a bearer token but a **mutual exchange of public keys**.

### 4.1 Consent screen (site)

After discovery the plugin displays: service name, origin, description, privacy
policy and terms links, and one checkbox per scope (pre-ticked from
`scopes_requested`, with `scope_reasons`). Nothing is sent to the service until
the administrator (capability `manage_options`) submits this form, which is
protected by a WordPress nonce.

On submission the site:

1. Generates a new Ed25519 key pair for this pairing (the **site key**).
2. Generates `state` (32 random bytes, base64url) and a PKCE `code_verifier`
   (32 random bytes, base64url → 43 chars); computes
   `code_challenge = base64url(SHA-256(code_verifier))`.
3. Stores a *pending pairing* (discovery snapshot, granted scopes, site key,
   state, verifier) bound to the current user, valid for 15 minutes.
4. Redirects the browser to the authorization endpoint.

### 4.2 Authorization request (browser → service)

```
GET {authorization_endpoint}
    ?response_type=code
    &client_id=https%3A%2F%2Fexample.com
    &redirect_uri=https%3A%2F%2Fexample.com%2Fwp-admin%2Fadmin-post.php%3Faction%3Dsite_portrait_callback%26_wpnonce%3Dabc123
    &state=Q3kz…
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
    &scope=core%20plugins%20themes%20server
    &site_key_thumbprint=aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU
    &site_name=My%20Bakery
    &protocol_version=1
```

| Parameter | Description |
|---|---|
| `client_id` | The site's `home_url()` origin (scheme + host + port). |
| `redirect_uri` | wp-admin callback. **Must be returned to exactly as given** (it embeds a WordPress nonce). Its origin is the site's admin origin. |
| `state` | Opaque; must be echoed back unchanged. |
| `code_challenge`, `code_challenge_method` | PKCE, method is always `S256`. |
| `scope` | Space-separated list of scopes granted by the administrator. |
| `site_key_thumbprint` | `kid` of the site key that will be presented at the token endpoint. |
| `site_name` | Informational (blog name), plain text. |
| `protocol_version` | `1`. |

The service authenticates the user by its own means, displays at least the
site URL (`client_id`) and the scopes, and asks for approval. The service MUST
NOT accept scopes the site did not list.

### 4.3 Authorization response (service → browser → site)

Success:

```
302 Location: {redirect_uri}&code=SplxlOBeZQQYbYS6WxSbIA&state=Q3kz…
```

Failure (`error` per RFC 6749 §4.1.2.1, e.g. `access_denied`):

```
302 Location: {redirect_uri}&error=access_denied&error_description=User%20declined&state=Q3kz…
```

Requirements on the service:

* `code` MUST be single-use, unguessable (≥ 128 bits) and expire within
  10 minutes.
* `code` MUST be bound to `client_id`, `redirect_uri`, `code_challenge`,
  `site_key_thumbprint` and the approved scopes.

Requirements on the site (callback `admin-post.php?action=site_portrait_callback`):

* Verify the WordPress nonce, that the current user has `manage_options`, that
  a pending pairing exists **for this user**, and that `state` matches it
  (constant-time comparison). Any failure discards the pending pairing.

### 4.4 Code exchange (site → service, server-to-server)

```
POST {token_endpoint}
Content-Type: application/json
Content-Digest: sha-256=:…:
Signature-Input: sp=("@method" "@authority" "@path" "@query" "content-type" "content-digest");created=…;expires=…;nonce="…";keyid="<site kid>";alg="ed25519";tag="site-portrait/1"
Signature: sp=:…:

{
  "grant_type": "authorization_code",
  "code": "SplxlOBeZQQYbYS6WxSbIA",
  "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "client_id": "https://example.com",
  "redirect_uri": "https://example.com/wp-admin/admin-post.php?action=site_portrait_callback&_wpnonce=abc123",
  "site_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q", "kid": "aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU" },
  "endpoints": {
    "status":   "https://example.com/wp-json/site-portrait/v1/status",
    "portrait": "https://example.com/wp-json/site-portrait/v1/portrait",
    "revoke":   "https://example.com/wp-json/site-portrait/v1/revoke"
  },
  "mode": "single",
  "scopes": ["core", "plugins", "themes", "server"],
  "plugin_version": "1.0.0",
  "protocol_version": "1"
}
```

The request is signed (§5) with the **site key**. This is a proof of
possession: the service verifies the signature with `site_jwk` from the body.

`endpoints` are absolute URLs built with `rest_url()`; they may use the
`?rest_route=` form on sites without pretty permalinks. Services MUST use them
as given and never build REST URLs themselves. In `network` mode (§2.1),
`mode` is `"network"`, `client_id` is the main site's origin, the
`redirect_uri` points to the Network Admin
(`/wp-admin/network/edit.php?action=site_portrait_callback&_wpnonce=…`), and
`endpoints` additionally contains `"sites"` (§6.5).

The service MUST verify, and reject with HTTP 400 `{"error":"invalid_grant"}`
otherwise:

1. `code` is valid, unused, unexpired, and its bound `client_id` and
   `redirect_uri` equal the body values;
2. `base64url(SHA-256(code_verifier)) == code_challenge`;
3. the RFC 7638 thumbprint of `site_jwk` equals the bound `site_key_thumbprint`;
4. the HTTP signature is valid for `site_jwk` and `keyid` equals that thumbprint;
5. every `endpoints` URL has the same origin as `client_id` **or** the same
   host as `redirect_uri`.

Success response (`200`, JSON):

```json
{
  "pairing_id": "c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11",
  "scopes": ["core", "plugins", "themes", "server"],
  "jwks": { "keys": [ { "kty": "OKP", "crv": "Ed25519", "x": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w", "kid": "UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4" } ] },
  "account_hint": "Bakery Inc."
}
```

| Member | Description |
|---|---|
| `pairing_id` | Opaque identifier (≤ 64 chars, `[A-Za-z0-9._-]`) chosen by the service. |
| `scopes` | MUST equal (or be a subset of) the requested scopes. |
| `jwks` | Service keys the site will pin. Each key MUST also appear in the discovery `jwks` fetched in §3 (the site checks this). |
| `account_hint` | Optional plain-text label (e.g. customer account) shown in the site settings. |

The site then stores the pairing (service origin, name, endpoints, pinned
service keys, its own key pair, scopes, `pairing_id`, timestamps), deletes the
pending pairing, and enables the REST routes.

### 4.5 Confirmation (service → site)

A successful code exchange only proves that *someone* holding the code, the
verifier and the site key completed the flow. Before treating the pairing as
active the service MUST call `GET {endpoints.status}` (§6.2) with a signed
request and check that:

* the response signature verifies with the `site_jwk` received at §4.4, and
* the returned `pairing_id` equals the one it issued.

This proves that the WordPress installation actually reachable at `client_id`
holds the pairing. If confirmation fails within 15 minutes the service SHOULD
discard the pairing.

## 5. HTTP message signatures

All authenticated requests and all responses of the site REST API use HTTP
Message Signatures (RFC 9421) with Ed25519. Content digests use RFC 9530.

### 5.1 Request signatures

Signature label: `sp`. Required parameters:

| Parameter | Rule |
|---|---|
| `created` | Unix time. Receiver accepts if `|now − created| ≤ 300`. |
| `expires` | Unix time. MUST satisfy `created < expires ≤ created + 300` and `now < expires`. |
| `nonce` | 16–64 chars `[A-Za-z0-9_-]`, ≥ 128 bits of randomness. Single use (§5.4). |
| `keyid` | `kid` (RFC 7638 thumbprint) of the signing key. |
| `alg` | `"ed25519"`. |
| `tag` | `"site-portrait/1"`. |

Required covered components, **in this order**:

| Request | Covered components |
|---|---|
| `GET` (no body) | `"@method" "@authority" "@path" "@query"` |
| `POST` (JSON body) | `"@method" "@authority" "@path" "@query" "content-type" "content-digest"` |

Exception: the token request (§4.4) and the revocation notice (§10.1) are
addressed to the service and use the same `POST` list (`@query` is then `?`).

Component values follow RFC 9421 §2.2:

* `@authority` — lower-cased host, plus `:port` only when not the default port.
* `@path` — the path as sent on the wire (not decoded).
* `@query` — `?` followed by the query string exactly as sent (not decoded or
  re-encoded); `?` alone when there is no query.

Receivers rebuild the signature base from the request line they actually
received (on WordPress: `$_SERVER['REQUEST_URI']` and the `Host` header), and
compare `@authority` against the host of `home_url()`. Reverse proxies that
rewrite the path or host break verification by design.

Additional members in `Signature-Input` / `Signature` with other labels are
ignored. A request with no `sp` signature is rejected.

### 5.2 Response signatures

Every response of the site REST API (success **and** error) carries:

```
Content-Digest: sha-256=:<base64 SHA-256 of the body>:
Signature-Input: sp=("@status" "content-type" "content-digest" "signature";req;key="sp");created=…;keyid="<site kid>";alg="ed25519";tag="site-portrait/1"
Signature: sp=:…:
Site-Portrait-Protocol: 1
```

Covering `"signature";req;key="sp"` binds the response to the exact signed
request. Responses to requests that carried no valid `sp` signature are still
signed but omit that component. Services SHOULD verify response signatures; doing
so gives non-repudiable evidence that a portrait came from the paired site.

### 5.3 Verification algorithm (site side)

1. Parse `Signature-Input` and `Signature` (RFC 8941 dictionaries). Missing or
   malformed → `site_portrait_signature_missing` / `_malformed`.
2. Check `alg`, `tag`, covered components list → `_malformed`.
3. Check `created`/`expires` window → `_expired`.
4. Look up `keyid` among the pinned service keys → `_unknown_key` (may trigger
   §11 refresh).
5. For POST, recompute and compare `Content-Digest` → `site_portrait_digest_mismatch`.
6. Rebuild the signature base and verify the Ed25519 signature →
   `_signature_invalid`.
7. Atomically record the nonce; if already present → `_replay`.

Steps 1–6 happen before any database write. Comparisons are constant-time.

### 5.4 Replay protection

The site remembers `(keyid, nonce)` pairs for at least `expires − now + 60`
seconds and rejects any reuse. Combined with the 300-second window this makes
captured requests worthless after five minutes, and useless even within that
window.

## 6. Site REST endpoints

Namespace: `site-portrait/v1`. The routes are **only registered while an active
pairing exists**; otherwise the API answers with WordPress' standard 404
`rest_no_route`. All routes require a valid request signature from a pinned
service key; WordPress cookie or application-password authentication is
ignored and never sufficient.

### 6.1 Common response headers

```
Content-Type: application/json; charset=UTF-8
Cache-Control: no-store
Site-Portrait-Protocol: 1
Content-Digest, Signature-Input, Signature  (see §5.2)
```

### 6.2 `GET /site-portrait/v1/status`

Cheap health/identity check; used for confirmation (§4.5) and key discovery.

```json
{
  "protocol_version": "1",
  "plugin_version": "1.0.0",
  "pairing_id": "c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11",
  "mode": "single",
  "site_url": "https://example.com",
  "sites_count": 1,
  "scopes_granted": ["core", "plugins", "themes", "server"],
  "scopes_available": ["core", "plugins", "themes", "server", "database", "content", "users_counts"],
  "site_jwks": {
    "keys": [
      { "kty": "OKP", "crv": "Ed25519", "x": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q", "kid": "aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU" }
    ]
  },
  "rate_limit": { "limit": 60, "remaining": 59, "window": 3600 },
  "server_time": 1792400000
}
```

`scopes_granted` is authoritative: the administrator can change it at any time
in wp-admin without re-pairing. Services SHOULD call `/status` before each
portrait retrieval rather than caching scopes.

### 6.3 `GET /site-portrait/v1/portrait`

Query parameter:

| Name | Description |
|---|---|
| `scopes` | Optional comma-separated list. Defaults to all granted scopes. |
| `site_id` | `network` mode only. Optional blog ID from `/sites`. |

In `network` mode without `site_id`, the portrait describes the network as a
whole: `server` and `database` (always network-wide), `plugins` (network-active
plugins plus every plugin installed; `active` means active on at least one
site), `themes` (installed themes; `active` means active on at least one site),
`core` (whose `multisite` block then gives the network summary), `content` and `users_counts` summed over
all sites **within the time budget** (see `warnings` with code `partial`).
With `site_id`, `content`, `users_counts`, `themes` (active theme) and the
per-site part of `plugins` describe that site only; `server` and `database`
remain network-wide. An unknown, archived, spam or deleted site →
`404 site_portrait_unknown_site`. `site_id` in `single` mode →
`400 site_portrait_invalid_param`.

* An unknown scope name → `400 site_portrait_invalid_scope`.
* A known but not-granted scope is **omitted**, listed in `scopes_denied`, and
  the request still succeeds (so that narrowing scopes on the site does not
  break the service).
* If no requested scope is granted → `403 site_portrait_scope_denied`.

Response body: the portrait document (§8). Example request:

```
GET /wp-json/site-portrait/v1/portrait?scopes=core,plugins HTTP/1.1
Host: example.com
Signature-Input: sp=("@method" "@authority" "@path" "@query");created=1792400000;expires=1792400300;nonce="bWFkZS1mb3ItdGVzdGluZw";keyid="UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4";alg="ed25519";tag="site-portrait/1"
Signature: sp=:BCOf82rkgP/WyuEMhL+8EJn9P9Z8Z0quKfLY2ghLzkiuICoNAMWZVBhJYbbelfkE/zEbDgzBXlqyFAwD50oNBA==:
```

Generating a portrait may take a few seconds on large sites (directory sizes
are computed with a time budget and cached for one hour; see §8.4). Services
SHOULD use a timeout of at least 30 seconds.

### 6.4 `POST /site-portrait/v1/revoke`

Service-initiated revocation (e.g. the customer closed their account). Body:

```json
{ "pairing_id": "c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11", "reason": "account_closed" }
```

The site verifies the signature and `pairing_id`, deletes the pairing (pinned
keys, site key pair, nonces) and answers `200 {"revoked": true}` signed with the
site key that was just discarded. This is the only request that changes state,
and it only removes the plugin's own pairing data.

### 6.5 `GET /site-portrait/v1/sites` (`network` mode only)

Lists the sites of the network, 100 per page, ordered by blog ID. Requires the
`core` scope. Not registered in `single` mode.

| Query parameter | Description |
|---|---|
| `page` | 1-based page number (default 1). |

```json
{
  "page": 1,
  "per_page": 100,
  "total": 3,
  "total_pages": 1,
  "sites": [
    { "site_id": 1, "url": "https://example.com/", "main": true,  "public": true, "archived": false, "spam": false, "deleted": false, "registered": "2019-04-02T10:11:12Z", "last_updated": "2026-10-18T22:01:00Z", "active_theme": "twentytwentyfive", "active_plugins_count": 12, "posts_count": 340, "attachments_count": 2210 },
    { "site_id": 2, "url": "https://example.com/shop/", "main": false, "public": true, "archived": false, "spam": false, "deleted": false, "registered": "2021-01-15T08:00:00Z", "last_updated": "2026-10-17T09:30:00Z", "active_theme": "storefront", "active_plugins_count": 25, "posts_count": 58, "attachments_count": 9120 }
  ]
}
```

`posts_count` counts published items of public post types. `posts_count` and
`attachments_count` require the `content` scope, `active_plugins_count` the
`plugins` scope and `active_theme` the `themes` scope; they are `null` when that
scope is not granted. The normative schema is
[`schema/sites-v1.schema.json`](schema/sites-v1.schema.json).

Site URLs of every site in the network are disclosed by this endpoint; the
consent screen states it explicitly in `network` mode.

## 7. Scopes

| Scope | Contents (summary) | Notes |
|---|---|---|
| `core` | WordPress version and update status, locale and installed languages, multisite summary, environment type, HTTPS status, permalink type, debug flags (booleans), cron health, object/page cache detection, auto-update settings. | |
| `plugins` | Installed plugins (slug, name, version, active / network-active, auto-update, available update), must-use plugins, drop-ins (file names only). | |
| `themes` | Active theme and parent, installed themes (slug, name, version, block/classic, available update). | |
| `server` | OS family, architecture, web server software, PHP version/SAPI/extensions/ini limits, OPcache, CPU count, memory, disk free/total on the wp-content volume, image libraries, cURL/OpenSSL versions. | No hostnames, no IPs, no paths. |
| `database` | Engine and version, charset/collation, total size, table count, size of the largest tables (prefix stripped), options and autoloaded-options size/count, transient count. | No credentials, no table prefix, no host. |
| `content` | Counts per post type and status, revisions, attachments by MIME family, taxonomies and term counts, comments by status, size of uploads / wp-content / plugins / themes directories. | Counts and sizes only, never content. |
| `users_counts` | Number of users in total and per role. | Counts only; never logins, names or e-mail addresses. |

Scope names match `^[a-z][a-z0-9_]{1,31}$`. Future versions may add scopes;
services MUST ignore unknown scopes in `scopes_available`.

## 8. The portrait document

The normative definition is the JSON Schema
[`schema/portrait-v1.schema.json`](schema/portrait-v1.schema.json) (draft
2020-12). This section explains the conventions.

### 8.1 Envelope

```json
{
  "schema_version": "1.0.0",
  "protocol_version": "1",
  "generated_at": "2026-10-19T14:00:00Z",
  "generation_time_ms": 412,
  "pairing_id": "c0a7d0e2-4f0f-4d8b-9a59-1d3c0f6a7b11",
  "mode": "single",
  "site_id": null,
  "site": { "home_url": "https://example.com", "site_url": "https://example.com", "name": "My Bakery" },
  "plugin": { "version": "1.0.0" },
  "scopes_returned": ["core", "plugins"],
  "scopes_denied": [],
  "data": {
    "core": { "...": "..." },
    "plugins": { "...": "..." }
  },
  "warnings": [
    { "scope": "server", "field": "memory.total", "code": "unavailable", "message": "/proc/meminfo is not readable." }
  ]
}
```

* `schema_version` follows SemVer. Minor versions only **add** optional members;
  a major version bump means a new protocol version.
* `data` contains exactly one member per scope in `scopes_returned`.
* A value that cannot be determined is `null` (never omitted, never guessed) and
  MAY have a matching entry in `warnings`.
* A collector that fails entirely yields `data.<scope> = null` plus a warning;
  the rest of the portrait is still returned.
* `mode` is `single` or `network`; `site_id` is the requested blog ID, or
  `null` for a single site or a network-wide portrait. In a network-wide
  portrait, `site` describes the main site.

### 8.2 Data sources

Where possible the plugin reuses the core *Site Health* data
(`WP_Debug_Data::debug_data()`), then normalises it into typed values (Site
Health returns localised, human-formatted strings, which are unsuitable for
machines). CPU and memory are read from `/proc/cpuinfo`, `/proc/meminfo` and
the cgroup files (`/sys/fs/cgroup/cpu.max`, `memory.max`) when readable, so
that container limits are reported in addition to host values; otherwise the
values are `null`. The plugin never executes shell commands.

### 8.3 Minimisation rules (normative for the plugin)

The portrait MUST NOT contain: passwords, salts, keys, tokens, database
credentials or host, `wp-config.php` contents or constants other than the
documented booleans, user logins, display names or e-mail addresses, post or
comment content or titles, IP addresses, server hostnames, absolute file-system
paths, the database table prefix, or environment variables.

### 8.4 Expensive values

Directory sizes are computed with a time budget (default 10 s in total) and
cached for one hour. When the budget is exceeded the size is `null`, with a
`timeout` warning; later calls continue from the cache.

### 8.5 Extensibility

The filter `site_portrait_scope_data` lets other plugins append data inside
the `extensions` member of a scope object (namespaced by their slug). It cannot
remove or alter core members, and the result is still subject to §8.3 review by
whoever adds data.

## 9. Errors

Error responses use WordPress' REST format and are signed like any response:

```json
{ "code": "site_portrait_signature_expired", "message": "The request signature has expired.", "data": { "status": 401 } }
```

| HTTP | `code` | Meaning |
|---|---|---|
| 404 | `rest_no_route` | No active pairing (routes not registered). |
| 400 | `site_portrait_invalid_scope` | Unknown scope in `scopes`. |
| 400 | `site_portrait_digest_mismatch` | `Content-Digest` does not match the body. |
| 400 | `site_portrait_invalid_body` | Malformed JSON body (POST). |
| 400 | `site_portrait_invalid_param` | Invalid query parameter (e.g. `site_id` in `single` mode, bad `page`). |
| 404 | `site_portrait_unknown_site` | `site_id` does not designate an active site of the network. |
| 401 | `site_portrait_signature_missing` | No `sp` signature. |
| 401 | `site_portrait_signature_malformed` | Unparseable fields, wrong `alg`/`tag`, wrong covered components. |
| 401 | `site_portrait_signature_expired` | Outside the `created`/`expires` window (check your clock). |
| 401 | `site_portrait_unknown_key` | `keyid` is not a pinned service key. |
| 401 | `site_portrait_signature_invalid` | Signature verification failed. |
| 401 | `site_portrait_replay` | Nonce already used. |
| 403 | `site_portrait_ip_not_allowed` | Source IP not in the allow-list. |
| 403 | `site_portrait_scope_denied` | None of the requested scopes is granted. |
| 403 | `site_portrait_https_required` | Request received over plain HTTP. |
| 409 | `site_portrait_pairing_mismatch` | `pairing_id` in body does not match (revoke). |
| 429 | `site_portrait_rate_limited` | Too many requests; see `Retry-After`. |
| 500 | `site_portrait_internal_error` | Unexpected failure (details only in the site's log). |

Failed authentication attempts are logged (§12.3) but never echo back the
expected values.

Service-side endpoints (§4.4, §10.1) use OAuth-style errors:
`{"error": "invalid_grant" | "invalid_request" | "invalid_signature" | "server_error", "error_description": "…"}`.

## 10. Revocation

### 10.1 Site-initiated (administrator clicks "Disconnect")

1. The site immediately deletes the pinned service keys and marks the pairing
   revoked locally. From this instant every signed request fails with 404.
2. Best effort, the site sends a revocation notice signed with its site key:

   ```
   POST {revocation_endpoint}
   Content-Type: application/json
   Content-Digest / Signature-Input / Signature (site key, §5.1 POST list)

   { "pairing_id": "c0a7…", "client_id": "https://example.com", "reason": "revoked_by_site" }
   ```

   The service verifies the signature with the site key it recorded for
   `pairing_id`, deletes the pairing and answers `200 {"revoked": true}`.
   Failure (network, 5xx) is shown to the administrator but does not undo the
   local revocation; the service will see 404s anyway.
3. The site deletes its own key pair.

`reason` is one of `revoked_by_site`, `plugin_uninstalled`, `key_compromised`.
The plugin's `uninstall.php` sends `plugin_uninstalled` (best effort, 5 s
timeout). Plain deactivation does **not** revoke: routes disappear while the
plugin is inactive and come back on reactivation.

### 10.2 Service-initiated

See §6.4.

## 11. Key rotation

Pinned keys can be rotated without re-pairing through **endorsements**: a new
key is accepted only if it is signed by a key the receiver already trusts.

Endorsement of a new key `N` by a trusted key `T`:

```
message   = "site-portrait/1 key-endorsement " + kid(N)     (ASCII)
signature = Ed25519-sign(T.private, message)
```

carried as an extra JWK member of `N`:

```json
{ "kty": "OKP", "crv": "Ed25519", "x": "<N>", "kid": "<kid(N)>",
  "endorsements": [ { "kid": "<kid(T)>", "sig": "<base64url signature>" } ] }
```

### 11.1 Service key rotation

1. The service publishes `N` (with an endorsement by the current key) in the
   discovery `jwks`, alongside the current key, for at least 7 days.
2. It then signs requests with `N`.
3. A site receiving an unknown `keyid` re-fetches discovery (at most once per
   hour), pins every key that carries a valid endorsement by an already pinned
   key, and retries verification once.
4. Keys that disappear from the discovery `jwks` are unpinned on the next
   refresh — **unless** this would leave no pinned key.

A service whose keys are all compromised or lost cannot rotate; the
administrator must disconnect and pair again.

### 11.2 Site key rotation

The administrator can click "Rotate site key". The site generates `N`, endorses
it with the current key, starts signing responses with `N` and keeps the old
public key listed in `/status` `site_jwks` for 7 days. A service that sees an
unknown response `keyid` calls `/status`, verifies the endorsement against the
site key it already knows, and records `N`.

## 12. Site-side policies

### 12.1 Rate limiting

Per pairing, sliding one-hour window; default **60 requests/hour** for all
endpoints combined in `single` mode, and **60 + 2 × number of sites** in
`network` mode so that every site can be listed and described once per hour
(filter `site_portrait_rate_limit`). Exceeding it returns
429 with `Retry-After` (seconds). Failed authentication attempts are rate
limited per source IP as well (default 30/hour) to keep log noise bounded.

### 12.2 IP allow-list

Optional, configured by the administrator (one IP or CIDR per line, IPv4 and
IPv6). The plugin checks `REMOTE_ADDR` only; sites behind a trusted reverse
proxy can supply the client IP through the `site_portrait_client_ip` filter.
Services SHOULD publish the IP ranges they call from (e.g. in their
documentation) so administrators can use this feature.

### 12.3 Access log

Every request to the REST routes is logged: date (UTC), source IP, endpoint,
`keyid`, requested/returned scopes, HTTP status and error code. The log is
visible to administrators in the plugin settings, capped at 500 entries and
90 days, and deleted on uninstall.

## 13. Service implementation checklist

A compatible service must:

- [ ] Serve `/.well-known/site-portrait` over HTTPS (§3), with a privacy policy URL.
- [ ] Generate and protect an Ed25519 key pair (HSM/KMS or secret store
      recommended); publish its public key with an RFC 7638 `kid`.
- [ ] Implement the authorization endpoint (§4.2–4.3): authenticate the user,
      display site URL and scopes, issue single-use codes bound to the request
      parameters, redirect to `redirect_uri` exactly as received.
- [ ] Implement the token endpoint (§4.4): verify PKCE, thumbprint, signature and
      endpoint origins; return `pairing_id` and `jwks`.
- [ ] Confirm the pairing with a signed `GET /status` (§4.5).
- [ ] Sign every request per §5.1 with unique nonces and a synced clock (NTP).
- [ ] Use the `endpoints` URLs exactly as provided.
- [ ] Respect `scopes_granted`, `429`/`Retry-After`, and treat `404` as "pairing
      gone".
- [ ] Implement the revocation endpoint (§10.1) and optionally call `/revoke`
      (§6.4).
- [ ] Verify response signatures (§5.2) — recommended.
- [ ] Document what it does with the data, and how long it keeps it, in its
      privacy policy.

The repository ships a reference command-line client (`bin/reference-client`)
that plays the service role and can be used as a starting point and for
end-to-end tests.

## 14. Security considerations

### 14.1 Threat model

| Threat | Mitigation |
|---|---|
| Site database leaked (backup, SQL injection elsewhere) | Only the service **public** key is stored: the attacker cannot forge requests. They obtain the site private key, which only lets them sign responses / revocation notices as that site; the administrator can rotate or re-pair. |
| Service database leaked | No credential grants admin access. If the service private key itself leaks, the attacker can read granted scopes (read-only) until the service rotates keys or administrators disconnect. Keep the key in a KMS. |
| Network attacker | TLS everywhere; signatures over method, authority, path and query; replay protection via nonces and a 300 s window. |
| Request replay to another site paired with the same service | `@authority` is covered and compared with `home_url()`. |
| CSRF / login CSRF on pairing | WP nonce + `manage_options` + per-user pending state + `state` parameter. |
| Authorization-code interception | PKCE S256; code bound to `site_key_thumbprint`; token request signed with the site key. |
| Someone pairs a site they do not own | The confirmation step (§4.5) requires the real site at `client_id` to return the `pairing_id` signed with the registered site key. |
| Subsite administrator in a multisite network discloses network-wide data | Pairing is only possible in `network` mode by a super admin (§2.1). |
| Malicious or compromised service | Read-only API, admin-chosen scopes, data minimisation (§8.3), access log, IP allow-list, one-click revocation. No code or configuration is ever accepted from the service. |
| SSRF via service URL | Only administrators can enter it; `wp_safe_remote_*` blocks private ranges; no redirects; HTTPS only; response size capped. |
| Malicious discovery content | All strings are escaped on display; URLs must be HTTPS and same-origin; size limit. |
| Brute force / log flooding | Rate limits per pairing and per IP; capped log. |

### 14.2 Private key storage on the site

The site private key is stored in a non-autoloaded option. WordPress offers no
better secret store; the impact of its disclosure is limited as described
above. Uninstalling or disconnecting deletes it.

### 14.3 Clock skew

Both parties MUST keep their clocks synchronised. `/status` returns
`server_time` to help services diagnose `site_portrait_signature_expired`.

### 14.4 Cryptographic implementation

The plugin uses `sodium_crypto_sign_detached()` / `_verify_detached()` and
`random_bytes()`, provided by PHP's sodium extension or WordPress' bundled
`sodium_compat` polyfill. No custom cryptography is implemented; RFC 9421 is
only used to define *what* is signed.

### 14.5 Privacy

The portrait describes a website's technical configuration; it contains no
personal data under the rules of §8.3, apart from the site URL and name and the
source IP addresses kept in the site's own access log.

### 14.6 Development mode

For local testing only, the plugin accepts `http` service URLs and private IP
addresses when **all** of the following hold: the constant
`SITE_PORTRAIT_DEV_MODE` is `true`, `wp_get_environment_type()` is `local` or
`development`, and both the site and the service hosts end in `.test`,
`.localhost` or are `localhost`. The settings page shows a permanent warning
while it is active.

## 15. Test vectors

All keys below are derived from fixed 32-byte seeds and MUST NOT be used
outside tests.

| Key | Seed | `x` | `kid` |
|---|---|---|---|
| Service | 32 × `0x01` | `iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w` | `UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4` |
| Site | 32 × `0x02` | `gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q` | `aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU` |
| New key | 32 × `0x03` | `7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E` | `nRIE2VmKdMjL1JD7tbV7fXVgXxmv0GKnMFWRUJMTf9Q` |

### 15.1 PKCE

```
code_verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

### 15.2 Signed request (service key)

`GET https://example.com/wp-json/site-portrait/v1/portrait?scopes=core,plugins`

Signature base (lines separated by `\n`, no trailing newline):

```
"@method": GET
"@authority": example.com
"@path": /wp-json/site-portrait/v1/portrait
"@query": ?scopes=core,plugins
"@signature-params": ("@method" "@authority" "@path" "@query");created=1792400000;expires=1792400300;nonce="bWFkZS1mb3ItdGVzdGluZw";keyid="UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4";alg="ed25519";tag="site-portrait/1"
```

Headers:

```
Signature-Input: sp=("@method" "@authority" "@path" "@query");created=1792400000;expires=1792400300;nonce="bWFkZS1mb3ItdGVzdGluZw";keyid="UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4";alg="ed25519";tag="site-portrait/1"
Signature: sp=:BCOf82rkgP/WyuEMhL+8EJn9P9Z8Z0quKfLY2ghLzkiuICoNAMWZVBhJYbbelfkE/zEbDgzBXlqyFAwD50oNBA==:
```

### 15.3 Signed response (site key)

Status `200`, body `{"ok":true}`.

```
"@status": 200
"content-type": application/json; charset=UTF-8
"content-digest": sha-256=:QGLtr3UPuAdOfoPgyQKMlOMkaKi28WFHdDKO8EUVD5M=:
"signature";req;key="sp": :BCOf82rkgP/WyuEMhL+8EJn9P9Z8Z0quKfLY2ghLzkiuICoNAMWZVBhJYbbelfkE/zEbDgzBXlqyFAwD50oNBA==:
"@signature-params": ("@status" "content-type" "content-digest" "signature";req;key="sp");created=1792400001;keyid="aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU";alg="ed25519";tag="site-portrait/1"
```

```
Signature: sp=:RB+R308P9gAS41M/lWK4oVEiAGNAuSReP3aOzmo55wNQIbGs9V7R2G10u9kagVAP8WMv2Q3vAa1UBGetZtQZDQ==:
```

### 15.4 Key endorsement (new key endorsed by the service key)

```
message   = site-portrait/1 key-endorsement nRIE2VmKdMjL1JD7tbV7fXVgXxmv0GKnMFWRUJMTf9Q
signature = 2whhMLNOI50wh8SQIwO-ka3zfQUduDeJYsuolyt7xJfMEsjlwPwEatNVosebORX9LcMcoGiCOvfF6qI8QJQfBA
```

## 16. Comparison with Application Passwords

WordPress core ships an "Authorize Application" flow
(`/wp-admin/authorize-application.php`) that hands an Application Password to an
external app. It was considered and rejected for this use case:

| | Application Password | Site Portrait signatures |
|---|---|---|
| Privileges | All capabilities of the user (an administrator → can install plugins, create users…) | Read-only, per-scope, administrator-chosen |
| Credential type | Bearer secret sent on every request | Asymmetric; private key never leaves the service |
| Service breach | Full admin access to every connected site | Read access to granted scopes only |
| Site DB breach | Hashed, cannot be replayed | Public key only, cannot be replayed |
| Replay protection | None beyond TLS | Nonce + 300 s window |
| Hosting quirks | `Authorization` header stripped by some hosts (CGI/FastCGI) | Uses `Signature*` headers, unaffected |
| Implementation cost | Built into core | Plugin and service must implement RFC 9421 (libraries exist for most languages) |
| Revocation | Core UI | Plugin UI + notification |

A dedicated low-privilege user with an application password would reduce the
blast radius but still exposes the whole REST API readable by that user, keeps
a bearer secret, and requires creating a user account on the site. The
signature-based design gives least privilege by construction.
