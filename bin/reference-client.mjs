#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Site Portrait reference client: plays the service role for end-to-end tests
// and shows what a compatible service must implement (docs/PROTOCOL.md §13).
//
//   node bin/reference-client.mjs serve [--port 8787] [--public-url URL] [--auto-approve]
//        [--scopes-supported a,b] [--scopes-requested a,b]
//   node bin/reference-client.mjs status|portrait|sites|revoke [--pairing ID] [...]
//   node bin/reference-client.mjs pairings | rotate-key
//
// Options: --state-dir DIR (default .reference-client), --scopes a,b,
// --site-id N, --page N, --out FILE, --validate (portrait/sites, needs ajv).
// --scopes-supported defaults to every scope of the portrait schema (all
// platforms); --scopes-requested (pre-ticked scopes) defaults to the same list.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { State } from './lib/state.mjs';
import { createService } from './lib/service.mjs';
import { signedFetch } from './lib/client.mjs';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2);
      if (v !== undefined) args[k] = v;
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) args[k] = argv[++i];
      else args[k] = true;
    } else {
      args._.push(a);
    }
  }
  return args;
}

async function validate(schemaFile, data) {
  const { default: Ajv } = await import('ajv/dist/2020.js');
  const { default: addFormats } = await import('ajv-formats');
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/schema', schemaFile), 'utf8'));
  const ok = ajv.validate(schema, data);
  return ok ? [] : ajv.errors;
}

function print(result) {
  console.error(`HTTP ${result.status}${result.kid ? ` — response signature verified (site key ${result.kid})` : ' — response not signed'}`);
  console.log(JSON.stringify(result.json ?? result.text, null, 2));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];
  const state = new State(path.resolve(args['state-dir'] ?? path.join(ROOT, '.reference-client')));

  if (command === 'serve') {
    const port = Number(args.port ?? 8787);
    const publicUrl = (args['public-url'] ?? `http://127.0.0.1:${port}`).replace(/\/$/, '');
    const { server, scopesSupported } = createService({
      state,
      publicUrl,
      autoApprove: Boolean(args['auto-approve']),
      log: (m) => console.log(`[service] ${m}`),
      ...(typeof args['scopes-supported'] === 'string' && { scopesSupported: args['scopes-supported'] }),
      ...(typeof args['scopes-requested'] === 'string' && { scopesRequested: args['scopes-requested'] }),
    });
    server.listen(port, () => console.log(`[service] listening on ${publicUrl} (key ${state.signingKey().kid}, scopes ${scopesSupported.join(',')})`));
    return;
  }

  if (command === 'pairings') {
    console.log(JSON.stringify(Object.values(state.load().pairings), null, 2));
    return;
  }
  if (command === 'rotate-key') {
    console.log(`New service key: ${state.rotateKey()} (endorsed by the previous key, both published)`);
    return;
  }

  const pairing = state.pairing(typeof args.pairing === 'string' ? args.pairing : undefined);
  if (!pairing) {
    console.error('No pairing. Run "serve" and connect a site first.');
    process.exit(1);
  }

  let result;
  if (command === 'status') {
    result = await signedFetch(state, pairing, 'status');
  } else if (command === 'portrait') {
    result = await signedFetch(state, pairing, 'portrait', { query: { scopes: args.scopes, site_id: args['site-id'] } });
  } else if (command === 'sites') {
    result = await signedFetch(state, pairing, 'sites', { query: { page: args.page } });
  } else if (command === 'revoke') {
    result = await signedFetch(state, pairing, 'revoke', { method: 'POST', body: { pairing_id: pairing.pairing_id, reason: 'account_closed' } });
    if (result.status === 200) state.deletePairing(pairing.pairing_id);
  } else {
    console.error('Usage: reference-client.mjs serve|status|portrait|sites|revoke|pairings|rotate-key [options]');
    process.exit(2);
  }

  print(result);
  if (args.out && result.json) fs.writeFileSync(args.out, JSON.stringify(result.json, null, 2));
  if (args.validate && result.status === 200) {
    const errors = await validate(command === 'sites' ? 'sites-v1.schema.json' : 'portrait-v1.schema.json', result.json);
    console.error(errors.length ? `Schema: INVALID\n${JSON.stringify(errors, null, 2)}` : 'Schema: valid');
    if (errors.length) process.exit(3);
  }
  if (result.status >= 400) process.exit(1);
}

main().catch((e) => {
  console.error(e.code ? `${e.code}: ${e.message}` : e);
  process.exit(1);
});
