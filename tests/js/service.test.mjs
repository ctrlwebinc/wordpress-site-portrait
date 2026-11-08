// Reference service: configurable scope list (discovery document, §3.1).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { State } from '../../bin/lib/state.mjs';
import { createService, parseScopes, DEFAULT_SCOPES } from '../../bin/lib/service.mjs';

async function discovery(options) {
  const state = new State(fs.mkdtempSync(path.join(os.tmpdir(), 'sp-service-unit-')));
  const { server } = createService({ state, publicUrl: 'http://127.0.0.1', ...options });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/.well-known/site-portrait`);
    return await res.json();
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(state.dir, { recursive: true, force: true });
  }
}

test('defaults to every scope of the schema', async () => {
  const d = await discovery({});
  assert.deepEqual(d.scopes_supported, DEFAULT_SCOPES);
  assert.deepEqual(d.scopes_requested, DEFAULT_SCOPES);
  assert.equal(DEFAULT_SCOPES.length, 10);
});

test('accepts a custom list as an array or a string', async () => {
  let d = await discovery({ scopesSupported: ['laravel', 'packages', 'storage', 'server'] });
  assert.deepEqual(d.scopes_supported, ['laravel', 'packages', 'storage', 'server']);
  d = await discovery({ scopesSupported: 'server, database users_counts', scopesRequested: 'server,core' });
  assert.deepEqual(d.scopes_supported, ['server', 'database', 'users_counts']);
  assert.deepEqual(d.scopes_requested, ['server'], 'requested scopes are limited to supported ones');
});

test('rejects empty lists and invalid names', () => {
  assert.throws(() => parseScopes(''), /empty/);
  assert.throws(() => parseScopes(['core', 'Bad-Scope']), /Invalid scope name/);
  assert.deepEqual(parseScopes('core,core,plugins'), ['core', 'plugins']);
});
