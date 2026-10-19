// End-to-end tests in network mode (multisite, network-activated plugin).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { startWordPress, startService, Browser, formFields, notices, waitFor, rewriteOrigin, ROOT } from './helpers.mjs';
import { signedFetch } from '../../bin/lib/client.mjs';

const ALL_SCOPES = ['core', 'plugins', 'themes', 'server', 'database', 'content', 'users_counts'];
const SETTINGS = '/wp-admin/network/settings.php?page=site-portrait';

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const schema = (name) => ajv.compile(JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/schema', name), 'utf8')));
const validatePortrait = schema('portrait-v1.schema.json');
const validateSites = schema('sites-v1.schema.json');

let wp;
let svc;
let admin;
let pairing;
let restoreFetch = () => {};
const call = (endpoint, opts) => signedFetch(svc.state, pairing, endpoint, opts);

before(async () => {
  wp = await startWordPress({ port: 9412, blueprint: 'blueprint-multisite.json', siteUrl: 'http://127.0.0.1' });
  restoreFetch = rewriteOrigin('http://127.0.0.1', 'http://127.0.0.1:9412');
  svc = await startService();
  admin = new Browser(wp.url);
  await admin.login();
});

after(async () => {
  await svc?.stop();
  await wp?.stop();
  restoreFetch();
});

test('subsite administrators see no settings page', async () => {
  const page = await admin.request('/shop/wp-admin/options-general.php?page=site-portrait');
  assert.doesNotMatch(page.text, /Look up service/);
});

test('super admin pairs the network from the Network Admin', async () => {
  let page = await admin.request(SETTINGS);
  let f = formFields(page.text, 'discover');
  assert.match(f.action, /\/wp-admin\/network\/edit\.php\?action=site_portrait_discover/);
  page = await admin.request(f.action, { method: 'POST', form: { ...f.fields, service_url: svc.url } });
  assert.match(page.text, /list the addresses of all sites/);
  f = formFields(page.text, 'connect');
  const form = new URLSearchParams(f.fields);
  for (const s of ALL_SCOPES) form.append('scopes[]', s);
  page = await admin.request(f.action, { method: 'POST', form });
  assert.ok(notices(page.text).some((n) => n.startsWith('success')), notices(page.text).join('\n'));
  pairing = await waitFor(() => Object.values(svc.state.load().pairings).find((p) => p.confirmed));
  assert.equal(pairing.mode, 'network');
  assert.ok(pairing.endpoints.sites);
});

test('status reports network mode', async () => {
  const r = await call('status');
  assert.equal(r.status, 200);
  assert.equal(r.json.mode, 'network');
  assert.equal(r.json.sites_count, 2);
});

test('sites lists every site with counts', async () => {
  const r = await call('sites');
  assert.equal(r.status, 200);
  assert.ok(r.kid);
  assert.ok(validateSites(r.json), JSON.stringify(validateSites.errors, null, 2));
  assert.equal(r.json.total, 2);
  const shop = r.json.sites.find((s) => s.url.endsWith('/shop/'));
  assert.equal(shop.main, false);
  assert.equal(shop.posts_count, 5, 'three products, the default post and the sample page');
  assert.equal(shop.active_plugins_count, 1);
});

test('network-wide portrait aggregates sites', async () => {
  const r = await call('portrait');
  assert.equal(r.status, 200);
  assert.ok(validatePortrait(r.json), JSON.stringify(validatePortrait.errors, null, 2));
  assert.equal(r.json.mode, 'network');
  assert.equal(r.json.site_id, null);
  assert.equal(r.json.data.core.multisite.enabled, true);
  assert.equal(r.json.data.core.multisite.sites_count, 2);
  const posts = r.json.data.content.post_types.find((t) => t.name === 'post');
  assert.equal(posts.counts.publish, 5);
  const hello = r.json.data.plugins.items.find((p) => p.slug === 'hello');
  assert.equal(hello.active, true);
  assert.equal(hello.active_sites, 1);
  const self = r.json.data.plugins.items.find((p) => p.slug === 'site-portrait');
  assert.equal(self.network_active, true);
  assert.equal(r.json.data.users_counts.network_total, 1);
});

test('per-site portrait', async () => {
  const sites = (await call('sites')).json.sites;
  const shop = sites.find((s) => s.url.endsWith('/shop/'));
  const r = await call('portrait', { query: { site_id: shop.site_id, scopes: 'content,themes' } });
  assert.equal(r.status, 200);
  assert.ok(validatePortrait(r.json), JSON.stringify(validatePortrait.errors, null, 2));
  assert.equal(r.json.site_id, shop.site_id);
  assert.match(r.json.site.home_url, /\/shop$/);
  assert.equal(r.json.data.content.post_types.find((t) => t.name === 'post').counts.publish, 4);

  const missing = await call('portrait', { query: { site_id: 999 } });
  assert.equal(missing.status, 404);
  assert.equal(missing.json.code, 'site_portrait_unknown_site');
});

test('routes are only served by the main site', async () => {
  const res = await fetch(`${wp.url}/shop/wp-json/site-portrait/v1/status`);
  assert.equal(res.status, 404);
});

test('disconnect from the Network Admin', async () => {
  const page = await admin.request(SETTINGS);
  const f = formFields(page.text, 'disconnect');
  const result = await admin.request(f.action, { method: 'POST', form: f.fields });
  assert.ok(notices(result.text).some((n) => n.startsWith('success')), notices(result.text).join('\n'));
  assert.equal(svc.state.pairing(pairing.pairing_id), null);
});
