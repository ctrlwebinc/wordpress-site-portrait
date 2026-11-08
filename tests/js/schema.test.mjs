// Portrait schema 1.1.0: platform member, Laravel scopes, extended database engines.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const read = (rel) => JSON.parse(fs.readFileSync(new URL(rel, import.meta.url), 'utf8'));
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(read('../../docs/schema/portrait-v1.schema.json'));
const laravel = read('./fixtures/portrait-laravel.json');
const check = (doc) => assert.ok(validate(doc), JSON.stringify(validate.errors, null, 2));
const clone = (o) => structuredClone(o);

test('a Laravel portrait is valid', () => check(laravel));

test('platform is optional (absent means wordpress)', () => {
  const doc = clone(laravel);
  delete doc.platform;
  check(doc);
});

test('WordPress distribution members, including future values', () => {
  const doc = clone(laravel);
  doc.platform = { name: 'wordpress', version: '6.8.3', distribution: 'bedrock', distribution_version: '1.24.0', composer_managed: true, acorn: 'v5.0.1' };
  check(doc);
  doc.platform.distribution = 'some-future-distribution';
  check(doc);
  doc.platform.composer_managed = 'yes';
  assert.equal(validate(doc), false);
});

test('platform name must be a lower-case identifier', () => {
  const doc = clone(laravel);
  doc.platform.name = 'Laravel';
  assert.equal(validate(doc), false);
});

test('scope members are strict about their required fields', () => {
  for (const [scope, member] of [['laravel', 'drivers'], ['packages', 'platform'], ['storage', 'disks']]) {
    const doc = clone(laravel);
    delete doc.data[scope][member];
    assert.equal(validate(doc), false, `${scope}.${member} is required`);
  }
  const doc = clone(laravel);
  doc.data.laravel.environment_type = 'testing';
  assert.equal(validate(doc), false, 'unknown environment types are null');
});

test('storage.files is optional, its counts may be null', () => {
  const doc = clone(laravel);
  doc.data.storage.files = { app: null, app_public: null, public: null, computed_at: null };
  check(doc);
  delete doc.data.storage.files;
  check(doc);
  doc.data.storage.files = { app: 1 };
  assert.equal(validate(doc), false, 'all members are required when files is present');
});

test('unknown values are null and every scope may be null', () => {
  const doc = clone(laravel);
  doc.data.laravel.environment_type = null;
  doc.data.storage.sizes.vendor = null;
  doc.data.packages.items[0].version = null;
  doc.data.storage = null;
  check(doc);
});
