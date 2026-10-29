import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildApp } from './with-api-key.js';
import { assertSchema } from '../src/schema-validator.js';

const spec = JSON.parse(readFileSync(new URL('../../../contracts/developer.openapi.json', import.meta.url), 'utf8'));

test('shared native and fixture duplicate-query refusals satisfy the retained Error contract', async () => {
  const app = buildApp([]);
  try {
    for (const url of [
      '/v1/users?offset=0&offset=1',
      '/v1/following/v3/followers/user-001?limit=1&limit=2',
      '/v1/posts/example/replies?limit=1&limit=2',
      '/v1/competitions?x=1&x=2',
      '/v1/pnl-leaderboard?period=daily&period=weekly',
      '/v1/unimplemented?x=1&%78=2',
    ]) {
      const response = await app.inject(url);
      assert.equal(response.statusCode, 501, url);
      assert.equal(response.json().error, 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED', url);
      assertSchema(response.json(), spec.components.schemas.Error, url, spec);
      assert.equal(response.json().statusCode, response.statusCode, url);
    }
  } finally { await app.close(); }
});

test('an unavailable fixture operation carries statusCode without changing its diagnostic fields', async () => {
  const app = buildApp([]);
  try {
    const response = await app.inject('/v1/unimplemented');
    assert.equal(response.statusCode, 501);
    assertSchema(response.json(), spec.components.schemas.Error, 'unavailable operation', spec);
    assert.deepEqual(response.json(), {
      statusCode: 501, error: 'COMPATIBILITY_NOT_IMPLEMENTED', method: 'GET', path: '/v1/unimplemented',
    });
    const success = await app.inject('/v1/users?offset=0&limit=1');
    assert.equal(success.statusCode, 200);
    assert.ok(Array.isArray(success.json()));
  } finally { await app.close(); }
});
