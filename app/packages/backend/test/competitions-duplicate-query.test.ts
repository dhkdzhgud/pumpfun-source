/**
 * Duplicate scalar query keys on the native /competitions routes.
 *
 * The replay harness and the native /users, /following, and /posts
 * sub-resource reads fail closed with 501
 * DUPLICATE_QUERY_KEYS_UNIMPLEMENTED on a repeated query key, because
 * the scalar OpenAPI parameters do not establish semantics for repeated
 * keys. The competitions routes previously coerced them silently: a
 * repeated limit fell through to the default page size with 200
 * (Number of an array value is NaN, so the finite check kept the
 * default), so the request the caller thought it made was not the one
 * served. Routes that take no query parameter silently ignored a
 * repeated key instead of failing closed like the replay harness.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from './with-api-key.js';

const LIVE_ID = '11111111-1111-4000-8000-000000000002';
const LIVE_ENTRY_1 = '22222222-2222-4000-8000-000000000001';

describe('duplicate query keys on competitions routes', () => {
  test('repeated limit on competition detail fails closed instead of silently defaulting', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/competitions/${LIVE_ID}?limit=1&limit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated perMemberLimit on competition highlights fails closed', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/competitions/${LIVE_ID}/highlights?perMemberLimit=1&perMemberLimit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated limit on entry highlights fails closed', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/competitions/${LIVE_ID}/entries/${LIVE_ENTRY_1}/highlights?limit=1&limit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated key on the parameter-less competitions routes fails closed', async () => {
    const app = buildApp([]);
    try {
      const list = await app.inject('/v1/competitions?limit=1&limit=2');
      assert.equal(list.statusCode, 501);
      assert.deepEqual(list.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });

      const detail = await app.inject(`/v1/competitions/${LIVE_ID}/entries/${LIVE_ENTRY_1}?limit=1&limit=2`);
      assert.equal(detail.statusCode, 501);
      assert.deepEqual(detail.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('percent-encoded duplicate key cannot bypass the check', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/competitions/${LIVE_ID}?limit=1&%6cimit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('single limit still pages', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/competitions/${LIVE_ID}?limit=2`);
      assert.equal(res.statusCode, 200);
      assert.equal(res.json().leaderboard.entries.length, 2);
    } finally {
      await app.close();
    }
  });
});
