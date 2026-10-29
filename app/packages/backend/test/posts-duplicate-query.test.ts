/**
 * Duplicate scalar query keys on the posts reads.
 *
 * The replay harness and the native /users and /following reads fail closed
 * with 501 DUPLICATE_QUERY_KEYS_UNIMPLEMENTED on a repeated query key, because
 * the scalar OpenAPI parameters do not establish semantics for repeated keys.
 * The posts sub-resources previously coerced them silently: a repeated limit
 * fell through to the default page size with 200, and a repeated cursor was
 * misreported as 400 INVALID_CURSOR. The single-post read takes no query
 * parameters but previously served 200 past any repeated key. The batch
 * /v1/posts route is exempt by design: repeated `ids` keys are documented to
 * collapse (POSTS.md item 24).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from './with-api-key.js';

const POST_1 = '00000000-0000-4000-8000-000000000001';
const POST_2 = '00000000-0000-4000-8000-000000000002';

describe('duplicate query keys on posts sub-resources', () => {
  test('repeated limit on replies fails closed instead of silently defaulting', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}/replies?limit=1&limit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated offset on likers fails closed', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}/likers?offset=0&offset=1`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated cursor on quotes fails closed instead of INVALID_CURSOR', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}/quotes?cursor=abc&cursor=def`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated limit on reposters fails closed', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}/reposters?limit=1&limit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated key on the single-post read fails closed instead of serving past it', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}?limit=1&limit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('percent-encoded duplicate key on the single-post read cannot bypass the check', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}?%6cimit=1&limit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('single post without a repeated key still serves', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}`);
      assert.equal(res.statusCode, 200);
      assert.equal(res.json().post.postId, POST_1);
    } finally {
      await app.close();
    }
  });

  test('percent-encoded duplicate key cannot bypass the check', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject(`/v1/posts/${POST_1}/replies?limit=1&%6cimit=2`);
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('single limit still pages, and repeated ids on the batch route still collapse', async () => {
    const app = buildApp([]);
    try {
      const single = await app.inject(`/v1/posts/${POST_1}/replies?limit=1`);
      assert.equal(single.statusCode, 200);
      assert.equal(single.json().replies.length, 1);

      const batch = await app.inject(`/v1/posts?ids=${POST_1}&ids=${POST_2}`);
      assert.equal(batch.statusCode, 200);
      assert.equal(batch.json().posts.length, 2);
    } finally {
      await app.close();
    }
  });
});
