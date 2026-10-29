/**
 * Tests for the native /pnl-leaderboard read operation.
 *
 * Verifies:
 * - Contract conformance for the 200 response via assertSchema(..., specRoot).
 * - Deterministic ranking by the combined measure, descending, with ranks 1..N.
 * - sort=realized reorders on the realized measure.
 * - positionsLimit clamps to 5, 0 means count-only, positionsCount stays whole.
 * - limit defaults/ceilings at 100 and never goes negative.
 * - Required period: missing and unknown values are 400s on the Error schema.
 * - Profile hydration from the shared UserStore, including bare-wallet rows.
 * - Repeated query keys fail closed with 501 DUPLICATE_QUERY_KEYS_UNIMPLEMENTED,
 *   matching the native users/following/posts reads.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildApp } from './with-api-key.js';
import { assertSchema, type SchemaNode, type SchemaRoot } from '../src/schema-validator.js';
import { SYNTHETIC_HEADER } from '../src/users-routes.js';
import { DATA_SOURCE } from '../src/users-store.js';

interface OpenApiDocument {
  paths: Record<string, Record<string, {
    responses?: Record<string, { content?: Record<string, { schema?: SchemaNode }> }>;
  }>>;
  components?: { schemas?: Record<string, SchemaNode> };
}

const SPEC_PATH = fileURLToPath(new URL('../../../contracts/developer.openapi.json', import.meta.url));
const spec = JSON.parse(readFileSync(SPEC_PATH, 'utf8')) as OpenApiDocument;
const specRoot = spec as unknown as SchemaRoot;

function documentedSchema(path: string, method: string, status: number): SchemaNode {
  const schema = spec.paths[path]?.[method.toLowerCase()]?.responses?.[String(status)]?.content?.['application/json']?.schema;
  assert.ok(schema, `No documented schema for ${method.toUpperCase()} ${path} ${status}`);
  return schema;
}

const boardSchema = documentedSchema('/pnl-leaderboard', 'get', 200);
const errorSchema = spec.components?.schemas?.Error as SchemaNode;
assert.ok(errorSchema, 'components.schemas.Error must exist');

const ALICE = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
const BOB = 'DfMxre4cKmvogbLrPigxmibVTTQDuzjdXojWzjCXXhzj';

describe('GET /v1/pnl-leaderboard', () => {
  test('200 conforms to the published schema and is marked synthetic', async () => {
    const app = buildApp([]);
    try {
      const r = await app.inject('/v1/pnl-leaderboard?period=weekly');
      assert.equal(r.statusCode, 200);
      assert.equal(r.headers[SYNTHETIC_HEADER.toLowerCase()], DATA_SOURCE);
      assertSchema(r.json(), boardSchema, 'GET /v1/pnl-leaderboard?period=weekly', specRoot);
      const body = r.json() as { periodType: number; periodLabel: string; windowStartSec: number; entries: unknown[] };
      assert.equal(body.periodType, 2);
      assert.equal(body.periodLabel, 'Weekly');
      assert.ok(Number.isInteger(body.windowStartSec) && body.windowStartSec > 0);
      assert.ok(body.entries.length > 0);
    } finally {
      await app.close();
    }
  });

  test('default ranking is the combined measure, descending, ranks 1..N', async () => {
    const app = buildApp([]);
    try {
      const r = await app.inject('/v1/pnl-leaderboard?period=weekly');
      const entries = (r.json() as { entries: Array<{ rank: number; pnlUsd: number; walletAddress: string }> }).entries;
      assert.deepEqual(entries.map(e => e.rank), entries.map((_, i) => i + 1));
      for (let i = 1; i < entries.length; i++) {
        assert.ok(entries[i - 1].pnlUsd >= entries[i].pnlUsd, 'pnlUsd must not increase down the board');
      }
      assert.equal(entries[0].walletAddress, ALICE);
    } finally {
      await app.close();
    }
  });

  test('sort=realized reorders on the realized measure', async () => {
    const app = buildApp([]);
    try {
      const r = await app.inject('/v1/pnl-leaderboard?period=weekly&sort=realized');
      const entries = (r.json() as { entries: Array<{ realizedPnlUsd: number; walletAddress: string }> }).entries;
      assert.equal(entries[0].walletAddress, BOB, 'Bob has the highest realized PnL');
      for (let i = 1; i < entries.length; i++) {
        assert.ok(entries[i - 1].realizedPnlUsd >= entries[i].realizedPnlUsd);
      }
    } finally {
      await app.close();
    }
  });

  test('positionsLimit clamps to 5, 0 is count-only, positionsCount stays whole', async () => {
    const app = buildApp([]);
    try {
      const top = async (query: string) => {
        const r = await app.inject(`/v1/pnl-leaderboard?period=weekly&${query}`);
        return (r.json() as { entries: Array<{ positionsCount: number; topPositions: unknown[] }> }).entries[0];
      };
      const dflt = await top('');
      assert.equal(dflt.positionsCount, 6);
      assert.equal(dflt.topPositions.length, 3);
      const wide = await top('positionsLimit=10');
      assert.equal(wide.positionsCount, 6);
      assert.equal(wide.topPositions.length, 5);
      const countOnly = await top('positionsLimit=0');
      assert.equal(countOnly.positionsCount, 6);
      assert.equal(countOnly.topPositions.length, 0);
    } finally {
      await app.close();
    }
  });

  test('limit ceilings at 100 and never goes negative', async () => {
    const app = buildApp([]);
    try {
      const count = async (query: string) => {
        const r = await app.inject(`/v1/pnl-leaderboard?period=weekly&${query}`);
        return (r.json() as { entries: unknown[] }).entries.length;
      };
      const full = await count('limit=100');
      assert.equal(full, 6);
      assert.equal(await count('limit=2'), 2);
      assert.equal(await count('limit=0'), 0);
      assert.equal(await count('limit=-5'), 0);
      assert.equal(await count('limit=9999'), 6);
    } finally {
      await app.close();
    }
  });

  test('a missing period is a 400 on the Error schema', async () => {
    const app = buildApp([]);
    try {
      const r = await app.inject('/v1/pnl-leaderboard');
      assert.equal(r.statusCode, 400);
      assertSchema(r.json(), errorSchema, '400 missing period', specRoot);
      assert.equal((r.json() as { error: string }).error, 'PERIOD_REQUIRED');
    } finally {
      await app.close();
    }
  });

  test('an unknown period is a 400 on the Error schema', async () => {
    const app = buildApp([]);
    try {
      const r = await app.inject('/v1/pnl-leaderboard?period=yearly');
      assert.equal(r.statusCode, 400);
      assertSchema(r.json(), errorSchema, '400 invalid period', specRoot);
      assert.equal((r.json() as { error: string }).error, 'INVALID_PERIOD');
    } finally {
      await app.close();
    }
  });

  test('profiles hydrate from the user store; bare-wallet rows stay anonymous', async () => {
    const app = buildApp([]);
    try {
      const r = await app.inject('/v1/pnl-leaderboard?period=weekly');
      const entries = (r.json() as { entries: Array<Record<string, unknown>> }).entries;
      const alice = entries.find(e => e.walletAddress === ALICE)!;
      assert.equal(alice.username, 'alice_pump');
      assert.equal(alice.isVerified, true);
      assert.equal(alice.verifiedBadgeVisible, true);
      const bare = entries.find(e => e.userId === null)!;
      assert.ok(bare, 'a bare-wallet row exists');
      assert.equal(bare.username, null);
      assert.equal(bare.profileImage, null);
      assert.equal(bare.isVerified, false);
      // Anonymous reads never carry viewer-relative keys.
      assert.equal(Object.hasOwn(alice, 'isViewer'), false);
      assert.equal(Object.hasOwn(alice, 'viewerFollows'), false);
    } finally {
      await app.close();
    }
  });

  test('daily and monthly windows resolve to their period types', async () => {
    const app = buildApp([]);
    try {
      for (const [period, type] of [['daily', 1], ['monthly', 3]] as const) {
        const r = await app.inject(`/v1/pnl-leaderboard?period=${period}`);
        assert.equal(r.statusCode, 200);
        assertSchema(r.json(), boardSchema, `GET /v1/pnl-leaderboard?period=${period}`, specRoot);
        assert.equal((r.json() as { periodType: number }).periodType, type);
      }
    } finally {
      await app.close();
    }
  });

  test('the board is deterministic across identical reads', async () => {
    const app = buildApp([]);
    try {
      const a = await app.inject('/v1/pnl-leaderboard?period=weekly&positionsLimit=5');
      const b = await app.inject('/v1/pnl-leaderboard?period=weekly&positionsLimit=5');
      assert.deepEqual(a.json(), b.json());
    } finally {
      await app.close();
    }
  });
});

describe('duplicate query keys on GET /v1/pnl-leaderboard', () => {
  test('repeated period fails closed instead of a 400 with an array received', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject('/v1/pnl-leaderboard?period=daily&period=weekly');
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated limit fails closed instead of silently defaulting', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject('/v1/pnl-leaderboard?period=weekly&limit=1&limit=2');
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('repeated sort and positionsLimit fail closed', async () => {
    const app = buildApp([]);
    try {
      for (const query of ['sort=realized&sort=combined', 'positionsLimit=1&positionsLimit=5']) {
        const res = await app.inject(`/v1/pnl-leaderboard?period=weekly&${query}`);
        assert.equal(res.statusCode, 501, query);
        assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
      }
    } finally {
      await app.close();
    }
  });

  test('percent-encoded duplicate key cannot bypass the check', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject('/v1/pnl-leaderboard?period=weekly&limit=1&%6cimit=2');
      assert.equal(res.statusCode, 501);
      assert.deepEqual(res.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    } finally {
      await app.close();
    }
  });

  test('single-valued queries still serve the board', async () => {
    const app = buildApp([]);
    try {
      const res = await app.inject('/v1/pnl-leaderboard?period=weekly&limit=2&sort=realized&positionsLimit=1');
      assert.equal(res.statusCode, 200);
      assertSchema(res.json(), boardSchema, 'GET /v1/pnl-leaderboard single-valued', specRoot);
      const entries = (res.json() as { entries: Array<{ topPositions: unknown[] }> }).entries;
      assert.equal(entries.length, 2);
      assert.equal(entries[0].topPositions.length, 1);
    } finally {
      await app.close();
    }
  });
});
