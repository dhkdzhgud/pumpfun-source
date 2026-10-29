/**
 * Developer profiles/graph contract boundaries, not website compatibility tests.
 * The public OpenAPI explicitly omits last_active_at on the API host, even though
 * the shared UserProfile schema permits the property for signed-in website reads.
 * All identities and timestamps below are synthetic local test data.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from './with-api-key.js';
import { UserStore, type User } from '../src/users-store.js';
import { FollowingStore } from '../src/following-store.js';

const DATA_HEADER = 'x-reconstruction-data-source';

function makeApp(lastActive: string | null = '2026-10-28T12:00:00.000Z') {
  const seed: User[] = [
    {
      address: 'wallet-alice', userId: 'alice', username: 'alice', profile_image: null,
      bio: 'Synthetic profile', followers: 2, following: 1, x_username: null,
      last_active_at: lastActive, resolved_avatar_decoration: 'epic',
      group_badges: [{ group_id: 'group-example', username: 'example', profile_image_url: null, role: 'MEMBER' }],
    },
    {
      address: 'wallet-bob', userId: 'bob', username: 'bob', profile_image: null,
      bio: null, followers: 1, following: 1, x_username: null, last_active_at: lastActive,
    },
  ];
  // A transport projection must never delete activity from the domain store.
  for (const user of seed) Object.freeze(user);
  Object.freeze(seed);
  const users = new UserStore(seed, ['alice']);
  const following = new FollowingStore(users, [
    { follower_id: 'bob', following_id: 'alice', timestamp: 1000 },
    { follower_id: 'alice', following_id: 'bob', timestamp: 2000 },
  ]);
  return { app: buildApp([], { userStore: users, followingStore: following }), users, seed };
}

const profileReads = [
  { method: 'GET', url: '/v1/users', rows: (body: any) => body },
  { method: 'GET', url: '/v1/users/alice', rows: (body: any) => [body] },
  { method: 'GET', url: '/v1/users/search-v2?searchTerm=ali', rows: (body: any) => body },
  { method: 'GET', url: '/v1/users/alice/overview', rows: (body: any) => [body.profile] },
  { method: 'POST', url: '/v1/users/batch', payload: { addresses: ['wallet-alice'] }, rows: (body: any) => body },
  { method: 'GET', url: '/v1/following/v3/followers/search/alice?searchTerm=bob', rows: (body: any) => body },
  { method: 'GET', url: '/v1/following/v3/following/search/bob?searchTerm=ali', rows: (body: any) => body },
] as const;

for (const lastActive of ['2026-10-28T12:00:00.000Z', null]) {
  for (const request of profileReads) {
    test(`${request.method} ${request.url} omits API-host activity (${lastActive === null ? 'null' : 'populated'})`, async t => {
      const { app, users, seed } = makeApp(lastActive);
      t.after(() => app.close());
      const before = structuredClone(seed);
      const response = await app.inject(request);
      assert.equal(response.statusCode, request.method === 'POST' ? 201 : 200);
      assert.equal(response.headers[DATA_HEADER], 'synthetic-seed-play');
      const rows = request.rows(response.json());
      assert.ok(rows.length > 0, 'must exercise an actual profile, not an empty page');
      for (const row of rows) {
        assert.equal(Object.hasOwn(row, 'last_active_at'), false);
        const expected = { ...users.getById(row.userId)! };
        delete expected.last_active_at;
        assert.deepEqual(row, expected, 'all other profile fields must be preserved');
      }
      assert.deepEqual(seed, before);
      assert.equal(users.getById('alice')!.last_active_at, lastActive);
      assert.equal(users.getById('bob')!.last_active_at, lastActive);
    });
  }
}

test('verified batch preserves every requested string key, including object prototype names', async t => {
  const { app } = makeApp();
  t.after(() => app.close());
  const ids = ['alice', '__proto__', 'constructor', 'toString', 'hasOwnProperty', 'missing'];
  const response = await app.inject({ method: 'POST', url: '/v1/profiles/verified', payload: { ids } });
  assert.equal(response.statusCode, 201);
  assert.equal(response.headers[DATA_HEADER], 'synthetic-seed-play');
  const body = response.json();
  assert.deepEqual(body, Object.fromEntries(ids.map(id => [id, id === 'alice'])));
  for (const id of ids) assert.equal(Object.hasOwn(body, id), true, id);
});

test('verified map can represent a verified user whose id is __proto__', t => {
  const { app, seed } = makeApp();
  t.after(() => app.close());
  const users = new UserStore([{ ...seed[0], userId: '__proto__' }], ['__proto__']);
  const result = users.batchVerified(['__proto__']);
  assert.equal(Object.hasOwn(result, '__proto__'), true);
  assert.equal(result['__proto__'], true);
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
});

const nativeReadRequests = [
  ...profileReads,
  { method: 'GET', url: '/v1/users/username-exists/alice' },
  { method: 'POST', url: '/v1/profiles/verified', payload: { ids: ['alice'] } },
  { method: 'GET', url: '/v1/following/single/alice?userId=bob' },
  { method: 'GET', url: '/v1/following/v3/followers/count/alice' },
  { method: 'GET', url: '/v1/following/v3/following/count/alice' },
  { method: 'GET', url: '/v1/following/v3/followers/alice' },
  { method: 'GET', url: '/v1/following/v3/following/alice' },
] as const;

for (const request of nativeReadRequests) {
  test(`${request.method} ${request.url} fails closed for ambiguous query keys`, async t => {
    const { app } = makeApp();
    t.after(() => app.close());
    const reference = await app.inject('/services/profile/unimplemented?extra=one&extra=two');
    assert.equal(reference.statusCode, 501);
    assert.deepEqual(reference.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
    // Compare with the existing replay boundary rather than invent upstream semantics.
    const separator = request.url.includes('?') ? '&' : '?';
    const response = await app.inject({ ...request, url: `${request.url}${separator}extra=one&%65xtra=two` });
    assert.equal(response.statusCode, reference.statusCode);
    assert.deepEqual(response.json(), reference.json());
    assert.equal(response.headers[DATA_HEADER], undefined);
    // Rejection is request-local, not a store mutation or poisoned route state.
    const valid = await app.inject(request);
    assert.equal(valid.statusCode, request.method === 'POST' ? 201 : 200);
  });
}

for (const url of [
  '/v1/users/search-v2?searchTerm=alice&searchTerm=bob',
  '/v1/following/v3/followers/search/alice?searchTerm=alice&searchTerm=bob',
  '/v1/following/v3/following/search/bob?searchTerm=alice&searchTerm=bob',
  '/v1/following/single/alice?userId=bob&userId=alice',
  '/v1/following/v3/followers/alice?offset=0&offset=1',
  '/v1/following/v3/following/alice?limit=1&limit=2',
]) {
  test(`duplicate scalar parameter cannot crash or silently coerce: ${url}`, async t => {
    const { app } = makeApp();
    t.after(() => app.close());
    const response = await app.inject(url);
    assert.equal(response.statusCode, 501);
    assert.deepEqual(response.json(), { statusCode: 501, error: 'DUPLICATE_QUERY_KEYS_UNIMPLEMENTED' });
  });
}

for (const path of [
  '/v1/following/v3/followers/alice',
  '/v1/following/v3/following/alice',
  '/v1/following/v3/followers/search/alice?searchTerm=bo',
  '/v1/following/v3/following/search/alice?searchTerm=bo',
]) {
  test(`${path} enforces the documented safe-integer offset maximum`, async t => {
    const { app } = makeApp();
    t.after(() => app.close());
    const separator = path.includes('?') ? '&' : '?';
    for (const offset of ['9007199254740992', '1e100', 'Infinity', '0.5', '-1']) {
      const response = await app.inject(`${path}${separator}offset=${offset}`);
      assert.equal(response.statusCode, 400, offset);
      assert.equal(response.json().error, 'INVALID_OFFSET', offset);
      assert.equal(response.headers[DATA_HEADER], undefined);
    }
    const maximum = await app.inject(`${path}${separator}offset=9007199254740991`);
    assert.equal(maximum.statusCode, 200);
    assert.deepEqual(maximum.json(), []);
    const first = await app.inject(`${path}${separator}offset=0&limit=1`);
    assert.equal(first.statusCode, 200);
    assert.equal(first.json().length, 1);
  });
}

test('API-key gate still runs before profile/graph query rejection', async t => {
  const { app } = makeApp();
  t.after(() => app.close());
  for (const url of ['/v1/users', '/v1/following/v3/followers/alice']) {
    const response = await app.inject({ url: `${url}?x=a&x=b`, headers: { authorization: '' } });
    assert.equal(response.statusCode, 401);
    assert.equal(response.json().error, 'API_KEY_REQUIRED');
  }
});
