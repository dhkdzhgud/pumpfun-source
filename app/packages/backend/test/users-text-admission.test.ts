import test from 'node:test';
import assert from 'node:assert/strict';
import { UserStore, type User } from '../src/users-store.js';
import { buildApp } from './with-api-key.js';

const sample = () => new UserStore().list({})[0];
const nullable = ['username', 'profile_image', 'bio', 'x_username'] as const;
const optionalNullable = ['header_image_url', 'avatar_decoration', 'resolved_avatar_decoration', 'last_active_at'] as const;
const optional = ['userId', 'wallet_label', 'canonical_svm_wallet', 'canonical_evm_wallet'] as const;

test('mistyped public user text is rejected before it can reach a response or search', () => {
  for (const field of ['address', ...nullable, ...optionalNullable, ...optional]) {
    for (const value of [123, false, [], {}]) {
      const row = { ...sample(), [field]: value } as unknown as User;
      assert.throws(() => new UserStore([row]), TypeError, `${field}: ${JSON.stringify(value)}`);
    }
  }
});

test('required nullable text must be supplied; optional fields may be absent', () => {
  for (const field of ['address', ...nullable]) {
    const row = sample();
    delete (row as unknown as Record<string, unknown>)[field];
    assert.throws(() => new UserStore([row]), TypeError, field);
  }
  for (const field of ['address', ...optional]) {
    assert.throws(() => new UserStore([{ ...sample(), [field]: null } as unknown as User]), TypeError, field);
  }
  const row = sample();
  for (const field of [...optional, ...optionalNullable]) delete row[field];
  assert.doesNotThrow(() => new UserStore([row]));
});

test('nullable and empty string metadata remain available through the real user route', async () => {
  const row = sample();
  row.username = null;
  row.profile_image = null;
  row.bio = '';
  row.x_username = null;
  row.header_image_url = null;
  row.avatar_decoration = '';
  row.resolved_avatar_decoration = null;
  row.last_active_at = null;
  const store = new UserStore([row]);
  const app = buildApp([], { userStore: store });
  try {
    const response = await app.inject(`/v1/users/${row.userId ?? row.address}`);
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().bio, '');
    assert.equal(response.json().username, null);
    assert.equal(response.json().header_image_url, null);
  } finally { await app.close(); }
});
