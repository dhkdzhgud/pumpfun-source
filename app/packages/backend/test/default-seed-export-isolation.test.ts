import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { UserStore, SYNTHETIC_SEED } from '../src/users-store.js';
import { PostStore, SYNTHETIC_POSTS_SEED } from '../src/posts-store.js';

test('editing an exported user seed row cannot rewrite later default stores', () => {
  const retained = JSON.parse(readFileSync(new URL('../src/users-seed.json', import.meta.url), 'utf8'))[0];
  const row = SYNTHETIC_SEED[0];
  const bio = row.bio;
  try {
    // The exported array is readonly, but its row properties are publicly mutable.
    row.bio = 'Consumer-owned presentation note';
    assert.deepEqual(new UserStore().getById(retained.userId ?? retained.address), retained);
  } finally { row.bio = bio; }
});

test('editing nested exported post data cannot rewrite later default stores', () => {
  const retained = JSON.parse(readFileSync(new URL('../src/posts-seed.json', import.meta.url), 'utf8'));
  const row = SYNTHETIC_POSTS_SEED.find(row => !row.deleted && !row.hidden && row.kind !== 'repost')!;
  const expected = retained.find((entry: { postId: string }) => entry.postId === row.postId);
  const mentions = structuredClone(row.mentions);
  const content = row.content;
  try {
    row.content = 'Consumer-owned preview';
    row.mentions.push({ userId: 'local-only', username: 'local-only', walletAddress: null });
    const post = new PostStore().getLivePost(row.postId)!;
    assert.equal(post.content, expected.content);
    assert.deepEqual(post.mentions, expected.mentions);
  } finally { row.content = content; row.mentions = mentions; }
});

test('explicit caller-owned seeds continue to supply custom rows', () => {
  const rows = structuredClone([...SYNTHETIC_SEED]);
  rows[0].bio = 'Explicit synthetic fixture';
  const store = new UserStore(rows);
  assert.equal(store.getById(rows[0].userId ?? rows[0].address)!.bio, 'Explicit synthetic fixture');
});
