import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { LeaderboardStore } from '../src/leaderboard-store.js';

const seed = JSON.parse(readFileSync(new URL('../src/leaderboard-seed.json', import.meta.url), 'utf8'));

test('PnL ties use exact wallet identities after locale collation equivalence', () => {
  // The materialized contract permits string wallet identifiers, including
  // canonically equivalent but distinct strings. No wallet ownership is implied.
  const wallets = ['wallet-\u00e9', 'wallet-e\u0301'];
  assert.equal(wallets[0].localeCompare(wallets[1]), 0);
  const template = seed.daily[0];
  const rows = wallets.map(walletAddress => ({ ...structuredClone(template), userId: null, walletAddress }));
  const boards = (entries: typeof rows) => new LeaderboardStore({ daily: entries, weekly: entries, monthly: entries });
  const expected = [...wallets].sort();
  for (const period of ['daily', 'weekly', 'monthly'] as const) {
    for (const sort of ['combined', 'realized', 'unrealized'] as const) {
      for (const entries of [rows, [...rows].reverse()]) {
        const board = boards(entries).getBoard({ period, sort });
        assert.deepEqual(board.entries.map(row => row.walletAddress), expected);
        assert.deepEqual(board.entries.map(row => row.rank), [1, 2]);
        assert.equal(boards(entries).getBoard({ period, sort, limit: 1 }).entries[0].walletAddress, expected[0]);
      }
    }
  }
});

test('PnL measure takes priority over the wallet tie break', () => {
  const lower = { ...structuredClone(seed.daily[0]), userId: null, walletAddress: 'wallet-a', pnlUsd: 1 };
  const higher = { ...structuredClone(seed.daily[0]), userId: null, walletAddress: 'wallet-z', pnlUsd: 2 };
  const entries = [lower, higher];
  const store = new LeaderboardStore({ daily: entries, weekly: entries, monthly: entries });
  assert.deepEqual(store.getBoard({ period: 'daily' }).entries.map(row => row.walletAddress), ['wallet-z', 'wallet-a']);
});
