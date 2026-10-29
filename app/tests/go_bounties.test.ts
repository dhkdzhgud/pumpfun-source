import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  GO_CAPTURE_BYTES,
  GO_CAPTURE_SHA256,
  GoEvidenceError,
  GoQueryError,
  formatAtomicAmount,
  normalizeGoQuery,
  parseGoQuery,
  queryArchivedBounties,
  validateArchivedBounty,
  verifyGoEvidence,
} from "../packages/frontend/src/app/go/go-data.ts";

const capturePath = "evidence/web/objects/e66810e11f481135";
const manifestPath = "evidence/web/manifest.json";

async function snapshot() {
  const [bytes, manifestText] = await Promise.all([
    readFile(capturePath),
    readFile(manifestPath, "utf8"),
  ]);
  return {
    bytes,
    manifest: JSON.parse(manifestText),
    value: verifyGoEvidence(bytes, JSON.parse(manifestText)),
  };
}

test("verifies exact GO capture provenance and extracts only direct bounty records", async () => {
  const { bytes, value } = await snapshot();
  assert.equal(bytes.byteLength, GO_CAPTURE_BYTES);
  assert.equal(value.sha256, GO_CAPTURE_SHA256);
  assert.equal(value.sourceUrl, "https://pump.fun/go");
  assert.equal(value.bounties.length, 25);
  assert.equal(new Set(value.bounties.map((bounty) => bounty.taskId)).size, 25);
  assert.ok(value.bounties.every((bounty) => bounty.title.length > 0));
});

test("fails closed for modified page bytes and manifest provenance", async () => {
  const { bytes, manifest } = await snapshot();
  const modifiedBytes = Buffer.from(bytes);
  modifiedBytes[modifiedBytes.length - 100] ^= 1;
  assert.throws(
    () => verifyGoEvidence(modifiedBytes, manifest),
    GoEvidenceError,
  );

  const changedManifest = structuredClone(manifest);
  const record = changedManifest.records.find(
    (entry: { url?: string }) => entry.url === "https://pump.fun/go",
  );
  record.sha256 = "0".repeat(64);
  assert.throws(
    () => verifyGoEvidence(bytes, changedManifest),
    GoEvidenceError,
  );
});

test("bounds and canonicalizes public query state", () => {
  assert.deepEqual(
    parseGoQuery(
      new URLSearchParams(
        "q=%24x&status=OPEN&sort=expiresAt&order=asc&cursor=c24",
      ),
    ),
    {
      q: "$x",
      status: "OPEN",
      sort: "expiresAt",
      order: "asc",
      cursor: "c24",
      task: undefined,
    },
  );
  for (const query of [
    "status=LIVE",
    "sort=unknown",
    "order=random",
    "cursor=c1",
    "q=a&q=b",
    "remote=https://example.com",
  ]) {
    assert.throws(
      () => parseGoQuery(new URLSearchParams(query)),
      GoQueryError,
      query,
    );
  }
  const normalized = normalizeGoQuery(
    new URLSearchParams("q=safe&status=LIVE&remote=x"),
  );
  assert.equal(normalized.ignoredInvalidState, true);
  assert.equal(normalized.query.q, "safe");
  assert.equal(normalized.query.status, "ALL");
});

test("overlong GO search recovery preserves complete Unicode characters", () => {
  const raw = "x".repeat(255) + "😀";
  const normalized = normalizeGoQuery(new URLSearchParams({ q: raw }));
  assert.equal(normalized.ignoredInvalidState, true);
  assert.equal(normalized.query.q, "x".repeat(255));
  const reparsed = parseGoQuery(new URLSearchParams({ q: normalized.query.q }));
  assert.equal(reparsed.q, normalized.query.q, "recovery must survive URL serialization without replacement characters");
});

test("GO recovery retains the existing UTF-16 limit and complete boundary characters", () => {
  const exact = "x".repeat(254) + "😀";
  assert.equal(parseGoQuery(new URLSearchParams({ q: exact })).q, exact);
  assert.equal(normalizeGoQuery(new URLSearchParams({ q: exact, unsupported: "1" })).query.q, exact);
  assert.equal(normalizeGoQuery(new URLSearchParams({ q: "a".repeat(257) })).query.q, "a".repeat(256));
  assert.throws(() => parseGoQuery(new URLSearchParams({ q: "😀".repeat(129) })), GoQueryError);
});

test("search, validated sorting and cursor pagination are deterministic", async () => {
  const { value } = await snapshot();
  const base = {
    q: "",
    status: "ALL" as const,
    sort: "createdAt" as const,
    order: "desc" as const,
  };
  const first = queryArchivedBounties(value, base);
  assert.equal(first.items.length, 24);
  assert.equal(first.total, 25);
  assert.equal(first.nextCursor, "c24");
  const second = queryArchivedBounties(value, {
    ...base,
    cursor: first.nextCursor,
  });
  assert.equal(second.items.length, 1);
  assert.equal(second.previousCursor, "c0");
  assert.equal(
    new Set([...first.items, ...second.items].map((item) => item.taskId)).size,
    25,
  );

  const reversed = queryArchivedBounties(value, { ...base, order: "asc" });
  assert.notEqual(first.items[0].taskId, reversed.items[0].taskId);
  const searched = queryArchivedBounties(value, {
    ...base,
    q: first.items[0].taskId,
  });
  assert.deepEqual(
    searched.items.map((item) => item.taskId),
    [first.items[0].taskId],
  );
});

test("atomic rewards never use floating point and missing values stay unavailable", () => {
  assert.equal(
    formatAtomicAmount("900719925474099312345678", 9),
    "900719925474099.312345678",
  );
  assert.equal(formatAtomicAmount("1000000000", 9), "1");
  assert.equal(formatAtomicAmount(undefined, 9), undefined);
  assert.equal(formatAtomicAmount("not-a-number", 9), undefined);
});

test("malformed bounty records fail schema validation", () => {
  assert.throws(
    () =>
      validateArchivedBounty({ taskId: "not-a-uuid" }, "2026-10-28T00:00:00Z"),
    GoEvidenceError,
  );
});

test('archived bounty dates require real ISO instants',()=>{
  const base={taskId:'11111111-1111-4111-8111-111111111111',creatorAddress:'1'.repeat(32),status:'PUBLISHED',createdAt:'2026-10-29T00:00:00Z',title:'Synthetic',bodyMarkdown:'Synthetic body',counts:{submissionCount:0},rewardLegs:[]};
  for(const field of ['createdAt','expiresAt']) for(const value of ['1','10/29/2026','2026-02-30T00:00:00Z','2025-02-29T00:00:00Z','2026-10-29T24:00:00Z']) assert.throws(()=>validateArchivedBounty({...base,[field]:value},'2026-10-29T12:00:00Z'),/invalid/);
  assert.doesNotThrow(()=>validateArchivedBounty({...base,expiresAt:'2026-10-30T00:00:00+05:30'},'2026-10-29T12:00:00Z'));
});

test('atomic display never coerces already-rounded numeric inputs',()=>{
  for(const value of [9007199254740992,1,{},true,null])assert.equal(formatAtomicAmount(value as any,0),undefined);
  assert.equal(formatAtomicAmount('9007199254740993',0),'9007199254740993');
});
