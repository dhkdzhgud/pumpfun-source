import { createHash } from "node:crypto";

export const GO_CAPTURE_URL = "https://pump.fun/go";
export const GO_CAPTURE_PATH = "evidence/web/objects/e66810e11f481135";
export const GO_CAPTURE_SHA256 =
  "8037ac8c628063897531326090f1a4d3cbf8ed0051f4f6e9f88c821f4fee9ece";
export const GO_CAPTURE_BYTES = 1_030_034;
export const GO_PAGE_SIZE = 24;

const GO_RSC_MARKER = '123:["$","$L13b",null,{"initialTrendingFeed":';
const MAX_RSC_BYTES = 600_000;
const MAX_JSON_SEGMENT_BYTES = 300_000;
const MAX_SEARCH_LENGTH = 256;
const SOL_MINT = "So11111111111111111111111111111111111111112";
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const atomicPattern = /^\d{1,80}$/u;
const cursorPattern = /^c(\d{1,4})$/u;
const capturedBountyPools = new Set(["bounties", "paid-out", "big"]);

const bountyStatuses = new Set([
  "DRAFT",
  "PUBLISHED",
  "PENDING_RESOLUTION",
  "IN_DISPUTE_PERIOD",
  "CLOSED",
] as const);

export const publicPhases = [
  "OPEN",
  "PENDING_RESOLUTION",
  "IN_DISPUTE_PERIOD",
  "CLOSED",
] as const;

export const goSortFields = [
  "createdAt",
  "rewardTotalUsd",
  "expiresAt",
  "submissionCount",
] as const;

export type BountyStatus =
  | "DRAFT"
  | "PUBLISHED"
  | "PENDING_RESOLUTION"
  | "IN_DISPUTE_PERIOD"
  | "CLOSED";
export type PublicPhase = (typeof publicPhases)[number];
export type GoSortField = (typeof goSortFields)[number];
export type GoSortOrder = "asc" | "desc";

type UnknownRecord = Record<string, unknown>;

export type ArchivedRewardLeg = {
  mintAddress: string;
  amountAtomic?: string;
  decimalsSnapshot?: number;
};

export type ArchivedBounty = {
  taskId: string;
  creatorAddress: string;
  title: string;
  bodyText: string;
  status: BountyStatus;
  phaseAtCapture: PublicPhase | "DRAFT" | "PUBLISHED";
  createdAt: string;
  expiresAt?: string;
  submissionCount: number;
  rewardLegs: ArchivedRewardLeg[];
  rewardTotalUsdAtCapture?: number;
};

export type GoSnapshot = {
  capturedAt: string;
  refreshedAt: string;
  sourceUrl: string;
  sha256: string;
  bounties: ArchivedBounty[];
};

export type GoQuery = {
  q: string;
  status: "ALL" | PublicPhase;
  sort: GoSortField;
  order: GoSortOrder;
  cursor?: string;
  task?: string;
};

export type GoPageResult = {
  source: "archived-go-html";
  capturedAt: string;
  refreshedAt: string;
  items: ArchivedBounty[];
  total: number;
  offset: number;
  nextCursor?: string;
  previousCursor?: string;
};

export class GoEvidenceError extends Error {
  override name = "GoEvidenceError";
}

export class GoQueryError extends Error {
  override name = "GoQueryError";
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(
  record: UnknownRecord,
  field: string,
  context: string,
  maximum: number,
  allowNewlines = false,
): string {
  const value = record[field];
  const controls = allowNewlines
    ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u
    : /[\u0000-\u001f\u007f]/u;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    controls.test(value)
  ) {
    throw new GoEvidenceError(`${context} ${field} is invalid`);
  }
  return value;
}

function optionalIsoDate(
  record: UnknownRecord,
  field: string,
  context: string,
): string | undefined {
  const value = record[field];
  if (value === undefined) return undefined;
  const parts =
    typeof value === "string"
      ? value.match(
          /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/,
        )
      : null;
  if (
    typeof value !== "string" ||
    value.length > 40 ||
    !parts ||
    !Number.isFinite(Date.parse(value)) ||
    Number(parts[4]) > 23 ||
    Number(parts[5]) > 59 ||
    Number(parts[6]) > 59 ||
    new Date(`${parts[1]}-${parts[2]}-${parts[3]}T00:00:00Z`)
      .toISOString()
      .slice(0, 10) !== value.slice(0, 10)
  ) {
    throw new GoEvidenceError(`${context} ${field} is invalid`);
  }
  return value;
}

function requireIsoDate(
  record: UnknownRecord,
  field: string,
  context: string,
): string {
  const value = optionalIsoDate(record, field, context);
  if (value === undefined) {
    throw new GoEvidenceError(`${context} ${field} is missing`);
  }
  return value;
}

function findJsonEnd(source: string, start: number): number {
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let index = start; index < source.length; index += 1) {
    const character = source[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === "[" || character === "{") depth += 1;
    else if (character === "]" || character === "}") {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  throw new GoEvidenceError("Captured GO data segment is not closed");
}

function extractRscPayload(source: string): string {
  const scripts = source.matchAll(
    /<script>self\.__next_f\.push\((\[.*?\])\)<\/script>/gsu,
  );
  const payloads: string[] = [];
  for (const match of scripts) {
    if (payloads.length >= 32) {
      throw new GoEvidenceError(
        "Captured GO page contains too many RSC chunks",
      );
    }
    let tuple: unknown;
    try {
      tuple = JSON.parse(match[1]);
    } catch {
      throw new GoEvidenceError("Captured GO RSC chunk is invalid JSON");
    }
    if (
      Array.isArray(tuple) &&
      tuple[0] === 1 &&
      typeof tuple[1] === "string"
    ) {
      payloads.push(tuple[1]);
    }
  }
  const payload = payloads.join("");
  if (payload.length === 0 || payload.length > MAX_RSC_BYTES) {
    throw new GoEvidenceError("Captured GO RSC payload size is invalid");
  }
  return payload;
}

function phaseAtCapture(
  status: BountyStatus,
  expiresAt: string | undefined,
  capturedAt: string,
): ArchivedBounty["phaseAtCapture"] {
  if (status !== "PENDING_RESOLUTION") return status;
  if (expiresAt === undefined) return "OPEN";
  return Date.parse(expiresAt) > Date.parse(capturedAt)
    ? "OPEN"
    : "PENDING_RESOLUTION";
}

export function validateArchivedBounty(
  input: unknown,
  capturedAt: string,
): ArchivedBounty {
  if (!isRecord(input)) {
    throw new GoEvidenceError("Archived bounty must be an object");
  }
  const context = "Archived bounty";
  const taskId = requireString(input, "taskId", context, 64);
  if (!uuidPattern.test(taskId)) {
    throw new GoEvidenceError(`${context} taskId is invalid`);
  }
  const creatorAddress = requireString(input, "creatorAddress", context, 64);
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/u.test(creatorAddress)) {
    throw new GoEvidenceError(`${context} creatorAddress is invalid`);
  }
  const statusValue = input.status;
  if (
    typeof statusValue !== "string" ||
    !bountyStatuses.has(statusValue as BountyStatus)
  ) {
    throw new GoEvidenceError(`${context} status is invalid`);
  }
  const status = statusValue as BountyStatus;
  const createdAt = requireIsoDate(input, "createdAt", context);
  const expiresAt = optionalIsoDate(input, "expiresAt", context);

  if (!isRecord(input.counts)) {
    throw new GoEvidenceError(`${context} counts are invalid`);
  }
  const submissionCount = input.counts.submissionCount;
  if (
    typeof submissionCount !== "number" ||
    !Number.isSafeInteger(submissionCount) ||
    submissionCount < 0 ||
    submissionCount > 10_000_000
  ) {
    throw new GoEvidenceError(`${context} submissionCount is invalid`);
  }

  if (!Array.isArray(input.rewardLegs) || input.rewardLegs.length > 10) {
    throw new GoEvidenceError(`${context} rewardLegs are invalid`);
  }
  const rewardLegs = input.rewardLegs.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new GoEvidenceError(`${context} reward leg ${index} is invalid`);
    }
    const mintAddress = requireString(
      entry,
      "mintAddress",
      `${context} reward leg ${index}`,
      64,
    );
    const amountAtomic = entry.amountAtomic;
    if (
      amountAtomic !== undefined &&
      (typeof amountAtomic !== "string" || !atomicPattern.test(amountAtomic))
    ) {
      throw new GoEvidenceError(
        `${context} reward leg ${index} amountAtomic is invalid`,
      );
    }
    const decimalsSnapshot = entry.decimalsSnapshot;
    if (
      decimalsSnapshot !== undefined &&
      (typeof decimalsSnapshot !== "number" ||
        !Number.isInteger(decimalsSnapshot) ||
        decimalsSnapshot < 0 ||
        decimalsSnapshot > 18)
    ) {
      throw new GoEvidenceError(
        `${context} reward leg ${index} decimalsSnapshot is invalid`,
      );
    }
    return { mintAddress, amountAtomic, decimalsSnapshot };
  });

  const rewardTotalUsd = input.rewardTotalUsd;
  if (
    rewardTotalUsd !== undefined &&
    (typeof rewardTotalUsd !== "number" ||
      !Number.isFinite(rewardTotalUsd) ||
      rewardTotalUsd < 0 ||
      rewardTotalUsd > 1_000_000_000_000)
  ) {
    throw new GoEvidenceError(`${context} rewardTotalUsd is invalid`);
  }

  return {
    taskId,
    creatorAddress,
    title: requireString(input, "title", context, 300),
    bodyText: requireString(input, "bodyMarkdown", context, 20_000, true),
    status,
    phaseAtCapture: phaseAtCapture(status, expiresAt, capturedAt),
    createdAt,
    expiresAt,
    submissionCount,
    rewardLegs,
    rewardTotalUsdAtCapture: rewardTotalUsd as number | undefined,
  };
}

export function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function parseGoCapture(
  bytes: Uint8Array,
  capturedAt: string,
  expectedSha256 = GO_CAPTURE_SHA256,
): Pick<GoSnapshot, "refreshedAt" | "bounties"> {
  if (bytes.byteLength > 1_100_000) {
    throw new GoEvidenceError("Captured GO page exceeds the size limit");
  }
  const actualSha256 = sha256(bytes);
  if (actualSha256 !== expectedSha256) {
    throw new GoEvidenceError(
      `Captured GO page SHA-256 mismatch: expected ${expectedSha256}, received ${actualSha256}`,
    );
  }

  let html: string;
  try {
    html = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new GoEvidenceError("Captured GO page is not valid UTF-8");
  }
  const rsc = extractRscPayload(html);
  const markerStart = rsc.indexOf(GO_RSC_MARKER);
  if (
    markerStart < 0 ||
    rsc.indexOf(GO_RSC_MARKER, markerStart + GO_RSC_MARKER.length) >= 0
  ) {
    throw new GoEvidenceError(
      "Captured GO initial discovery payload is missing or ambiguous",
    );
  }
  const jsonStart = markerStart + "123:".length;
  const jsonEnd = findJsonEnd(rsc, jsonStart);
  if (jsonEnd - jsonStart > MAX_JSON_SEGMENT_BYTES) {
    throw new GoEvidenceError(
      "Captured GO data segment exceeds the size limit",
    );
  }

  let flightValue: unknown;
  try {
    flightValue = JSON.parse(rsc.slice(jsonStart, jsonEnd));
  } catch {
    throw new GoEvidenceError("Captured GO data segment is invalid JSON");
  }
  if (
    !Array.isArray(flightValue) ||
    flightValue.length !== 4 ||
    !isRecord(flightValue[3]) ||
    !isRecord(flightValue[3].initialTrendingFeed)
  ) {
    throw new GoEvidenceError("Captured GO discovery payload shape is invalid");
  }
  const feed = flightValue[3].initialTrendingFeed;
  if (!Array.isArray(feed.items) || feed.items.length !== 50) {
    throw new GoEvidenceError("Captured GO discovery item count is invalid");
  }
  if (
    typeof feed.refreshedAt !== "string" ||
    !Number.isFinite(Date.parse(feed.refreshedAt))
  ) {
    throw new GoEvidenceError("Captured GO refreshedAt is invalid");
  }

  const bounties: ArchivedBounty[] = [];
  const taskIds = new Set<string>();
  for (const item of feed.items) {
    if (!isRecord(item) || item.type !== "bounty") continue;
    if (typeof item.pool !== "string" || !capturedBountyPools.has(item.pool)) {
      throw new GoEvidenceError("Captured GO bounty pool is invalid");
    }
    const bounty = validateArchivedBounty(item.bounty, capturedAt);
    if (taskIds.has(bounty.taskId)) {
      throw new GoEvidenceError("Captured GO bounty identity is duplicated");
    }
    taskIds.add(bounty.taskId);
    bounties.push(bounty);
  }
  if (bounties.length !== 25) {
    throw new GoEvidenceError("Captured GO bounty count is invalid");
  }
  return { refreshedAt: feed.refreshedAt, bounties };
}

export function verifyGoEvidence(
  bytes: Uint8Array,
  manifest: unknown,
): GoSnapshot {
  if (!isRecord(manifest) || !Array.isArray(manifest.records)) {
    throw new GoEvidenceError("Capture manifest records are missing");
  }
  const matches = manifest.records.filter(
    (entry): entry is UnknownRecord =>
      isRecord(entry) && entry.url === GO_CAPTURE_URL,
  );
  if (matches.length !== 1) {
    throw new GoEvidenceError("Capture manifest GO record is not unique");
  }
  const record = matches[0];
  if (
    record.final_url !== GO_CAPTURE_URL ||
    record.status !== 200 ||
    record.path !== GO_CAPTURE_PATH ||
    record.bytes !== GO_CAPTURE_BYTES ||
    record.sha256 !== GO_CAPTURE_SHA256
  ) {
    throw new GoEvidenceError("Capture manifest GO provenance does not match");
  }
  if (bytes.byteLength !== GO_CAPTURE_BYTES) {
    throw new GoEvidenceError("Captured GO page byte length does not match");
  }
  if (
    typeof manifest.captured_at !== "string" ||
    !Number.isFinite(Date.parse(manifest.captured_at))
  ) {
    throw new GoEvidenceError("Capture manifest timestamp is invalid");
  }
  const parsed = parseGoCapture(bytes, manifest.captured_at);
  return {
    capturedAt: manifest.captured_at,
    refreshedAt: parsed.refreshedAt,
    sourceUrl: GO_CAPTURE_URL,
    sha256: GO_CAPTURE_SHA256,
    bounties: parsed.bounties,
  };
}

function singleParameter(
  parameters: URLSearchParams,
  key: string,
): string | undefined {
  const values = parameters.getAll(key);
  if (values.length > 1) throw new GoQueryError(`${key} must be unique`);
  return values[0];
}

export function parseGoQuery(parameters: URLSearchParams): GoQuery {
  const allowed = new Set(["q", "status", "sort", "order", "cursor", "task"]);
  for (const key of parameters.keys()) {
    if (!allowed.has(key))
      throw new GoQueryError(`Unsupported query key: ${key}`);
  }
  const rawQ = singleParameter(parameters, "q") ?? "";
  if (rawQ.length > MAX_SEARCH_LENGTH) {
    throw new GoQueryError("q exceeds the captured 256-character limit");
  }
  const q = rawQ.trim();
  const rawStatus = singleParameter(parameters, "status") ?? "ALL";
  if (rawStatus !== "ALL" && !publicPhases.includes(rawStatus as PublicPhase)) {
    throw new GoQueryError("status is invalid");
  }
  const rawSort = singleParameter(parameters, "sort") ?? "createdAt";
  if (!goSortFields.includes(rawSort as GoSortField)) {
    throw new GoQueryError("sort is invalid");
  }
  const rawOrder = singleParameter(parameters, "order") ?? "desc";
  if (rawOrder !== "asc" && rawOrder !== "desc") {
    throw new GoQueryError("order is invalid");
  }
  const cursor = singleParameter(parameters, "cursor");
  if (cursor !== undefined) {
    const match = cursorPattern.exec(cursor);
    if (!match || Number.parseInt(match[1], 10) % GO_PAGE_SIZE !== 0) {
      throw new GoQueryError("cursor is invalid");
    }
  }
  const task = singleParameter(parameters, "task");
  if (task !== undefined && !uuidPattern.test(task)) {
    throw new GoQueryError("task is invalid");
  }
  return {
    q,
    status: rawStatus as GoQuery["status"],
    sort: rawSort as GoSortField,
    order: rawOrder,
    cursor,
    task,
  };
}

export function normalizeGoQuery(parameters: URLSearchParams): {
  query: GoQuery;
  ignoredInvalidState: boolean;
} {
  try {
    return { query: parseGoQuery(parameters), ignoredInvalidState: false };
  } catch {
    const safe = new URLSearchParams();
    const q = parameters.get("q");
    if (q !== null) {
      // Keep the existing UTF-16 bound without retaining half of a character.
      const bounded = q.slice(0, MAX_SEARCH_LENGTH);
      safe.set("q", bounded.replace(/[\uD800-\uDBFF]$/u, ""));
    }
    const status = parameters.get("status");
    if (
      status !== null &&
      (status === "ALL" || publicPhases.includes(status as PublicPhase))
    )
      safe.set("status", status);
    const sort = parameters.get("sort");
    if (goSortFields.includes(sort as GoSortField)) safe.set("sort", sort!);
    const order = parameters.get("order");
    if (order === "asc" || order === "desc") safe.set("order", order);
    const cursor = parameters.get("cursor");
    if (cursor !== null) {
      const match = cursorPattern.exec(cursor);
      if (match && Number.parseInt(match[1], 10) % GO_PAGE_SIZE === 0)
        safe.set("cursor", cursor);
    }
    const task = parameters.get("task");
    if (task !== null && uuidPattern.test(task)) safe.set("task", task);
    return { query: parseGoQuery(safe), ignoredInvalidState: true };
  }
}

function compareOptionalNumbers(
  left: number | undefined,
  right: number | undefined,
  direction: number,
): number {
  if (left === undefined) return right === undefined ? 0 : 1;
  if (right === undefined) return -1;
  return (left - right) * direction;
}

function compareOptionalDates(
  left: string | undefined,
  right: string | undefined,
  direction: number,
): number {
  if (left === undefined) return right === undefined ? 0 : 1;
  if (right === undefined) return -1;
  return (Date.parse(left) - Date.parse(right)) * direction;
}

export function queryArchivedBounties(
  snapshot: GoSnapshot,
  query: GoQuery,
): GoPageResult {
  const search = query.q.toLocaleLowerCase("en-US");
  const filtered = snapshot.bounties.filter((bounty) => {
    if (query.status !== "ALL" && bounty.phaseAtCapture !== query.status)
      return false;
    if (search.length === 0) return true;
    return [bounty.title, bounty.bodyText, bounty.creatorAddress, bounty.taskId]
      .join("\n")
      .toLocaleLowerCase("en-US")
      .includes(search);
  });
  const direction = query.order === "asc" ? 1 : -1;
  const sorted = [...filtered].sort((left, right) => {
    let result = 0;
    if (query.sort === "createdAt")
      result =
        (Date.parse(left.createdAt) - Date.parse(right.createdAt)) * direction;
    else if (query.sort === "rewardTotalUsd")
      result = compareOptionalNumbers(
        left.rewardTotalUsdAtCapture,
        right.rewardTotalUsdAtCapture,
        direction,
      );
    else if (query.sort === "expiresAt")
      result = compareOptionalDates(left.expiresAt, right.expiresAt, direction);
    else result = (left.submissionCount - right.submissionCount) * direction;
    return result === 0
      ? left.taskId.localeCompare(right.taskId, "en-US")
      : result;
  });

  const rawOffset = query.cursor
    ? Number.parseInt(query.cursor.slice(1), 10)
    : 0;
  const offset =
    Number.isSafeInteger(rawOffset) &&
    rawOffset >= 0 &&
    rawOffset % GO_PAGE_SIZE === 0 &&
    rawOffset < Math.max(sorted.length, 1)
      ? rawOffset
      : 0;
  const nextOffset = offset + GO_PAGE_SIZE;
  const previousOffset = Math.max(0, offset - GO_PAGE_SIZE);

  return {
    source: "archived-go-html",
    capturedAt: snapshot.capturedAt,
    refreshedAt: snapshot.refreshedAt,
    items: sorted.slice(offset, nextOffset),
    total: sorted.length,
    offset,
    nextCursor: nextOffset < sorted.length ? `c${nextOffset}` : undefined,
    previousCursor: offset > 0 ? `c${previousOffset}` : undefined,
  };
}

export function formatAtomicAmount(
  amountAtomic: string | undefined,
  decimalsSnapshot: number | undefined,
): string | undefined {
  if (
    typeof amountAtomic !== "string" ||
    decimalsSnapshot === undefined ||
    !atomicPattern.test(amountAtomic) ||
    !Number.isInteger(decimalsSnapshot) ||
    decimalsSnapshot < 0 ||
    decimalsSnapshot > 18
  ) {
    return undefined;
  }
  const atomic = BigInt(amountAtomic);
  if (decimalsSnapshot === 0) return atomic.toString();
  const divisor = 10n ** BigInt(decimalsSnapshot);
  const whole = atomic / divisor;
  const fraction = (atomic % divisor)
    .toString()
    .padStart(decimalsSnapshot, "0")
    .replace(/0+$/u, "");
  return fraction.length > 0 ? `${whole}.${fraction}` : whole.toString();
}

export function rewardMintLabel(mintAddress: string): string {
  if (mintAddress === SOL_MINT) return "SOL";
  return `${mintAddress.slice(0, 4)}…${mintAddress.slice(-4)}`;
}
