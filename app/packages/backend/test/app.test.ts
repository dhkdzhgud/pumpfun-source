import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildApp, type Fixture } from "../src/app.js";

const fixture = (overrides: Partial<Fixture> = {}): Fixture => ({
  method: "GET",
  path: "/coins",
  query: { limit: "1", offset: "0" },
  status: 200,
  body: { fixture: true },
  source: "synthetic:test",
  ...overrides,
});

const malformedFixture = (overrides: Record<string, unknown>) =>
  ({ ...fixture(), ...overrides }) as Fixture;

const reservedFixturePaths = [
  "/health",
  "/__reconstruction/status",
  "/__reconstruction/openapi.json",
];

test("GET and HEAD fixtures cannot shadow reserved internal routes", () => {
  for (const path of reservedFixturePaths) {
    for (const method of ["GET", "HEAD"]) {
      const source = `https://user:password@example.test/${method}?token=secret`;
      const sourceDigest = createHash("sha256")
        .update(source)
        .digest("hex")
        .slice(0, 12);
      const pathDigest = createHash("sha256")
        .update(path)
        .digest("hex")
        .slice(0, 12);
      assert.throws(
        () => buildApp([fixture({ method, path, query: undefined, source })]),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /Reserved fixture route/);
          assert.match(error.message, new RegExp(pathDigest));
          assert.match(error.message, new RegExp(sourceDigest));
          assert.doesNotMatch(
            error.message,
            /password|token=|user:|example\.test/,
          );
          return true;
        },
      );
    }
  }
});

test("reserved routes reject mixed-case methods and every query variant", () => {
  for (const path of reservedFixturePaths) {
    for (const [method, query] of [
      ["gEt", { first: "1", second: "2" }],
      ["hEaD", { second: "2", first: "1" }],
    ] as const) {
      assert.throws(
        () =>
          buildApp([
            fixture({
              method,
              path,
              query,
              source: `synthetic:${path}:${method}`,
            }),
          ]),
        /Reserved fixture route/,
      );
    }
  }
});

test("nearby nonreserved paths remain replayable and countable", async () => {
  const fixtures = [
    fixture({
      path: "/health-check",
      query: undefined,
      body: { fixture: "health-neighbor" },
      source: "synthetic:health-neighbor",
    }),
    fixture({
      path: "/__reconstruction/status-extra",
      query: { view: "fixture" },
      body: { fixture: "status-neighbor" },
      source: "synthetic:status-neighbor",
    }),
    fixture({
      path: "/__reconstruction/openapi.json-copy",
      query: undefined,
      body: { fixture: "openapi-neighbor" },
      source: "synthetic:openapi-neighbor",
    }),
  ];
  const app = buildApp(fixtures);
  try {
    assert.deepEqual((await app.inject("/health-check")).json(), {
      fixture: "health-neighbor",
    });
    assert.deepEqual(
      (await app.inject("/__reconstruction/status-extra?view=fixture")).json(),
      { fixture: "status-neighbor" },
    );
    assert.deepEqual(
      (await app.inject("/__reconstruction/openapi.json-copy")).json(),
      { fixture: "openapi-neighbor" },
    );
    assert.equal(
      (await app.inject("/__reconstruction/status")).json().fixtureCount,
      fixtures.length,
    );
  } finally {
    await app.close();
  }
});

test("built-in routes retain GET, automatic HEAD, query, and HTTP behavior", async () => {
  const ordinary = fixture({
    path: "/ordinary",
    query: undefined,
    status: 209,
    body: { fixture: "ordinary" },
  });
  const app = buildApp([ordinary]);
  try {
    const health = await app.inject("/health?ignored=1");
    assert.equal(health.statusCode, 200);
    assert.deepEqual(health.json(), {
      status: "ok",
      mode: "reconstruction",
      compatibility: "unqualified",
    });

    const status = await app.inject("/__reconstruction/status?ignored=1");
    assert.equal(status.statusCode, 200);
    assert.equal(status.json().fixtureCount, 1);
    assert.equal(status.json().compatibility, "unqualified");
    assert.match(status.json().specificationSha256, /^[0-9a-f]{64}$/);

    const specification = readFileSync(
      new URL("../../../contracts/developer.openapi.json", import.meta.url),
      "utf8",
    );
    const openapi = await app.inject(
      "/__reconstruction/openapi.json?ignored=1",
    );
    assert.equal(openapi.statusCode, 200);
    assert.match(openapi.headers["content-type"] ?? "", /^application\/json/);
    assert.equal(openapi.body, specification);

    for (const path of reservedFixturePaths) {
      const response = await app.inject({ method: "HEAD", url: path });
      assert.equal(response.statusCode, 200, path);
      assert.equal(response.body, "", path);
    }

    const origin = await app.listen({ host: "127.0.0.1", port: 0 });
    const overHttp = (method: "GET" | "HEAD", path: string) =>
      new Promise<{ status: number | undefined; body: string }>(
        (resolve, reject) => {
          const outgoing = request(origin, { method, path }, (response) => {
            const chunks: Buffer[] = [];
            response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
            response.on("end", () =>
              resolve({
                status: response.statusCode,
                body: Buffer.concat(chunks).toString("utf8"),
              }),
            );
          });
          outgoing.on("error", reject);
          outgoing.end();
        },
      );
    const liveHealth = await overHttp("GET", "/health?ignored=1");
    assert.equal(liveHealth.status, 200);
    assert.equal(JSON.parse(liveHealth.body).compatibility, "unqualified");
    const liveHead = await overHttp("HEAD", "/health");
    assert.deepEqual(liveHead, { status: 200, body: "" });
    const liveFixture = await overHttp("GET", "/ordinary");
    assert.equal(liveFixture.status, 209);
    assert.deepEqual(JSON.parse(liveFixture.body), { fixture: "ordinary" });
  } finally {
    await app.close();
  }
});

test("fixture bodies must be explicitly present; null remains valid", async () => {
  const missing = { ...fixture() } as Partial<Fixture>;
  delete missing.body;
  for (const invalid of [missing, fixture({ body: undefined })]) {
    assert.throws(
      () => buildApp([invalid as Fixture]),
      /body must be explicitly present/,
    );
  }
  const app = buildApp([fixture({ body: null })]);
  try {
    assert.equal(
      (await app.inject("/__reconstruction/status")).json().fixtureCount,
      1,
    );
  } finally {
    await app.close();
  }
});

test("fixtures for statuses that cannot carry a body must use null", async () => {
  for (const status of [204, 304]) {
    assert.throws(
      () => buildApp([fixture({ status, body: { recorded: true } })]),
      new RegExp(`status ${status} responses cannot carry a body`),
    );
    assert.throws(
      () => buildApp([fixture({ status, body: "recorded" })]),
      new RegExp(`status ${status} responses cannot carry a body`),
    );
  }
  const app = buildApp([fixture({ status: 204, body: null })]);
  try {
    const response = await app.inject("/coins?limit=1&offset=0");
    assert.equal(response.statusCode, 204);
    assert.equal(response.body, "");
  } finally {
    await app.close();
  }
});

test("JSON scalar fixtures retain their JSON representation", async () => {
  const cases = [
    {
      path: "/string",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: "recorded string",
    },
    {
      path: "/null",
      headers: { "Content-Type": "application/json" },
      body: null,
    },
    {
      path: "/vendor",
      headers: { "Content-Type": "application/problem+json" },
      body: "vendor string",
    },
    {
      path: "/plain",
      headers: { "Content-Type": "text/plain" },
      body: "plain string",
    },
  ];
  const app = buildApp(
    cases.map((entry) => ({
      ...entry,
      method: "GET",
      status: 200,
      source: "synthetic:scalar",
    })),
  );
  try {
    for (const entry of cases) {
      const response = await app.inject(entry.path);
      assert.equal(response.statusCode, 200);
      assert.equal(
        response.body,
        entry.path === "/plain" ? entry.body : JSON.stringify(entry.body),
      );
      assert.ok(
        (response.headers["content-type"] ?? "").startsWith(
          entry.headers["Content-Type"],
        ),
      );
    }
  } finally {
    await app.close();
  }
});

test("valid lowercase and mixed-case response headers retain their values", async () => {
  const app = buildApp([
    fixture({
      path: "/headers",
      query: undefined,
      headers: {
        "x-lowercase": "lowercase value",
        "X-Mixed-Case": "Mixed Value",
        "Content-Type": "application/json",
      },
      body: { ok: true },
    }),
  ]);
  try {
    const response = await app.inject("/headers");
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers["x-lowercase"], "lowercase value");
    assert.equal(response.headers["x-mixed-case"], "Mixed Value");
    assert.match(response.headers["content-type"] ?? "", /^application\/json/);
    assert.deepEqual(response.json(), { ok: true });
  } finally {
    await app.close();
  }
});

test("invalid response header names are rejected during registration", () => {
  for (const name of ["", "bad header", "bad\nheader", "bad:header"]) {
    assert.throws(
      () => buildApp([fixture({ headers: { [name]: "value" } })]),
      /headers contain an invalid HTTP field name/,
    );
  }
});

test("CRLF and invalid control characters in header values are rejected", () => {
  for (const value of ["first\r\nsecond", "null\0byte", "control\u0001byte"]) {
    assert.throws(
      () => buildApp([fixture({ headers: { "x-recorded-value": value } })]),
      /headers contain an invalid HTTP field value/,
    );
  }
});

test("non-string, null, array, and object header values are rejected", () => {
  for (const value of [1, null, ["first", "second"], { nested: "value" }]) {
    assert.throws(
      () =>
        buildApp([
          malformedFixture({ headers: { "x-recorded-value": value } }),
        ]),
      /header values must be strings/,
    );
  }
});

test("header collections must be plain objects", () => {
  for (const headers of [null, [], "x-recorded-value: value", 1]) {
    assert.throws(
      () => buildApp([malformedFixture({ headers })]),
      /headers must be a plain object/,
    );
  }
});

test("validation fails before startup without exposing fixture sources", () => {
  const source = "https://user:password@example.test/capture?token=secret";
  const sourceDigest = createHash("sha256")
    .update(source)
    .digest("hex")
    .slice(0, 12);
  assert.throws(
    () =>
      buildApp([
        fixture({
          source,
          headers: { "x-recorded-value": "first\r\nsecond" },
        }),
      ]),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /Invalid fixture registration/);
      assert.match(error.message, new RegExp(sourceDigest));
      assert.doesNotMatch(error.message, /password|token=|user:|example\.test/);
      return true;
    },
  );
});

const wellFormedKey = `pf_live_${"A".repeat(49)}`;

test("native /v1 operations sit behind the API-key gate", async () => {
  const app = buildApp();
  try {
    for (const url of ["/v1/users", "/v1/posts", "/v1/competitions"]) {
      const missing = await app.inject(url);
      assert.equal(missing.statusCode, 401, url);
      assert.equal(missing.json().error, "API_KEY_REQUIRED", url);
      const invalid = await app.inject({
        url,
        headers: { authorization: "Bearer pf_live_short" },
      });
      assert.equal(invalid.statusCode, 401, url);
      assert.equal(invalid.json().error, "API_KEY_INVALID", url);
      const accepted = await app.inject({
        url,
        headers: { authorization: `Bearer ${wellFormedKey}` },
      });
      assert.notEqual(accepted.statusCode, 401, url);
    }
  } finally {
    await app.close();
  }
});

test("unimplemented domain routes cannot pass as working APIs", async () => {
  const app = buildApp();
  try {
    // /v1/users and /v1/pnl-leaderboard are native now; use a documented
    // operation that still has no native handler.
    const response = await app.inject({
      url: "/v1/payouts/leaderboard",
      headers: { authorization: `Bearer ${wellFormedKey}` },
    });
    assert.equal(response.statusCode, 501);
    assert.deepEqual(response.json(), {
      statusCode: 501,
      error: "COMPATIBILITY_NOT_IMPLEMENTED",
      method: "GET",
      path: "/v1/payouts/leaderboard",
    });
  } finally {
    await app.close();
  }
});

test("documented routes reject requests without an API key", async () => {
  const app = buildApp();
  try {
    for (const url of ["/v1/users/test", "/v1/users/test?limit=1"]) {
      const response = await app.inject(url);
      assert.equal(response.statusCode, 401);
      const body = response.json();
      assert.equal(body.statusCode, 401);
      assert.equal(body.error, "API_KEY_REQUIRED");
      assert.equal(
        body.message,
        "Send Authorization: Bearer <key> or x-api-key: <key>",
      );
      assert.equal(body.path, "/users/test");
      assert.ok(Number.isFinite(Date.parse(body.timestamp)));
    }
    const head = await app.inject({ method: "HEAD", url: "/v1/users/test" });
    assert.equal(head.statusCode, 401);
  } finally {
    await app.close();
  }
});

test("documented routes reject malformed API keys", async () => {
  const app = buildApp();
  try {
    const malformed = [
      { authorization: "Bearer pf_live_short" },
      { authorization: `Bearer pk_live_${"A".repeat(49)}` },
      { authorization: `Bearer pf_live_${"A".repeat(48)}-` },
      { "x-api-key": "not-a-key" },
    ];
    for (const headers of malformed) {
      const response = await app.inject({ url: "/v1/users/test", headers });
      assert.equal(response.statusCode, 401);
      const body = response.json();
      assert.equal(body.error, "API_KEY_INVALID");
      assert.equal(
        body.message,
        "The key is malformed (wrong prefix, length or checksum) or unknown.",
      );
      assert.equal(body.path, "/users/test");
    }
  } finally {
    await app.close();
  }
});

test("a key in the query string does not satisfy the gate", async () => {
  const app = buildApp();
  try {
    const response = await app.inject(
      `/v1/users/test?api_key=${wellFormedKey}`,
    );
    assert.equal(response.statusCode, 401);
    assert.equal(response.json().error, "API_KEY_REQUIRED");
  } finally {
    await app.close();
  }
});

test("a well-formed key in either header reaches fixture replay", async () => {
  const app = buildApp([
    fixture({ path: "/v1/payouts/leaderboard", query: undefined, body: { id: "test" } }),
  ]);
  try {
    for (const headers of [
      { authorization: `Bearer ${wellFormedKey}` },
      { "x-api-key": wellFormedKey },
    ]) {
      const response = await app.inject({ url: "/v1/payouts/leaderboard", headers });
      assert.equal(response.statusCode, 200);
      assert.deepEqual(response.json(), { id: "test" });
    }
    const rejected = await app.inject("/v1/payouts/leaderboard");
    assert.equal(rejected.statusCode, 401);
  } finally {
    await app.close();
  }
});

test("fixture replay matches method, raw path, normalized query, status, and headers", async () => {
  const app = buildApp([
    fixture({
      status: 206,
      headers: { "x-fixture": "recorded" },
      body: [{ mint: "fixture-only" }],
    }),
  ]);
  try {
    const response = await app.inject("/coins?offset=0&limit=1");
    assert.equal(response.statusCode, 206);
    assert.equal(response.headers["x-fixture"], "recorded");
    assert.deepEqual(response.json(), [{ mint: "fixture-only" }]);
  } finally {
    await app.close();
  }
});

test("valid distinct query combinations remain independently replayable", async () => {
  const app = buildApp([
    fixture({
      query: { limit: "1" },
      body: { snapshot: "first" },
      source: "first",
    }),
    fixture({
      query: { limit: "2" },
      body: { snapshot: "second" },
      source: "second",
    }),
  ]);
  try {
    assert.deepEqual((await app.inject("/coins?limit=1")).json(), {
      snapshot: "first",
    });
    assert.deepEqual((await app.inject("/coins?limit=2")).json(), {
      snapshot: "second",
    });
    assert.equal(
      (await app.inject("/__reconstruction/status")).json().fixtureCount,
      2,
    );
  } finally {
    await app.close();
  }
});

test("query values and non-ASCII names round-trip through canonical encoding", async () => {
  const app = buildApp([
    fixture({
      path: "/search",
      query: { search: "a b=c&d" },
      body: { matched: "symbols" },
    }),
    fixture({
      path: "/unicode",
      query: { é: "值" },
      body: { matched: "unicode" },
      source: "synthetic:unicode",
    }),
  ]);
  try {
    assert.deepEqual((await app.inject("/search?search=a+b%3Dc%26d")).json(), {
      matched: "symbols",
    });
    assert.deepEqual((await app.inject("/unicode?%C3%A9=%E5%80%BC")).json(), {
      matched: "unicode",
    });
  } finally {
    await app.close();
  }
});

test("canonically duplicate fixture keys remain rejected", () => {
  const first = fixture({ source: "first" });
  const second = fixture({
    method: "get",
    query: { offset: "0", limit: "1" },
    body: { snapshot: "second" },
    source: "second",
  });
  assert.throws(
    () => buildApp([first, second]),
    /Duplicate canonical fixture key/,
  );
});

test("missing, invalid, and unsupported methods are rejected", () => {
  for (const method of [undefined, null, "", 1]) {
    assert.throws(
      () => buildApp([malformedFixture({ method })]),
      /method must be a non-empty string/,
    );
  }
  for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
    assert.throws(
      () => buildApp([malformedFixture({ method })]),
      /only GET and HEAD are supported/,
    );
  }
});

test("fixture paths must be local and keep query and fragment fields separate", () => {
  for (const path of [
    undefined,
    null,
    "",
    "coins",
    "//example.test/coins",
    "https://example.test/coins",
    "/coins?limit=1",
    "/coins#results",
  ]) {
    assert.throws(
      () => buildApp([malformedFixture({ path })]),
      /path must be a local absolute path without a query or fragment/,
    );
  }
});

test("malformed query objects and non-string values are rejected", () => {
  for (const query of [null, [], "limit=1", 1, new Map([["limit", "1"]])]) {
    assert.throws(
      () => buildApp([malformedFixture({ query })]),
      /query must be a plain object/,
    );
  }
  for (const query of [{ limit: 1 }, { limit: null }, { limit: ["1"] }]) {
    assert.throws(
      () => buildApp([malformedFixture({ query })]),
      /query values must be strings/,
    );
  }
});

test("malformed HTTP status codes are rejected", () => {
  for (const status of [undefined, null, "200", Number.NaN, 99, 600, 200.5]) {
    assert.throws(
      () => buildApp([malformedFixture({ status })]),
      /status must be an integer from 200 through 599/,
    );
  }
});

test("repeated incoming query keys retain their explicit 501 response", async () => {
  const app = buildApp([fixture()]);
  try {
    const response = await app.inject("/coins?limit=1&limit=2&offset=0");
    assert.equal(response.statusCode, 501);
    assert.deepEqual(response.json(), {
      statusCode: 501,
      error: "DUPLICATE_QUERY_KEYS_UNIMPLEMENTED",
    });
  } finally {
    await app.close();
  }
});

test("unsupported incoming methods cannot match a read-only fixture", async () => {
  const app = buildApp([fixture()]);
  try {
    const response = await app.inject({
      method: "POST",
      url: "/coins?limit=1&offset=0",
    });
    assert.equal(response.statusCode, 501);
    assert.deepEqual(response.json(), {
      statusCode: 501,
      error: "COMPATIBILITY_NOT_IMPLEMENTED",
      method: "POST",
      path: "/coins",
    });
  } finally {
    await app.close();
  }
});

test("unknown and near-match requests cannot select another fixture", async () => {
  const app = buildApp([fixture()]);
  try {
    for (const url of [
      "/coin?limit=1&offset=0",
      "/coins/?limit=1&offset=0",
      "/coins?limit=1",
      "/coins?limit=1&offset=0&extra=1",
    ]) {
      const response = await app.inject(url);
      assert.equal(response.statusCode, 501, url);
      assert.equal(response.json().error, "COMPATIBILITY_NOT_IMPLEMENTED", url);
    }
  } finally {
    await app.close();
  }
});

test("fixture paths retain dot segments from the request target", async () => {
  const app = buildApp([
    fixture({ path: "/coins", query: undefined, body: { ok: true } }),
  ]);
  try {
    assert.equal((await app.inject("/coins")).statusCode, 200);
    const origin = await app.listen({ host: "127.0.0.1", port: 0 });
    for (const path of ["/missing/../coins", "/missing/%2e%2e/coins"]) {
      const status = await new Promise<number | undefined>(
        (resolve, reject) => {
          const outgoing = request(origin, { path }, (response) => {
            response.resume();
            resolve(response.statusCode);
          });
          outgoing.on("error", reject);
          outgoing.end();
        },
      );
      assert.equal(status, 501, path);
    }
  } finally {
    await app.close();
  }
});

test("the committed public SOL-price fixture remains replayable", async () => {
  const fixtures = JSON.parse(
    readFileSync(
      new URL("../../../contracts/public-fixtures.json", import.meta.url),
      "utf8",
    ),
  ) as Fixture[];
  const app = buildApp(fixtures);
  try {
    const response = await app.inject("/services/frontend/sol-price");
    assert.equal(response.statusCode, 200);
    assert.match(response.headers["content-type"] ?? "", /^application\/json/);
    assert.deepEqual(response.json(), {
      solPrice: 102.94,
      asOfTimestamp: 1793184487312,
      stale: false,
    });
    assert.equal(
      (await app.inject("/__reconstruction/status")).json().fixtureCount,
      1,
    );
  } finally {
    await app.close();
  }
});
