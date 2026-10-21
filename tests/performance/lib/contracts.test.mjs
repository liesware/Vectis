// Built-in Node modules only. k6 adapters are stubbed; no HTTP/crypto is executed.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import test from "node:test";

async function harness(save = true) {
  const catalog = await readFile(new URL("../catalog.json", import.meta.url), "utf8");
  const samples = new Map();
  class Metric {
    constructor(name) { this.name = name; samples.set(name, []); }
    add(value, tags) { samples.get(this.name).push({ value, tags }); }
  }
  let response = { status: 200, body: '{"ok":true}', timings: { duration: 10 }, headers: { "X-Request-Id": "id" } };
  const calls = [];
  const context = vm.createContext({ __ENV: { VECTIS_API_URL: "http://loopback", VECTIS_APIKEY: "secret",
    ...(save ? { K6_RESULTS_DIR: "/results" } : {}) },
    __VU: 1, __ITER: 0, Date, console, open: () => catalog,
    adapters: { Metric, http: { post(url, body, options) { calls.push({ url, body, options }); return response; } } } });
  const sources = {
    "k6": "export function check(v, checks) {return Object.values(checks).every(f=>f(v));} export function fail(m){throw new Error(m);}",
    "k6/metrics": "export const Counter=adapters.Metric; export const Trend=adapters.Metric;",
    "k6/http": "export default adapters.http;",
    "k6/crypto": "export default {sha256(){return 'a'.repeat(64);}};",
  };
  const modules = new Map();
  async function load(specifier, parent = import.meta.url) {
    const key = specifier.startsWith("k6") ? specifier : new URL(specifier, parent).href;
    if (modules.has(key)) return modules.get(key);
    const source = sources[key] ?? await readFile(fileURLToPath(key), "utf8");
    const module = new vm.SourceTextModule(source, { context, identifier: key });
    modules.set(key, module);
    await module.link((child) => load(child, key));
    return module;
  }
  const transport = await load("./transport.js");
  await transport.evaluate();
  const flows = await load("./flows.js");
  await flows.evaluate();
  const registry = await load("./registry.js");
  const selected = registry.namespace.selectCases("fpe-batch", true, true, 3);
  const measurements = new transport.namespace.Measurements(selected, "hybrid-standard-v1",
    { url: "http://loopback", apikey: "secret" });
  const reporting = await load("./reporting.js");
  await reporting.evaluate();
  const fixtures = await load("./fixtures.js");
  await fixtures.evaluate();
  return { samples, calls, measurements, selected: selected[0], flows: flows.namespace,
    registry: registry.namespace, fixtures: fixtures.namespace,
    summary(data) { return reporting.namespace.renderSummary(measurements.rows, measurements.profile, data); },
    Measurements: transport.namespace.Measurements, reporting: reporting.namespace,
    selectCases: registry.namespace.selectCases,
    respond(value) { response = { ...response, ...value }; } };
}

test("successful values count validated batch items; labels never expose fixture IDs", async () => {
  const h = await harness();
  h.measurements.post(h.selected, "fpe_encrypt_batch", "/fpe/encrypt/private-kid/subject/private-subject", {}, () => {});
  const prefix = "vectis_fpe_batch_stored_auth_fpe_encrypt_batch";
  assert.equal(h.samples.get(prefix + "_values")[0].value, 3);
  const tags = JSON.stringify(h.calls[0].options.tags);
  for (const secret of ["private-kid", "private-subject", "secret"]) assert.ok(!tags.includes(secret));
  const data = { state: {}, metrics: {
    [prefix + "_requests"]: { values: { count: 1, rate: 2 } },
    [prefix + "_values"]: { values: { count: 3, rate: 6 } },
    [prefix + "_duration"]: { values: { avg: 10, "p(95)": 10, "p(99)": 10 } },
  }, setup_data: { secret: "must not persist" } };
  const summary = h.summary(data);
  assert.match(summary["/results/summary.tsv"], /\t2\.000\t6\.000\t/);
  assert.ok(!summary["/results/summary.json"].includes("must not persist"));
  assert.ok(!summary.stdout.includes("\t"));
  assert.equal(summary.stdout.split("Vectis operation summary").length - 1, 1);
});

test("without result destination summary produces terminal output only", async () => {
  const h = await harness(false);
  const summary = h.summary({ metrics: {}, state: {} });
  assert.deepEqual(Object.keys(summary), ["stdout"]);
  assert.match(summary.stdout, /Vectis operation summary/);
  assert.match(summary.stdout, /campaign rates, not per-operation throughput/);
});

test("429 and transport errors have zero useful values, without hiding failed requests", async () => {
  for (const status of [429, 0]) {
    const h = await harness();
    h.respond({ status });
    assert.throws(() => h.measurements.post(h.selected, "fpe_encrypt_batch", "/test", {}, () => {}),
      status === 429 ? /expected HTTP 200, got HTTP 429 \(server rejected load/ :
        /expected HTTP 200, got transport failure \(no HTTP response\)/);
    const prefix = "vectis_fpe_batch_stored_auth_fpe_encrypt_batch";
    assert.equal(h.samples.get(prefix + "_values")[0].value, 0);
    assert.equal(h.samples.get(prefix + "_requests")[0].value, 1);
    assert.equal(h.samples.get(prefix + (status ? "_429" : "_transport_errors"))[0].value, 1);
  }
});

test("contract failures count separately; batch shape/order cannot pass vacuously", async () => {
  const h = await harness();
  assert.throws(() => h.measurements.post(h.selected, "fpe_encrypt_batch", "/test", {}, () => { throw new Error("contract"); }));
  assert.equal(h.samples.get("vectis_fpe_batch_stored_auth_fpe_encrypt_batch_contract_errors")[0].value, 1);
  const items = [{ ref: "a" }, { ref: "b" }, { ref: "c" }];
  assert.throws(() => h.flows.batchOutput({ items: [] }, items));
  assert.throws(() => h.flows.batchOutput({ items: items.toReversed() }, items));
  assert.equal(h.flows.batchOutput({ items }, items).length, 3);
});

test("single FPE/random-token decode accepts their actual ref/plaintext-only API shape", async () => {
  const h = await harness();
  const suite = { kid: "kid", profiles: { fpe: { "none-legacy": "arbitrary-fpe" }, token: { none: "arbitrary-token" } } };
  for (const family of ["fpe", "token"]) {
    const selected = h.selectCases(family)[0];
    let plaintext;
    h.flows.runFlow(selected, suite, {
      flow(_, callback) { callback(); },
      post(_, operation, path, body, validate) {
        let response;
        if (operation.endsWith("encrypt") || operation.endsWith("encode")) {
          plaintext = body.plaintext;
          response = { kid: suite.kid, profile: body.profile, ref: body.ref,
            [family === "fpe" ? "ciphertext" : "token"]: "synthetic" };
        } else {
          response = { ref: body.ref, plaintext };
        }
        validate(response);
        return response;
      },
    });
  }
});

test("single MAC verify has ref/valid only; a failed flow is counted regardless of check ratio", async () => {
  const h = await harness();
  const selected = h.selectCases("mac")[0];
  h.flows.runFlow(selected, { kid: "kid", profiles: { mac: "arbitrary-mac" } }, {
    flow(_, callback) { callback(); },
    post(_, operation, path, body, validate) {
      const response = operation.endsWith("create") ?
        { kid: "kid", profile: body.profile, ref: body.ref, digest: "synthetic" } :
        { ref: body.ref, valid: true };
      validate(response);
      return response;
    },
  });
  assert.throws(() => h.measurements.flow(h.selected, () => { throw new Error("contract failed"); }));
  assert.equal(h.samples.get("vectis_flow_failures")[0].value, 1);
});

test("one failed flow does not skip the remaining selected cases", async () => {
  const h = await harness();
  const cases = h.selectCases("all").slice(0, 3);
  const visited = [];
  h.flows.runCases(cases, {}, {
    flow(test) {
      visited.push(test.id);
      if (visited.length === 1) throw new Error("contract failed");
    },
  });
  assert.deepEqual(visited, Array.from(cases, (c) => c.id));
});

test("catalog preserves pre-refactor variants, metric identifiers and report columns", async () => {
  const h = await harness();
  const baseline = JSON.parse(await readFile(new URL("./regression.json", import.meta.url)));
  const cases = h.selectCases("all");
  const normalized = (value) => JSON.parse(JSON.stringify(value));
  assert.deepEqual(normalized(h.registry.PROFILES), baseline.profiles);
  assert.deepEqual(normalized(h.registry.TARGETS), baseline.targets);
  assert.deepEqual(normalized(cases), baseline.cases);
  const measured = new h.Measurements(cases, h.measurements.profile, {});
  assert.deepEqual(normalized(measured.rows.map((row) => row.prefix)), baseline.metrics);
  const metrics = Object.fromEntries(measured.rows.map(({prefix}) =>
    [prefix + "_requests", { values: { count: 1 } }]));
  const summary = h.reporting.renderSummary(measured.rows, measured.profile, { metrics, state: {} });
  assert.deepEqual(summary["/results/summary.tsv"].split("\n")[0].split("\t"), baseline.tsv_columns);
  assert.deepEqual(Object.keys(JSON.parse(summary["/results/summary.json"])), baseline.summary_fields);
});

test("catalog rejects inconsistent definitions and missing or extra runners", async () => {
  const h = await harness();
  for (const mutate of [
    (c) => { c.version = 2; },
    (c) => { c.profiles[1].slug = c.profiles[0].slug; },
    (c) => { c.targets[0].operations = ["flow"]; },
    (c) => { c.targets[1].subject = false; },
    (c) => { c.targets[0].batch = "true"; },
    (c) => { c.targets[0].name = "unknown"; },
  ]) {
    const value = JSON.parse(JSON.stringify(h.registry.CATALOG));
    mutate(value);
    assert.throws(() => h.registry.validateCatalog(value), /invalid performance catalog/);
  }
  assert.throws(() => h.registry.validateRunners({}), /registry disagree/);
  assert.throws(() => h.registry.validateRunners({ ...h.flows.RUNNERS, unrelated() {} }), /registry disagree/);
  assert.doesNotThrow(() => h.registry.validateRunners(h.flows.RUNNERS));
});

function arbitrarySuite() {
  return { kid: "synthetic-kid", subject: "synthetic-subject", profiles: {
    fpe: { "none-legacy": "number-one", "none-auth": "number-two",
      "stored-legacy": "number-three", "stored-auth": "number-four" },
    token: { none: "random-first", stored: "random-second" },
    "token-deterministic": { none: "fixed-first", stored: "fixed-second" },
    mac: "authenticity", index: "membership", commitment: "opening", masking: "redaction", sharing: "split",
  } };
}

test("all 28 variants consume explicit fixture names and retain their response contracts", async () => {
  const h = await harness();
  const suite = arbitrarySuite();
  for (const selected of h.selectCases("all")) {
    const { family, batch } = h.registry.definition(selected);
    let originals;
    h.flows.runFlow(selected, suite, {
      flow(_, callback) { callback(); },
      post(_, operation, path, body, validate) {
        let response;
        const first = operation === h.registry.operations(selected)[0];
        const profile = family === "fpe" ?
          suite.profiles.fpe[`${selected.subject ? "stored" : "none"}-${selected.authenticated ? "auth" : "legacy"}`] :
          ["token", "token-deterministic"].includes(family) ?
            suite.profiles[family][selected.subject ? "stored" : "none"] : suite.profiles[family];
        if (profile) assert.equal(body.profile, profile);
        if (family === "symmetric") {
          if (first) originals = body.plaintext;
          response = first ? { kid: suite.kid, message: { ctx: "synthetic" },
            ...(selected.subject ? { subject: suite.subject } : {}) } : { plaintext: originals };
        } else if (family === "sign") {
          response = first ? { kid: suite.kid, signature: "a.b.c.d" } :
            { valid: "ok", status: { eddsa: "ok", "ml-dsa": "ok" } };
        } else if (family === "sharing") {
          if (first) originals = body.plaintext;
          response = { kid: suite.kid, profile, set_id: "set", ...(first ?
            { threshold: 3, shares: ["a","b","c","d","e"] } : { plaintext: originals }) };
        } else {
          if (first) originals = batch ? body.items : [body];
          const values = originals.map((item) => {
            if (!first && ["fpe", "token", "token-deterministic"].includes(family)) {
              return { ref: item.ref, plaintext: item.plaintext };
            }
            if (!first) return { ref: item.ref, valid: true, matched: true, index: "synthetic" };
            return { ref: item.ref, ciphertext: "synthetic", token: "synthetic", digest: "synthetic",
              opening: "synthetic", commitment: "synthetic", index: "synthetic",
              masked: "*".repeat(12) + item.plaintext.slice(-4),
              ...(selected.authenticated ? { tag: "a".repeat(64) } : {}) };
          });
          const identity = { kid: suite.kid, profile, ...(selected.subject ? { subject: suite.subject } : {}) };
          response = batch ? { ...identity, items: values } :
            (!first && ["fpe", "token", "mac"].includes(family)) ? values[0] : { ...identity, ...values[0] };
        }
        validate(response);
        return response;
      },
    });
  }
});

test("fixture validation is versioned and never reflects secret or malformed content", async () => {
  const h = await harness();
  const suite = arbitrarySuite();
  const cases = h.selectCases("all");
  const value = { version: 1, url: "http://loopback", apikey: "private-key",
    profiles: { "hybrid-standard-v1": suite } };
  const parse = (v) => h.fixtures.readFixture(JSON.stringify(v), "hybrid-standard-v1", cases);
  assert.equal(parse(value).suite.profiles.fpe["none-auth"], "number-two");
  for (const mutate of [
    (v) => { v.version = 2; },
    (v) => { delete v.apikey; },
    (v) => { delete v.profiles["hybrid-standard-v1"].subject; },
    (v) => { delete v.profiles["hybrid-standard-v1"].profiles.mac; },
  ]) {
    const changed = JSON.parse(JSON.stringify(value));
    mutate(changed);
    assert.throws(() => parse(changed), /^Error: invalid performance fixture$/);
  }
  assert.throws(() => h.fixtures.readFixture("private-key", "missing", cases),
    /^Error: invalid performance fixture$/);
});
