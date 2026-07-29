import http from "k6/http";
import crypto from "k6/crypto";
import { check, fail } from "k6";
import { Counter, Trend } from "k6/metrics";

const DEFAULT_BASE_URL = "http://127.0.0.1:3020";
const operationDuration = new Trend("vectis_operation_duration", true);
const thresholds = {
  checks: ["rate>0.99"],
  http_req_failed: ["rate<0.01"],
};

if (__ENV.K6_P95_MS) {
  const p95 = Number(__ENV.K6_P95_MS);
  if (!Number.isFinite(p95) || p95 <= 0) {
    fail("K6_P95_MS must be a positive number");
  }
  thresholds.vectis_operation_duration = [`p(95)<${p95}`];
}

export const options = __ENV.K6_DURATION
  ? {
      vus: Number(__ENV.K6_VUS || 1),
      duration: __ENV.K6_DURATION,
      thresholds,
      summaryTrendStats: ["avg", "p(95)", "p(99)"],
    }
  : {
      vus: Number(__ENV.K6_VUS || 1),
      iterations: Number(__ENV.K6_ITERATIONS || 4),
      thresholds,
      summaryTrendStats: ["avg", "p(95)", "p(99)"],
    };

const SUITES = [
  {
    name: "performance",
    profile: "hybrid-performance-v1",
    kidEnv: "K6_KID_PERFORMANCE",
    prefix: "4111111111",
    fpe: "performance-pan-fpe-v1",
    token: "performance-pan-token-v1",
    mac: "performance-pan-mac-v1",
    mask: "performance-pan-mask-v1",
    commitment: "performance-pan-commit-v1",
    sharing: "performance-share-3of5-v1",
  },
  {
    name: "standard",
    profile: "hybrid-standard-v1",
    kidEnv: "K6_KID_STANDARD",
    prefix: "123",
    fpe: "standard-ssn-fpe-v1",
    token: "standard-ssn-token-v1",
    mac: "standard-ssn-mac-v1",
    mask: "standard-ssn-mask-v1",
    commitment: "standard-ssn-commit-v1",
    sharing: "standard-share-3of5-v1",
  },
  {
    name: "high-assurance",
    profile: "hybrid-high-assurance-v1",
    kidEnv: "K6_KID_HIGH_ASSURANCE",
    prefix: "987654",
    fpe: "high-assurance-bank-fpe-v1",
    token: "high-assurance-bank-token-v1",
    mac: "high-assurance-bank-mac-v1",
    mask: "high-assurance-bank-mask-v1",
    commitment: "high-assurance-bank-commit-v1",
    sharing: "high-assurance-share-3of5-v1",
  },
  {
    name: "long-term",
    profile: "hybrid-long-term-v1",
    kidEnv: "K6_KID_LONG_TERM",
    prefix: "555555",
    fpe: "long-term-account-fpe-v1",
    token: "long-term-account-token-v1",
    mac: "long-term-account-mac-v1",
    mask: "long-term-account-mask-v1",
    commitment: "long-term-account-commit-v1",
    sharing: "long-term-share-3of5-v1",
  },
];

const OPERATION_NAMES = [
  "health_startup",
  "health_live",
  "health_ready",
  "pub",
  "self_test_keys",
  "fpe_encrypt",
  "fpe_decrypt",
  "fpe_encrypt_batch",
  "fpe_decrypt_batch",
  "mask",
  "mask_batch",
  "token_encode",
  "token_decode",
  "token_encode_batch",
  "token_decode_batch",
  "mac_create",
  "mac_verify",
  "mac_create_batch",
  "mac_verify_batch",
  "index_create",
  "index_verify",
  "index_create_batch",
  "index_verify_batch",
  "commit_create",
  "commit_verify",
  "commit_create_batch",
  "commit_verify_batch",
  "share_split",
  "share_combine",
  "internal_message_encrypt",
  "internal_message_decrypt",
  "sign",
  "sign_verify",
  "metrics",
];
const PROFILE_NAMES = ["system", ...SUITES.map((suite) => suite.profile)];
const operationMetrics = {};

function metricSuffix(operation, profile) {
  return `${operation}_${profile.replace(/[^a-zA-Z0-9_]/g, "_")}`;
}

for (const profile of PROFILE_NAMES) {
  for (const operation of OPERATION_NAMES) {
    const suffix = metricSuffix(operation, profile);
    const key = `${operation}|${profile}`;
    const durationName = `vectis_${suffix}_duration`;
    const requestName = `vectis_${suffix}_requests`;
    operationMetrics[key] = {
      durationName,
      requestName,
      duration: new Trend(durationName, true),
      requests: new Counter(requestName),
    };
  }
}

function recordOperation(response, operation, profile) {
  const metric = operationMetrics[`${operation}|${profile}`];
  if (!metric) {
    fail(`missing metrics for ${operation}/${profile}`);
  }
  operationDuration.add(response.timings.duration, { operation, crypto_profile: profile });
  metric.duration.add(response.timings.duration);
  metric.requests.add(1);
}

function baseUrl() {
  return (__ENV.VECTIS_API_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
}

function apiKey() {
  return __ENV.VECTIS_APIKEY || "";
}

function requireEnvironment(name) {
  const value = __ENV[name];
  if (!value) {
    fail(`${name} is required`);
  }
  return value;
}

function headers(authenticated = true) {
  const values = { "Content-Type": "application/json" };
  if (authenticated) {
    values["X-API-Key"] = apiKey();
  }
  return values;
}

function requestId(response) {
  for (const name in response.headers) {
    if (name.toLowerCase() === "x-request-id") {
      return response.headers[name];
    }
  }
  return "";
}

function parseJson(response, operation) {
  try {
    return JSON.parse(response.body || "{}");
  } catch (_) {
    fail(`${operation} returned invalid JSON`);
  }
  return {};
}

function expect(value, label, predicate) {
  const passed = check(value, { [label]: predicate });
  if (!passed) {
    fail(`${label} response contract failed`);
  }
}

function get(path, operation, suite = "system", authenticated = false) {
  const response = http.get(`${baseUrl()}${path}`, {
    headers: headers(authenticated),
    tags: { operation, crypto_profile: suite },
  });
  recordOperation(response, operation, suite);
  expect(response, `${operation}: status 200`, (result) => result.status === 200);
  expect(response, `${operation}: request id`, (result) => requestId(result) !== "");
  return response;
}

function post(path, body, operation, suite) {
  const response = http.post(`${baseUrl()}${path}`, JSON.stringify(body), {
    headers: headers(),
    tags: { operation, crypto_profile: suite },
  });
  recordOperation(response, operation, suite);
  expect(response, `${operation}: status 200`, (result) => result.status === 200);
  expect(response, `${operation}: request id`, (result) => requestId(result) !== "");
  return parseJson(response, operation);
}

function plaintext(suite, offset = 0) {
  const sequence = ((__VU * 100000 + __ITER * 10 + offset) % 1000000)
    .toString()
    .padStart(6, "0");
  return `${suite.prefix}${sequence}`;
}

function ref(suite, operation, offset = 0) {
  return `${suite.name}-${__VU}-${__ITER}-${operation}-${offset}`;
}

function batchItems(suite, operation) {
  return [0, 1].map((offset) => ({
    ref: ref(suite, operation, offset),
    plaintext: plaintext(suite, offset),
  }));
}

function verifyHealth() {
  const startup = parseJson(get("/healthz/startup", "health_startup"), "health_startup");
  expect(startup, "health_startup: status started", (body) => body.status === "started");
  const live = parseJson(get("/healthz/live", "health_live"), "health_live");
  expect(live, "health_live: status ok", (body) => body.status === "ok");
  const ready = parseJson(get("/healthz/ready", "health_ready"), "health_ready");
  expect(ready, "health_ready: status ready", (body) => body.status === "ready");
}

function verifyKeyReadiness(suite) {
  const publicKeys = parseJson(get(`/pub/${suite.kid}`, "pub", suite.profile), "pub");
  expect(publicKeys, "pub: hybrid public keys", (body) =>
    body.keys && body.keys.eddsa && body.keys.xecdh && body.keys["ml-dsa"] && body.keys["ml-kem"],
  );
  const selfTest = parseJson(
    get(`/self-test/keys/${suite.kid}`, "self_test_keys", suite.profile, true),
    "self_test_keys",
  );
  expect(selfTest, "self_test_keys: all components valid", (body) =>
    body.symmetric?.valid === true &&
    body.eddsa?.valid === true &&
    body.xecdh?.valid === true &&
    body["ml-dsa"]?.valid === true &&
    body["ml-kem"]?.valid === true,
  );
}

function exerciseFpe(suite) {
  const input = plaintext(suite);
  const encrypted = post(
    `/fpe/encrypt/${suite.kid}`,
    { ref: ref(suite, "fpe-single"), profile: suite.fpe, plaintext: input },
    "fpe_encrypt",
    suite.profile,
  );
  const decrypted = post(
    "/fpe/decrypt",
    { ref: ref(suite, "fpe-single"), kid: suite.kid, profile: suite.fpe, ciphertext: encrypted.ciphertext },
    "fpe_decrypt",
    suite.profile,
  );
  expect(decrypted, "fpe_decrypt: plaintext matches", (body) => body.plaintext === input);

  const items = batchItems(suite, "fpe-batch");
  const encryptedBatch = post(
    `/fpe/encrypt/batch/${suite.kid}`,
    { profile: suite.fpe, items },
    "fpe_encrypt_batch",
    suite.profile,
  );
  const decryptedBatch = post(
    "/fpe/decrypt/batch",
    {
      kid: suite.kid,
      profile: suite.fpe,
      items: encryptedBatch.items.map((item) => ({
        ref: item.ref,
        ciphertext: item.ciphertext,
      })),
    },
    "fpe_decrypt_batch",
    suite.profile,
  );
  expect(decryptedBatch, "fpe_decrypt_batch: plaintexts match", (body) =>
    body.items?.every((item, index) => item.plaintext === items[index].plaintext),
  );
}

function exerciseMasking(suite) {
  const input = plaintext(suite);
  const masked = post(
    `/mask/${suite.kid}`,
    { ref: ref(suite, "mask-single"), profile: suite.mask, plaintext: input },
    "mask",
    suite.profile,
  );
  expect(masked, "mask: preserves final digits", (body) => body.masked?.endsWith(input.slice(-4)));

  const items = batchItems(suite, "mask-batch");
  const batch = post(
    `/mask/batch/${suite.kid}`,
    { profile: suite.mask, items },
    "mask_batch",
    suite.profile,
  );
  expect(batch, "mask_batch: preserves final digits", (body) =>
    body.items?.every((item, index) => item.masked.endsWith(items[index].plaintext.slice(-4))),
  );
}

function exerciseTokenization(suite) {
  const input = plaintext(suite);
  const encoded = post(
    `/token/encode/${suite.kid}`,
    { ref: ref(suite, "token-single"), profile: suite.token, plaintext: input },
    "token_encode",
    suite.profile,
  );
  const decoded = post(
    "/token/decode",
    { ref: ref(suite, "token-single"), kid: suite.kid, profile: suite.token, token: encoded.token },
    "token_decode",
    suite.profile,
  );
  expect(decoded, "token_decode: plaintext matches", (body) => body.plaintext === input);

  const items = batchItems(suite, "token-batch");
  const encodedBatch = post(
    `/token/encode/batch/${suite.kid}`,
    { profile: suite.token, items },
    "token_encode_batch",
    suite.profile,
  );
  const decodedBatch = post(
    "/token/decode/batch",
    {
      kid: suite.kid,
      profile: suite.token,
      items: encodedBatch.items.map((item) => ({ ref: item.ref, token: item.token })),
    },
    "token_decode_batch",
    suite.profile,
  );
  expect(decodedBatch, "token_decode_batch: plaintexts match", (body) =>
    body.items?.every((item, index) => item.plaintext === items[index].plaintext),
  );
}

function exerciseMac(suite) {
  const input = plaintext(suite);
  const created = post(
    `/mac/${suite.kid}`,
    { ref: ref(suite, "mac-single"), profile: suite.mac, plaintext: input },
    "mac_create",
    suite.profile,
  );
  const verified = post(
    "/mac/verify",
    { ref: ref(suite, "mac-single"), kid: suite.kid, profile: suite.mac, plaintext: input, digest: created.digest },
    "mac_verify",
    suite.profile,
  );
  expect(verified, "mac_verify: valid", (body) => body.valid === true);

  const items = batchItems(suite, "mac-batch");
  const createdBatch = post(
    `/mac/batch/${suite.kid}`,
    { profile: suite.mac, items },
    "mac_create_batch",
    suite.profile,
  );
  const verifiedBatch = post(
    "/mac/verify/batch",
    {
      kid: suite.kid,
      profile: suite.mac,
      items: createdBatch.items.map((item, index) => ({
        ref: item.ref,
        plaintext: items[index].plaintext,
        digest: item.digest,
      })),
    },
    "mac_verify_batch",
    suite.profile,
  );
  expect(verifiedBatch, "mac_verify_batch: valid", (body) => body.items?.every((item) => item.valid));
}

function exerciseIndexes(suite) {
  const input = plaintext(suite);
  const created = post(
    `/index/${suite.kid}`,
    { ref: ref(suite, "index-single"), profile: suite.mac, plaintext: input },
    "index_create",
    suite.profile,
  );
  const verified = post(
    "/index/verify",
    { ref: ref(suite, "index-single"), kid: suite.kid, profile: suite.mac, plaintext: input },
    "index_verify",
    suite.profile,
  );
  expect(verified, "index_verify: matched", (body) => body.matched === true && body.index === created.index);

  const items = batchItems(suite, "index-batch");
  const createdBatch = post(
    `/index/batch/${suite.kid}`,
    { profile: suite.mac, items },
    "index_create_batch",
    suite.profile,
  );
  const verifiedBatch = post(
    "/index/verify/batch",
    { kid: suite.kid, profile: suite.mac, items },
    "index_verify_batch",
    suite.profile,
  );
  expect(createdBatch, "index_create_batch: items", (body) => body.items?.length === items.length);
  expect(verifiedBatch, "index_verify_batch: matched", (body) => body.items?.every((item) => item.matched));
}

function exerciseCommitments(suite) {
  const input = plaintext(suite);
  const created = post(
    `/commit/${suite.kid}`,
    { ref: ref(suite, "commit-single"), profile: suite.commitment, plaintext: input },
    "commit_create",
    suite.profile,
  );
  const verified = post(
    "/commit/verify",
    { ref: ref(suite, "commit-single"), kid: suite.kid, profile: suite.commitment, plaintext: input, opening: created.opening, commitment: created.commitment },
    "commit_verify",
    suite.profile,
  );
  expect(verified, "commit_verify: valid", (body) => body.valid === true);

  const items = batchItems(suite, "commit-batch");
  const createdBatch = post(
    `/commit/batch/${suite.kid}`,
    { profile: suite.commitment, items },
    "commit_create_batch",
    suite.profile,
  );
  const verifiedBatch = post(
    "/commit/verify/batch",
    {
      kid: suite.kid,
      profile: suite.commitment,
      items: createdBatch.items.map((item, index) => ({
        ref: item.ref,
        plaintext: items[index].plaintext,
        opening: item.opening,
        commitment: item.commitment,
      })),
    },
    "commit_verify_batch",
    suite.profile,
  );
  expect(verifiedBatch, "commit_verify_batch: valid", (body) => body.items?.every((item) => item.valid));
}

function exerciseSharing(suite) {
  const secret = `share-${suite.name}-${__VU}-${__ITER}`;
  const split = post(
    `/shares/split/${suite.kid}`,
    { profile: suite.sharing, plaintext: secret },
    "share_split",
    suite.profile,
  );
  const combined = post(
    "/shares/combine",
    { kid: suite.kid, profile: suite.sharing, shares: split.shares.slice(0, 3) },
    "share_combine",
    suite.profile,
  );
  expect(combined, "share_combine: plaintext matches", (body) => body.plaintext === secret);
}

function exerciseInternalMessage(suite) {
  const input = `internal-${suite.name}-${__VU}-${__ITER}`;
  const encrypted = post(
    `/message/internal/encrypt/${suite.kid}`,
    { plaintext: input },
    "internal_message_encrypt",
    suite.profile,
  );
  const decrypted = post(
    "/message/internal/decrypt",
    encrypted,
    "internal_message_decrypt",
    suite.profile,
  );
  expect(decrypted, "internal_message_decrypt: plaintext matches", (body) => body.plaintext === input);
}

function exerciseSignatures(suite) {
  const hash = crypto.sha256(`sign-${suite.name}-${__VU}-${__ITER}`, "hex");
  const signed = post(
    `/sign/${suite.kid}`,
    { message_hash: { alg: "SHA-256", hex: hash } },
    "sign",
    suite.profile,
  );
  expect(signed, "sign: compact token", (body) =>
    body.kid === suite.kid && typeof body.signature === "string" && body.signature.split(".").length === 4,
  );
  const verified = post("/sign/verification", signed, "sign_verify", suite.profile);
  expect(verified, "sign_verify: valid", (body) => body.valid === "ok");
}

export function setup() {
  requireEnvironment("VECTIS_APIKEY");
  const suites = SUITES.map((suite) => ({ ...suite, kid: requireEnvironment(suite.kidEnv) }));
  verifyHealth();
  suites.forEach(verifyKeyReadiness);
  return { suites };
}

export default function (data) {
  const suite = data.suites[(__VU + __ITER) % data.suites.length];
  const live = parseJson(get("/healthz/live", "health_live", suite.profile), "health_live");
  expect(live, "health_live: status ok", (body) => body.status === "ok");
  const ready = parseJson(get("/healthz/ready", "health_ready", suite.profile), "health_ready");
  expect(ready, "health_ready: status ready", (body) => body.status === "ready");

  exerciseFpe(suite);
  exerciseMasking(suite);
  exerciseTokenization(suite);
  exerciseMac(suite);
  exerciseIndexes(suite);
  exerciseCommitments(suite);
  exerciseSharing(suite);
  exerciseInternalMessage(suite);
  exerciseSignatures(suite);
}

export function teardown() {
  const response = get("/metrics", "metrics", "system", true);
  expect(response, "metrics: crypto operations exported", (result) =>
    result.body.includes("vectis_crypto_operation_total"),
  );
}

function formatMetric(value, decimals = 2) {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(decimals) : "-";
}

export function handleSummary(data) {
  const lines = [
    "",
    "Vectis k6 operation summary",
    "operation\tcrypto_profile\tthroughput_rps\tavg_ms\tp95_ms\tp99_ms",
  ];

  for (const profile of PROFILE_NAMES) {
    for (const operation of OPERATION_NAMES) {
      const metric = operationMetrics[`${operation}|${profile}`];
      const duration = data.metrics[metric.durationName];
      const requests = data.metrics[metric.requestName];
      if (!duration || !requests || requests.values.count === 0) {
        continue;
      }
      lines.push(
        [
          operation,
          profile,
          formatMetric(requests.values.rate),
          formatMetric(duration.values.avg),
          formatMetric(duration.values["p(95)"]),
          formatMetric(duration.values["p(99)"]),
        ].join("\t"),
      );
    }
  }

  const checks = data.metrics.checks?.values.rate;
  const failures = data.metrics.http_req_failed?.values.rate;
  lines.push("");
  lines.push(`checks_rate=${formatMetric(checks, 4)} http_failure_rate=${formatMetric(failures, 4)}`);
  return { stdout: `${lines.join("\n")}\n` };
}
