import { selectCases, PROFILES } from "./lib/registry.js";
import { Measurements } from "./lib/transport.js";
import { runCases } from "./lib/flows.js";
import { readFixture } from "./lib/fixtures.js";
import { renderSummary } from "./lib/reporting.js";

const cases = selectCases(__ENV.K6_TARGET || "all", __ENV.K6_SUBJECT === "true",
  __ENV.K6_AUTHENTICATED === "true", Number(__ENV.K6_BATCH_SIZE || 3));
const profile = __ENV.K6_CRYPTO_PROFILE || PROFILES[0];
if (!PROFILES.includes(profile)) throw new Error("select one built-in crypto profile per k6 invocation");
if (!__ENV.K6_FIXTURE_PATH) throw new Error("K6_FIXTURE_PATH is required");
const fixture = readFixture(open(__ENV.K6_FIXTURE_PATH), profile, cases);
const measured = new Measurements(cases, profile, fixture.connection);
const thresholds = { checks: ["rate>0.99"], http_req_failed: ["rate<0.01"],
  vectis_flow_failures: ["count==0"] };
if (__ENV.K6_P95_MS) thresholds.vectis_operation_duration = [`p(95)<${Number(__ENV.K6_P95_MS)}`];
export const options = {
  vus: Number(__ENV.K6_VUS || 1),
  ...(__ENV.K6_DURATION ? { duration: __ENV.K6_DURATION } : { iterations: Number(__ENV.K6_ITERATIONS || 4) }),
  thresholds, summaryTrendStats: ["avg", "p(95)", "p(99)"],
  // Exclude URL/error text tags: paths contain instance-specific KIDs/subjects.
  systemTags: ["method", "status", "name", "scenario", "check", "expected_response", "error_code"],
};

export function setup() {
  return fixture.suite;
}

export default function (suite) {
  // Every VU iteration visits the entire selected list, even after a failed flow.
  runCases(cases, suite, measured);
}

export function handleSummary(data) {
  return renderSummary(measured.rows, profile, data);
}
