import http from "k6/http";
import { check, fail } from "k6";
import { Counter, Trend } from "k6/metrics";
import { operations } from "./registry.js";

export const operationDuration = new Trend("vectis_operation_duration", true);
export const flowFailures = new Counter("vectis_flow_failures");

export function expect(condition, label, failure = label) {
  if (!check(condition, { [label]: (value) => value === true })) fail(failure);
}

function metricSet(prefix) {
  return {
    duration: new Trend(`${prefix}_duration`, true),
    requests: new Counter(`${prefix}_requests`), values: new Counter(`${prefix}_values`),
    httpErrors: new Counter(`${prefix}_http_errors`), transportErrors: new Counter(`${prefix}_transport_errors`),
    rejected: new Counter(`${prefix}_429`), contractErrors: new Counter(`${prefix}_contract_errors`),
  };
}

export class Measurements {
  constructor(cases, profile, connection) {
    this.connection = connection;
    this.profile = profile;
    this.rows = [];
    this.metrics = {};
    for (const test of cases) {
      for (const operation of [...operations(test), "flow"]) {
        const prefix = `vectis_${test.id}_${operation}`;
        this.metrics[`${test.id}/${operation}`] = metricSet(prefix);
        this.rows.push({ test, operation, prefix });
      }
    }
  }

  tags(test, operation) {
    return { name: `${test.target}/${operation}`, operation, crypto_profile: this.profile,
      subject_mode: test.subject ? "stored" : "none", fpe_authenticated: String(test.authenticated),
      batch_size: String(test.batchSize) };
  }

  post(test, operation, path, body, validate) {
    const tags = this.tags(test, operation);
    const metric = this.metrics[`${test.id}/${operation}`];
    const response = http.post(`${this.connection.url}${path}`, JSON.stringify(body), {
      headers: { "Content-Type": "application/json", "X-API-Key": this.connection.apikey },
      tags, redirects: 0, timeout: "30s",
    });
    metric.duration.add(response.timings.duration, tags);
    operationDuration.add(response.timings.duration, tags);
    metric.requests.add(1, tags);
    metric.httpErrors.add(response.status !== 0 && response.status !== 200 ? 1 : 0, tags);
    metric.transportErrors.add(response.status === 0 ? 1 : 0, tags);
    metric.rejected.add(response.status === 429 ? 1 : 0, tags);
    let valid = false;
    try {
      const received = response.status === 0 ? "transport failure (no HTTP response)" : `HTTP ${response.status}`;
      const rejection = response.status === 429 ? " (server rejected load; inspect concurrency limits)" : "";
      expect(response.status === 200, `${operation}: HTTP 200`,
        `${operation}: expected HTTP 200, got ${received}${rejection}`);
      expect(Object.keys(response.headers).some((key) => key.toLowerCase() === "x-request-id"), `${operation}: request ID`);
      let payload;
      try { payload = JSON.parse(response.body); } catch (_) { fail(`${operation}: invalid JSON`); }
      validate(payload);
      valid = true;
      return payload;
    } finally {
      metric.values.add(valid ? test.batchSize : 0, tags);
      metric.contractErrors.add(!valid && response.status === 200 ? 1 : 0, tags);
    }
  }

  flow(test, callback) {
    const started = Date.now();
    let valid = false;
    try { callback(); valid = true; } finally {
      const metric = this.metrics[`${test.id}/flow`];
      const tags = this.tags(test, "flow");
      metric.duration.add(Date.now() - started, tags);
      metric.requests.add(1, tags);
      metric.values.add(valid ? test.batchSize : 0, tags);
      metric.contractErrors.add(valid ? 0 : 1, tags);
      flowFailures.add(valid ? 0 : 1, tags);
    }
  }

}
