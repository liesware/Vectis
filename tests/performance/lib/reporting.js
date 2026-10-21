function alignedTable(rows) {
  const widths = rows[0].map((_, column) => Math.max(...rows.map((row) => String(row[column]).length)));
  return rows.map((row) => row.map((cell, column) => column < 2 ?
    String(cell).padEnd(widths[column]) : String(cell).padStart(widths[column])).join("  ")).join("\n");
}

export function renderSummary(rows, profile, data) {
  const lines = ["kind\ttarget\tcrypto_profile\tsubject\tfpe_authenticated\tbatch_size\toperation\tsamples\tavg_ms\tp95_ms\tp99_ms\trequests_or_flows_per_s\tvalues_per_s\thttp_errors\ttransport_errors\t429\tcontract_errors"];
  const groups = new Map();
  for (const { test, operation, prefix } of rows) {
    const values = (name) => data.metrics[`${prefix}_${name}`]?.values || {};
    const count = values("requests").count || 0;
    if (!count) continue;
    const duration = values("duration");
    const fmt = (value) => Number.isFinite(value) ? value.toFixed(3) : "-";
    lines.push([operation === "flow" ? "flow" : "http", test.target, profile,
      test.subject, test.authenticated, test.batchSize, operation, count,
      fmt(duration.avg), fmt(duration["p(95)"]), fmt(duration["p(99)"]),
      fmt(values("requests").rate), fmt(values("values").rate),
      values("http_errors").count || 0, values("transport_errors").count || 0,
      values("429").count || 0, values("contract_errors").count || 0].join("\t"));
    if (!groups.has(test.id)) groups.set(test.id, { test, rows: [
      ["Kind", "Operation", "Samples", "avg ms", "p95 ms", "p99 ms", "req/flow/s", "values/s", "H/T/429/C"],
    ] });
    const family = test.target.replace(/-batch$/, "").replace(/-/g, "_");
    groups.get(test.id).rows.push([operation === "flow" ? "FLOW" : "HTTP",
      operation === "flow" ? "flow" : operation.slice(family.length + 1), count,
      fmt(duration.avg), fmt(duration["p(95)"]), fmt(duration["p(99)"]),
      fmt(values("requests").rate), fmt(values("values").rate),
      [values("http_errors").count || 0, values("transport_errors").count || 0,
        values("429").count || 0, values("contract_errors").count || 0].join("/")]);
  }
  const table = lines.join("\n") + "\n";
  const display = [`\nVectis operation summary | ${profile}`];
  for (const { test, rows } of groups.values()) {
    const tag = test.target.startsWith("fpe") ? (test.authenticated ? "on" : "off") : "n/a";
    display.push(`\n${test.target} | subject=${test.subject ? "stored" : "none"} | FPE tag=${tag} | batch=${test.batchSize}`);
    display.push(alignedTable(rows));
  }
  display.push("\nErrors H/T/429/C: HTTP / transport / throttled / contract (FLOW: incomplete flow).");
  display.push("Rates (req/flow/s, values/s) = count / whole k6 run duration; with \"all\" they are campaign rates, not per-operation throughput.");
  const output = { stdout: `${display.join("\n")}\n` };
  if (__ENV.K6_RESULTS_DIR) {
    output[`${__ENV.K6_RESULTS_DIR}/summary.json`] = JSON.stringify({ metrics: data.metrics, state: data.state }, null, 2);
    output[`${__ENV.K6_RESULTS_DIR}/summary.tsv`] = table;
  }
  return output;
}
