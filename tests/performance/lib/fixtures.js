import { definition } from "./registry.js";

// Reject incomplete private fixtures without reflecting their values in errors.
export function readFixture(text, profile, cases) {
  try {
    const value = JSON.parse(text);
    const suite = value.profiles[profile];
    const required = (field) => {
      if (typeof field !== "string" || !field) throw new Error();
    };
    if (value.version !== 1) throw new Error();
    required(value.url);
    required(value.apikey);
    required(suite.kid);
    for (const test of cases) {
      const spec = definition(test);
      if (test.subject) required(suite.subject);
      if (spec.family === "fpe") {
        required(suite.profiles.fpe[`${test.subject ? "stored" : "none"}-${test.authenticated ? "auth" : "legacy"}`]);
      } else if (spec.family === "token" || spec.family === "token-deterministic") {
        required(suite.profiles[spec.family][test.subject ? "stored" : "none"]);
      } else if (!["symmetric", "sign"].includes(spec.family)) {
        required(suite.profiles[spec.family]);
      }
    }
    return { connection: { url: value.url, apikey: value.apikey }, suite };
  } catch (_) {
    throw new Error("invalid performance fixture");
  }
}
