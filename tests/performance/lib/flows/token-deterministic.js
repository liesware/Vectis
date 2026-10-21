import { expect } from "../transport.js";
import { operations, definition } from "../registry.js";
import { inputs, batchOutput } from "./common.js";

export default function token(test, suite, measured) {
  const batch = definition(test).batch;
  const profile = suite.profiles["token-deterministic"][test.subject ? "stored" : "none"];
  const identity = { kid: suite.kid, profile, ...(test.subject ? { subject: suite.subject } : {}) };
  const items = inputs(test);
  const [encode, decode] = operations(test);
  const suffix = test.subject ? `/subject/${suite.subject}` : "";
  const encoded = measured.post(test, encode,
    `/token/deterministic/encode${batch ? "/batch" : ""}/${suite.kid}${suffix}`,
    batch ? { profile, items } : { profile, ...items[0] }, (payload) => {
      expect(payload.kid === suite.kid && payload.profile === profile, "encode: identity");
      if (test.subject) expect(payload.subject === suite.subject, "encode: subject");
      const values = batch ? batchOutput(payload, items) : [payload];
      expect(values.every((item, i) => item.ref === items[i].ref &&
        typeof item.token === "string" && item.token.length > 0), "encode: result");
    });
  const values = batch ? encoded.items : [encoded];
  const requests = values.map((item) => ({ ref: item.ref, token: item.token }));
  measured.post(test, decode, `/token/deterministic/decode${batch ? "/batch" : ""}`,
    { ...identity, ...(batch ? { items: requests } : requests[0]) }, (payload) => {
      expect(payload.kid === suite.kid && payload.profile === profile, "decode: identity");
      const results = batch ? batchOutput(payload, items) : [payload];
      expect(results.every((item, i) => item.ref === items[i].ref &&
        item.plaintext === items[i].plaintext), "decode: exact plaintext");
    });
}
