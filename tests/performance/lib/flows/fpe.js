import { expect } from "../transport.js";
import { operations, definition } from "../registry.js";
import { inputs, batchOutput } from "./common.js";

export default function fpe(test, suite, measured) {
  const batch = definition(test).batch;
  const mode = test.subject ? "stored" : "none";
  const profile = suite.profiles.fpe[`${mode}-${test.authenticated ? "auth" : "legacy"}`];
  const identity = { kid: suite.kid, profile, ...(test.subject ? { subject: suite.subject } : {}) };
  const items = inputs(test);
  const [encrypt, decrypt] = operations(test);
  const suffix = test.subject ? `/subject/${suite.subject}` : "";
  const encoded = measured.post(test, encrypt,
    `/fpe/encrypt${batch ? "/batch" : ""}/${suite.kid}${suffix}`,
    batch ? { profile, items } : { profile, ...items[0] }, (payload) => {
      expect(payload.kid === suite.kid && payload.profile === profile, "encode: identity");
      if (test.subject) expect(payload.subject === suite.subject, "encode: subject");
      const values = batch ? batchOutput(payload, items) : [payload];
      expect(values.every((item, i) => item.ref === items[i].ref &&
        typeof item.ciphertext === "string" && item.ciphertext.length > 0), "encode: result");
      expect(values.every((item) => test.authenticated ? /^[0-9a-f]{64}$/.test(item.tag) :
        item.tag === undefined), "FPE: tag policy");
    });
  const values = batch ? encoded.items : [encoded];
  const requests = values.map((item) => ({ ref: item.ref, ciphertext: item.ciphertext,
    ...(test.authenticated ? { tag: item.tag } : {}) }));
  measured.post(test, decrypt, `/fpe/decrypt${batch ? "/batch" : ""}`,
    { ...identity, ...(batch ? { items: requests } : requests[0]) }, (payload) => {
      if (batch) expect(payload.kid === suite.kid && payload.profile === profile, "decode: identity");
      const results = batch ? batchOutput(payload, items) : [payload];
      expect(results.every((item, i) => item.ref === items[i].ref &&
        item.plaintext === items[i].plaintext), "decode: exact plaintext");
    });
}
