import { expect } from "../transport.js";
import { operations } from "../registry.js";
import { inputs, batchOutput } from "./common.js";

export default function masking(test, suite, measured) {
  const items = inputs(test);
  const isBatch = test.target.endsWith("-batch");
  const profile = suite.profiles.masking;
  measured.post(test, operations(test)[0], `/mask${isBatch ? "/batch" : ""}/${suite.kid}`,
    isBatch ? { profile, items } : { profile, ...items[0] }, (payload) => {
      expect(payload.kid === suite.kid && payload.profile === profile, "mask: identity");
      const values = isBatch ? batchOutput(payload, items) : [payload];
      expect(values.every((item, i) => item.ref === items[i].ref && item.masked === "*".repeat(12) + items[i].plaintext.slice(-4)), "mask: exact policy");
    });
}
