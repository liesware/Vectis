import { expect } from "../transport.js";
import { operations, definition } from "../registry.js";
import { inputs, batchOutput } from "./common.js";

export default function index(test, suite, measured) {
  const batch = definition(test).batch;
  const profile = suite.profiles.index;
  const items = inputs(test);
  const [create, verify] = operations(test);
  const output = measured.post(test, create, `/index${batch ? "/batch" : ""}/${suite.kid}`,
    batch ? { profile, items } : { profile, ...items[0] }, (payload) => {
      expect(payload.kid === suite.kid && payload.profile === profile, "create: identity");
      const values = batch ? batchOutput(payload, items) : [payload];
      expect(values.every((item, i) => item.ref === items[i].ref &&
        ["index"].every((name) => typeof item[name] === "string" && item[name].length > 0)), "create: material");
    });
  const created = batch ? output.items : [output];
  const requests = created.map((item, i) => ({ ...items[i] }));
  measured.post(test, verify, `/index/verify${batch ? "/batch" : ""}`,
    { kid: suite.kid, profile, ...(batch ? { items: requests } : requests[0]) }, (payload) => {
      expect(payload.kid === suite.kid && payload.profile === profile, "verify: identity");
      const values = batch ? batchOutput(payload, items) : [payload];
      expect(values.every((item, i) => item.ref === items[i].ref &&
        item.matched === true && item.index === created[i].index), "verify: valid");
    });
}
