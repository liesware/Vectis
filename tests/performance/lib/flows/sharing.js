import { expect } from "../transport.js";
import { operations } from "../registry.js";
import { inputs } from "./common.js";

export default function sharing(test, suite, measured) {
  const text = inputs(test)[0].plaintext;
  const profile = suite.profiles.sharing;
  const [split, combine] = operations(test);
  const output = measured.post(test, split, `/shares/split/${suite.kid}`, { profile, plaintext: text }, (payload) =>
    expect(payload.kid === suite.kid && payload.profile === profile && payload.threshold === 3 && payload.shares?.length === 5, "sharing: 3 of 5"));
  measured.post(test, combine, "/shares/combine", { kid: suite.kid, profile,
    shares: [output.shares[0], output.shares[2], output.shares[4]] }, (payload) =>
    expect(payload.kid === suite.kid && payload.profile === profile &&
      payload.plaintext === text && payload.set_id === output.set_id, "sharing: exact secret"));
}
