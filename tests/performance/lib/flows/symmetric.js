import { expect } from "../transport.js";
import { operations } from "../registry.js";
import { inputs } from "./common.js";

export default function symmetric(test, suite, measured) {
  const text = inputs(test)[0].plaintext;
  const [encrypt, decrypt] = operations(test);
  const envelope = measured.post(test, encrypt, `/symmetric/encrypt/${suite.kid}${test.subject ? `/subject/${suite.subject}` : ""}`,
    { plaintext: text }, (payload) => {
      expect(payload.kid === suite.kid && typeof payload.message?.ctx === "string", "symmetric: envelope");
      if (test.subject) expect(payload.subject === suite.subject, "symmetric: subject");
    });
  measured.post(test, decrypt, "/symmetric/decrypt", envelope, (payload) => expect(payload.plaintext === text, "symmetric: exact plaintext"));
}
