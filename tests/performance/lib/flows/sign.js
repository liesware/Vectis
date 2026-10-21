import { expect } from "../transport.js";
import { operations } from "../registry.js";
import { inputs } from "./common.js";
import crypto from "k6/crypto";

export default function signing(test, suite, measured) {
  const [sign, verify] = operations(test);
  const token = measured.post(test, sign, `/sign/${suite.kid}`,
    { message_hash: { alg: "SHA-256", hex: crypto.sha256(inputs(test)[0].plaintext, "hex") } },
    (payload) => expect(payload.kid === suite.kid && payload.signature?.split(".").length === 4, "sign: compact wrapper"));
  measured.post(test, verify, "/sign/verification", token, (payload) =>
    expect(payload.valid === "ok" && payload.status?.eddsa === "ok" && payload.status?.["ml-dsa"] === "ok", "sign: both verified"));
}
