import fpe from "./flows/fpe.js";
import token from "./flows/token.js";
import deterministic from "./flows/token-deterministic.js";
import mac from "./flows/mac.js";
import index from "./flows/index.js";
import commitment from "./flows/commitment.js";
import masking from "./flows/masking.js";
import symmetric from "./flows/symmetric.js";
import sign from "./flows/sign.js";
import sharing from "./flows/sharing.js";
import { definition, validateRunners } from "./registry.js";

export { batchOutput } from "./flows/common.js";

export const RUNNERS = { fpe, token, "token-deterministic": deterministic,
  mac, index, commitment, masking, symmetric, sign, sharing };
validateRunners(RUNNERS);

export function runFlow(test, suite, measured) {
  measured.flow(test, () => RUNNERS[definition(test).family](test, suite, measured));
}

// A failed flow is already counted by measured.flow; keep visiting the rest so
// one broken family cannot hide the results of the others in the same iteration.
export function runCases(cases, suite, measured) {
  for (const test of cases) {
    try { runFlow(test, suite, measured); } catch (_) { /* recorded as a flow failure */ }
  }
}
