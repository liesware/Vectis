import { expect } from "../transport.js";

export function inputs(test) {
  return Array.from({ length: test.batchSize }, (_, i) => ({
    ref: `${test.id}-${__VU}-${__ITER}-${i}`,
    plaintext: String(__VU % 100000).padStart(5, "0") + String(__ITER % 100000000).padStart(8, "0") + String(i).padStart(3, "0"),
  }));
}

export function batchOutput(payload, items) {
  expect(Array.isArray(payload.items) && payload.items.length === items.length, "batch: exact item count");
  expect(payload.items.every((item, i) => item.ref === items[i].ref), "batch: preserved refs/order");
  return payload.items;
}
