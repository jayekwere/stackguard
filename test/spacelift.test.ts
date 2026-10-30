import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { load } from "../src/io.js";

const check = (input: unknown): string[] => {
  const result = JSON.parse(
    execFileSync(
      process.env.OPA ?? ".tools/opa",
      ["eval", "--stdin-input", "--format=json", "--data", "policy", "data.spacelift.deny"],
      { input: JSON.stringify(input), encoding: "utf8" },
    ),
  );
  return result.result[0].expressions[0].value as string[];
};
test("Spacelift adapter denies missing, incomplete and malformed envelopes", () => {
  for (const input of [
    {},
    { terraform: {} },
    { terraform: { resource_changes: "invalid" } },
    { terraform: { resource_changes: [], complete: false } },
    { terraform: { resource_changes: [{}] } },
  ])
    assert.ok(check(input).length > 0);
});
test("Spacelift adapter evaluates actual Terraform changes and permits a valid empty plan", async () => {
  const plan = await load("samples/unsafe-plan.json");
  assert.ok(check({ terraform: plan }).some((s) => s.includes("SG001")));
  assert.deepEqual(check({ terraform: { resource_changes: [] } }), []);
});
