import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("deployable Spacelift policy is self-contained and denies the actual unsafe Terraform plan", async () => {
  execFileSync(process.execPath, ["--import", "tsx", "scripts/build-spacelift.ts"]);
  const input = { terraform: JSON.parse(await readFile("samples/unsafe-plan.json", "utf8")) };
  const check = (value: unknown) =>
    JSON.parse(
      execFileSync(
        process.env.OPA ?? ".tools/opa",
        [
          "eval",
          "--stdin-input",
          "--format=json",
          "--data",
          "integrations/spacelift/policy.rego",
          "data.spacelift.deny",
        ],
        { input: JSON.stringify(value), encoding: "utf8" },
      ),
    ).result[0].expressions[0].value as string[];
  assert.ok(check(input).some((value) => value.includes("SG001")));
  assert.ok(check({}).length > 0);
  assert.deepEqual(check({ terraform: { resource_changes: [] } }), []);
  input.terraform.resource_changes[0].change.after.ingress[0].cidr_blocks = ["10.0.0.0/8"];
  assert.deepEqual(check(input), []);
});
