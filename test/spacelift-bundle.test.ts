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

test("standalone hosted policy preserves deletion and effective-tag boundaries", () => {
  const controls = {
    block_public_acls: true,
    block_public_policy: true,
    ignore_public_acls: true,
    restrict_public_buckets: true,
  };
  const check = (type: string, actions: string[], before: unknown, after: unknown): string[] =>
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
        {
          input: JSON.stringify({
            terraform: {
              resource_changes: [
                {
                  address: `${type}.synthetic`,
                  mode: "managed",
                  type,
                  change: { actions, before, after, after_unknown: {} },
                },
              ],
            },
          }),
          encoding: "utf8",
        },
      ),
    ).result[0].expressions[0].value;
  assert.ok(
    check("aws_s3_bucket_public_access_block", ["delete"], controls, null).some((x) =>
      x.startsWith("SG002:"),
    ),
  );
  assert.deepEqual(check("aws_s3_bucket_public_access_block", ["forget"], controls, null), []);
  assert.deepEqual(check("aws_s3_bucket_public_access_block", ["create"], null, controls), []);
  for (const actions of [["delete"], ["forget"], ["delete", "create"], ["create", "delete"]])
    assert.ok(
      check(
        "aws_security_group",
        actions,
        { tags: {}, tags_all: { stackguard_protected: "true" } },
        actions.includes("create") ? { ingress: [] } : null,
      ).some((x) => x.startsWith("SG003:")),
    );
  for (const actions of [["delete"], ["forget"]])
    assert.ok(
      check("aws_security_group", actions, { tags: {} }, { ingress: [] }).some((x) =>
        x.startsWith("SG000:"),
      ),
    );
});
