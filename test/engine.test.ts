import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate, normalize, reviewMarkdown } from "../src/engine.js";
import { load } from "../src/io.js";

const plan = (
  type: string,
  after: unknown,
  actions = ["create"],
  before: unknown = null,
  unknown = {},
) => ({
  format_version: "1.2",
  terraform_version: "1.15.8",
  resource_changes: [
    {
      address: `${type}.demo`,
      mode: "managed",
      type,
      change: { actions, before, after, after_unknown: unknown },
    },
  ],
});
test("real Terraform-shaped unsafe sample is blocked with stable evidence", async () => {
  const result = await evaluate(await load("samples/unsafe-plan.json"));
  assert.equal(result.decision, "deny");
  assert.ok(result.findings.some((f) => f.rule === "SG001"));
  assert.equal(result.findings.length, 1);
  assert.equal(
    result.findings[0]?.path,
    "/resource_changes/0/change/after/ingress/0/cidr_blocks/0",
  );
  assert.deepEqual(result.findings[0]?.actions, ["create"]);
  assert.match(result.plan_sha256, /^[a-f0-9]{64}$/);
  assert.match(reviewMarkdown(result), /resource_changes/);
});

test("computed descriptions remain non-security metadata while nested security unknowns deny", async () => {
  const after = { ingress: [{ cidr_blocks: ["10.0.0.0/8"] }] };
  assert.equal(
    (
      await evaluate(
        plan("aws_security_group", after, ["create"], null, { ingress: [{ description: true }] }),
      )
    ).decision,
    "allow",
  );
  for (const key of [
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "from_port",
    "protocol",
    "security_groups",
  ]) {
    const result = await evaluate(
      plan("aws_security_group", after, ["create"], null, { ingress: [{ [key]: true }] }),
    );
    assert.equal(result.decision, "deny");
    assert.ok(result.findings.some((f) => f.path.endsWith(`/after_unknown/ingress/0/${key}`)));
  }
});
test("private ingress permits and unknown ingress blocks", async () => {
  assert.equal(
    (await evaluate(plan("aws_security_group", { ingress: [{ cidr_blocks: ["10.0.0.0/8"] }] })))
      .decision,
    "allow",
  );
  assert.ok(
    (
      await evaluate(
        plan("aws_security_group", { ingress: [] }, ["create"], null, { ingress: true }),
      )
    ).findings.some((f) => f.rule === "SG004"),
  );
});
test("IPv6 public ingress and public ACLs denied", async () => {
  assert.equal(
    (await evaluate(plan("aws_security_group", { ingress: [{ ipv6_cidr_blocks: ["::/0"] }] })))
      .decision,
    "deny",
  );
  assert.equal(
    (
      await evaluate(
        plan("aws_security_group", { ingress: [{ ipv6_cidr_blocks: ["0:0:0:0:0:0:0:0/0"] }] }),
      )
    ).decision,
    "deny",
  );
  for (const acl of ["public-read", "public-read-write", "authenticated-read"])
    assert.equal((await evaluate(plan("aws_s3_bucket_acl", { acl }))).decision, "deny");
  assert.equal((await evaluate(plan("aws_s3_bucket_acl", { acl: "private" }))).decision, "allow");
});
test("S3 missing or false controls deny; all true allow", async () => {
  assert.equal((await evaluate(plan("aws_s3_bucket_public_access_block", {}))).decision, "deny");
  const controls = {
    block_public_acls: true,
    block_public_policy: true,
    ignore_public_acls: true,
    restrict_public_buckets: true,
  };
  assert.equal(
    (await evaluate(plan("aws_s3_bucket_public_access_block", controls))).decision,
    "allow",
  );
});
test("protected replacement blocks and ordinary deletion permits", async () => {
  assert.equal(
    (
      await evaluate(
        plan("aws_security_group", { ingress: [] }, ["delete", "create"], {
          tags: { stackguard_protected: "true" },
        }),
      )
    ).decision,
    "deny",
  );
  assert.equal(
    (await evaluate(plan("aws_security_group", null, ["delete"], { tags: {} }))).decision,
    "allow",
  );
});
test("protected state removal requires review and missing previous values reject", async () => {
  assert.equal(
    (
      await evaluate(
        plan("aws_security_group", null, ["forget"], { tags: { stackguard_protected: "true" } }),
      )
    ).decision,
    "deny",
  );
  assert.throws(() => normalize(plan("aws_security_group", null, ["forget"], null)));
});
test("unassessed resources fail closed, unchanged and data resources do not", async () => {
  assert.equal((await evaluate(plan("aws_unknown", {}))).decision, "deny");
  assert.equal((await evaluate(plan("aws_unknown", {}, ["no-op"]))).decision, "allow");
  const p = plan("aws_unknown", {});
  p.resource_changes[0]!.mode = "data";
  assert.equal((await evaluate(p)).decision, "allow");
});
test("malformed plans, duplicates, impossible actions and incomplete plans reject", () => {
  for (const p of [
    {},
    { ...plan("terraform_data", {}), format_version: "9" },
    { ...plan("terraform_data", {}), complete: false },
    { ...plan("terraform_data", {}), errored: true },
    { ...plan("terraform_data", {}), deferred_changes: [{}] },
    plan("terraform_data", {}, ["delete", "update"]),
  ])
    assert.throws(() => normalize(p));
  const p = plan("terraform_data", {});
  p.resource_changes.push(p.resource_changes[0]!);
  assert.throws(() => normalize(p));
});
test("malformed security attributes block and policy process failure rejects", async () => {
  await assert.rejects(evaluate(plan("aws_security_group", {})));
  await assert.rejects(evaluate(plan("terraform_data", {}), "/nonexistent/opa"));
});
test("review output neutralizes markup and mentions", async () => {
  const p = plan("unknown", {});
  p.resource_changes[0]!.address = "<script>@all|`x`";
  const md = reviewMarkdown(await evaluate(p));
  assert.ok(!md.includes("<script>"));
  assert.ok(!md.includes("@all"));
});

test("supported resources reject null planned values and malformed nested ingress", async () => {
  for (const after of [
    null,
    { ingress: [null] },
    { ingress: [{ cidr_blocks: "0.0.0.0/0" }] },
    { ingress: [{ cidr_blocks: ["invalid"] }] },
    { ingress: [{ ipv6_cidr_blocks: ["0.0.0.0/0"] }] },
  ])
    await assert.rejects(evaluate(plan("aws_security_group", after)));
  assert.throws(() => normalize(plan("aws_security_group", null, ["delete"], null)));
});
