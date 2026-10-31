import assert from "node:assert/strict";
import test from "node:test";
import { evaluate } from "../src/engine.js";

const controls = {
  block_public_acls: true,
  block_public_policy: true,
  ignore_public_acls: true,
  restrict_public_buckets: true,
};
const plan = (type: string, actions: string[], before: unknown, after: unknown) => ({
  format_version: "1.2",
  terraform_version: "1.15.8",
  resource_changes: [
    {
      address: `${type}.synthetic`,
      mode: "managed",
      type,
      change: { actions, before, after, after_unknown: {} },
    },
  ],
});
test("S3 block remote deletion denies while safe final states and state-only forget remain", async () => {
  const deletion = await evaluate(
    plan("aws_s3_bucket_public_access_block", ["delete"], controls, null),
  );
  assert.equal(deletion.decision, "deny");
  assert.equal(deletion.findings.length, 1);
  assert.equal(deletion.findings[0]?.rule, "SG002");
  assert.equal(deletion.findings[0]?.path, "/resource_changes/0/change/actions");
  for (const actions of [["create"], ["update"], ["delete", "create"], ["create", "delete"]])
    assert.equal(
      (await evaluate(plan("aws_s3_bucket_public_access_block", actions, controls, controls)))
        .decision,
      "allow",
    );
  assert.equal(
    (await evaluate(plan("aws_s3_bucket_public_access_block", ["forget"], controls, null)))
      .decision,
    "allow",
  );
});
test("effective inherited protection covers destructive actions with precise stable evidence", async () => {
  for (const actions of [["delete"], ["forget"], ["delete", "create"], ["create", "delete"]]) {
    const after = actions.includes("create") ? { ingress: [] } : null;
    for (const tags of [undefined, {}, null, "malformed", { stackguard_protected: "false" }]) {
      const report = await evaluate(
        plan(
          "aws_security_group",
          actions,
          { tags, tags_all: { stackguard_protected: "true" } },
          after,
        ),
      );
      assert.equal(report.decision, "deny");
      assert.equal(report.findings.length, 1);
      assert.equal(
        report.findings[0]?.path,
        "/resource_changes/0/change/before/tags_all/stackguard_protected",
      );
    }
  }
  const both = await evaluate(
    plan(
      "aws_security_group",
      ["delete"],
      { tags: { stackguard_protected: "true" }, tags_all: { stackguard_protected: "true" } },
      null,
    ),
  );
  assert.equal(both.findings.length, 1);
  assert.equal(
    both.findings[0]?.path,
    "/resource_changes/0/change/before/tags/stackguard_protected",
  );
  for (const marker of [undefined, "false", true])
    assert.equal(
      (
        await evaluate(
          plan(
            "aws_security_group",
            ["delete"],
            { tags_all: { stackguard_protected: marker } },
            null,
          ),
        )
      ).decision,
      "allow",
    );
  assert.equal(
    (
      await evaluate(
        plan(
          "aws_security_group",
          ["update"],
          { tags_all: { stackguard_protected: "true" } },
          { ingress: [] },
        ),
      )
    ).decision,
    "allow",
  );
});
