import { mkdir, readFile, writeFile } from "node:fs/promises";

const core = await readFile("policy/stackguard.rego", "utf8");
const adapter = await readFile("policy/spacelift.rego", "utf8");
const deployed =
  core
    .replace(/^package stackguard$/m, "package spacelift")
    .replaceAll("input.changes", "normalized.changes")
    .replace(/^deny contains/gm, "stackguard_deny contains") +
  "\n" +
  adapter
    .replace(/^package spacelift\nimport rego.v1\n/m, "")
    .replace(
      "findings := data.stackguard.deny with input as normalized",
      "findings := stackguard_deny",
    );
if (deployed.includes("data.stackguard"))
  throw new Error("Spacelift bundle has an external module dependency");
await mkdir("integrations/spacelift", { recursive: true });
await writeFile("integrations/spacelift/policy.rego", deployed);
