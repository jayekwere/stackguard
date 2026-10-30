import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { z } from "zod";
import { digest } from "./io.js";

const jsonObject = z.record(z.string(), z.unknown());
const resource = z
  .object({
    address: z.string().min(1).max(512),
    mode: z.enum(["managed", "data"]),
    type: z.string().min(1),
    change: z
      .object({
        actions: z
          .array(z.enum(["no-op", "create", "read", "update", "delete", "forget"]))
          .min(1)
          .max(2),
        before: jsonObject.nullable(),
        after: jsonObject.nullable(),
        after_unknown: jsonObject.optional(),
      })
      .passthrough(),
  })
  .passthrough();
const terraform = z
  .object({
    format_version: z.literal("1.2"),
    terraform_version: z.string(),
    resource_changes: z.array(resource).max(10000).default([]),
    errored: z.boolean().optional(),
    complete: z.boolean().optional(),
    deferred_changes: z.array(z.unknown()).optional(),
  })
  .passthrough();
export const findingSchema = z
  .object({
    rule: z.string(),
    address: z.string(),
    path: z.string(),
    message: z.string(),
    actions: z
      .array(z.enum(["no-op", "create", "read", "update", "delete", "forget"]))
      .min(1)
      .max(2),
  })
  .strict();
export type Finding = z.infer<typeof findingSchema>;
export function normalize(input: unknown) {
  const plan = terraform.parse(input);
  if (plan.errored || plan.complete === false || plan.deferred_changes?.length)
    throw new Error("Incomplete Terraform plan");
  const seen = new Set<string>();
  return {
    schema_version: "1.0" as const,
    changes: plan.resource_changes.map((r, index) => {
      if (seen.has(r.address)) throw new Error("Duplicate resource address");
      seen.add(r.address);
      const actions = r.change.actions;
      if ((actions.includes("create") || actions.includes("update")) && r.change.after === null)
        throw new Error("Missing planned values");
      if ((actions.includes("delete") || actions.includes("forget")) && r.change.before === null)
        throw new Error("Missing previous values");
      if (
        actions.length === 1 &&
        (actions[0] === "delete" || actions[0] === "forget") &&
        r.change.after !== null
      )
        throw new Error("Deletion has planned values");
      if (r.type === "aws_security_group" && r.change.after !== null) {
        const cidr = (family: number) =>
          z.string().refine((value) => {
            const parts = value.split("/");
            const ip = parts[0] ?? "";
            const prefix = Number(parts[1]);
            return (
              parts.length === 2 &&
              isIP(ip) === family &&
              /^\d+$/.test(parts[1] ?? "") &&
              prefix >= 0 &&
              prefix <= (family === 4 ? 32 : 128)
            );
          });
        z.object({
          ingress: z.array(
            z
              .object({
                cidr_blocks: z.array(cidr(4)).optional(),
                ipv6_cidr_blocks: z.array(cidr(6)).optional(),
              })
              .passthrough(),
          ),
        })
          .passthrough()
          .parse(r.change.after);
      }

      const valid = [
        ["no-op"],
        ["create"],
        ["read"],
        ["update"],
        ["delete"],
        ["forget"],
        ["delete", "create"],
        ["create", "delete"],
      ];
      if (!valid.some((v) => JSON.stringify(v) === JSON.stringify(actions)))
        throw new Error("Invalid Terraform action sequence");
      return {
        address: r.address,
        type: r.type,
        mode: r.mode,
        actions,
        before: r.change.before,
        after: r.change.after,
        unknown: r.change.after_unknown ?? {},
        path: `/resource_changes/${index}/change`,
      };
    }),
  };
}

export async function evaluate(input: unknown, opa = process.env.OPA ?? resolve(".tools/opa")) {
  const normalized = normalize(input);
  const policy = await readFile("policy/stackguard.rego", "utf8");
  const directory = await mkdtemp(join(tmpdir(), "stackguard-policy-"));
  const snapshot = join(directory, "policy.rego");
  await writeFile(snapshot, policy, { mode: 0o600 });
  let stdout: string;
  try {
    stdout = await new Promise<string>((accept, reject) => {
      const child = execFile(
        opa,
        ["eval", "--format=json", "--stdin-input", "--data", snapshot, "data.stackguard.deny"],
        { timeout: 10000, maxBuffer: 2_097_152, env: { PATH: process.env.PATH } },
        (error, output) => (error ? reject(error) : accept(output)),
      );
      child.stdin?.end(JSON.stringify(normalized));
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
  const envelope = z
    .object({
      result: z
        .array(z.object({ expressions: z.array(z.object({ value: z.array(findingSchema) })) }))
        .length(1),
    })
    .parse(JSON.parse(stdout));
  const findings = envelope.result[0]?.expressions[0]?.value;
  if (!findings) throw new Error("Undefined policy decision");
  findings.sort((a, b) =>
    `${a.address}:${a.rule}:${a.path}`.localeCompare(`${b.address}:${b.rule}:${b.path}`),
  );
  return {
    schema_version: "1.0",
    decision: findings.length ? "deny" : "allow",
    plan_sha256: digest(JSON.stringify(input)),
    policy_sha256: digest(policy),
    engine: "OPA / Rego v1",
    pinned_distribution: "1.22.0",
    assessed_changes: normalized.changes.length,
    findings,
  };
}

export function reviewMarkdown(report: Awaited<ReturnType<typeof evaluate>>): string {
  const clean = (s: string) => s.replace(/[\r\n|`<>]/g, " ").replace(/@/g, "[at]");
  return [
    `## StackGuard: ${report.decision}`,
    `Plan SHA-256: \`${report.plan_sha256}\``,
    `Policy SHA-256: \`${report.policy_sha256}\``,
    "",
    ...report.findings.map(
      (f) =>
        `- **${clean(f.rule)}** ${clean(f.address)} [${f.actions.join(", ")}] at \`${clean(f.path)}\`: ${clean(f.message)}`,
    ),
  ].join("\n");
}

export const planSchema = terraform;
