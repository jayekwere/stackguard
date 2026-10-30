import { readFile, writeFile } from "node:fs/promises";
import { evaluate, reviewMarkdown } from "./engine.js";
import { load, serve } from "./io.js";

async function main(): Promise<void> {
  const command = process.argv[2] ?? "serve";
  if (command === "serve") {
    await serve("StackGuard", await load("samples/unsafe-plan.json"), evaluate);
    return;
  }
  const path = command === "demo" ? "samples/unsafe-plan.json" : process.argv[3];
  if (!path || !["demo", "check"].includes(command))
    throw new Error("Usage: stackguard check PLAN.json [REVIEW.md] | demo | serve");
  const text = await readFile(path, "utf8");
  if (Buffer.byteLength(text) > 1_048_576) throw new Error("Plan exceeds 1 MiB");
  const result = await evaluate(JSON.parse(text));
  console.log(JSON.stringify(result, null, 2));
  if (process.argv[4]) await writeFile(process.argv[4], reviewMarkdown(result));
  if (command === "check" && result.decision === "deny") process.exitCode = 1;
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Evaluation failed");
  process.exitCode = 2;
});
