# StackGuard threat model

## Overview

StackGuard evaluates Terraform plan JSON through TypeScript normalization and a fixed OPA/Rego query. It exposes a CLI, an offline demo and a stateless local HTTP evaluator. A separate build step produces one self-contained Spacelift plan policy. The program does not apply infrastructure or publish its own GitHub App results. One independent fresh-context read-only architecture review informed this model; source-backed architecture and separately recorded runtime evidence are distinguished from security-audit coverage.

| Component | Source and role |
| --- | --- |
| CLI and HTTP startup | `src/main.ts:5` |
| Plan normalization | `src/engine.ts:51` |
| OPA execution and evidence | `src/engine.ts:126` |
| Core security rules | `policy/stackguard.rego:4` |
| Spacelift source adapter and deployable bundle | `policy/spacelift.rego:4`, `scripts/build-spacelift.ts:3`, `integrations/spacelift/policy.rego:160` |
| Verified OPA installer | `scripts/install-opa.mjs:4` |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| CLI check/demo | Plan JSON | Check argument or samples/unsafe-plan.json | Selected local JSON file or cwd/samples/unsafe-plan.json | Evaluator and OPA through normalized stdin | 1 MiB CLI input check, strict normalizer | `src/main.ts:11`, `src/main.ts:14`, `src/engine.ts:51` |
| Host evaluator | OPA executable | OPA environment override or resolved .tools/opa | Trusted override or cwd/.tools/opa | Evaluator host | No shell, fixed arguments/query, 10-second timeout, 2 MiB output bound, PATH-only child environment | `src/engine.ts:126`, `src/engine.ts:135`; override authenticity is operator-owned |
| Host evaluator | Evaluated policy snapshot | Read cwd/policy/stackguard.rego, private temporary directory, policy.rego | OS tmpdir/stackguard-policy-random/policy.rego | OPA and trusted host | 0600 file, private directory, finally cleanup; exact read bytes also hashed | `src/engine.ts:128`, `src/engine.ts:129`, `src/engine.ts:143` |
| Compose evaluation | Executable and temporary policy | WORKDIR /app, copied binary/policy, /tmp tmpfs | /app/.tools/opa, /app/policy/stackguard.rego, /tmp/stackguard-policy-random/policy.rego | UID 10001 Node/OPA processes | Read-only root, dropped capabilities, no-new-privileges; 64 MiB noexec/nosuid /tmp | `Dockerfile:10`, `Dockerfile:17`, `Dockerfile:18`, `compose.yaml:8`; binary executes outside /tmp |
| Setup/build | OPA distribution | Supported platform/architecture, pinned v1.22.0 URL and SHA-256 | .tools/opa mode 0755 for supported macOS arm64 or Linux architectures | Trusted setup host | Unsupported-platform rejection and hardcoded download digest | `scripts/install-opa.mjs:4`, `scripts/install-opa.mjs:9`, `scripts/install-opa.mjs:16` |
| CLI check | Review export | Optional output argument | Operator-selected Markdown file and JSON stdout | Operator or separately configured publisher | Findings, digests, markup/mention neutralization | `src/main.ts:17`, `src/engine.ts:170`; no GitHub write occurs |
| Host HTTP | Stateless evaluator | HOST/PORT or defaults | 127.0.0.1:8080; no persisted plan store | Reachable clients | Host/Origin checks, JSON content type, 1 MiB body bound, fixed static assets, CSP/no-store | `src/io.ts:10`, `src/io.ts:34`, `src/io.ts:49` |
| Compose HTTP | Evaluator listener | Container HOST=0.0.0.0 and loopback publication | Container 0.0.0.0:8080; host 127.0.0.1:8080 | Container peers and loopback clients | Compose publication plus application controls and resource limits | `Dockerfile:9`, `compose.yaml:4`; direct Docker exposure is operator-configured |
| Spacelift | Conditional external plan gate | Core plus source adapter transformed into a single package spacelift bundle | integrations/spacelift/policy.rego, attached as one plan policy | Spacelift runner and stack operators | Envelope/change/completeness/duplicate validation and bundled core rules | `scripts/build-spacelift.ts:3`, `integrations/spacelift/policy.rego:160`, `integrations/spacelift/policy.rego:190` |
| Verification CI | Evidence export | Policy/bundle checks, demo/browser/container tests, artifact upload | verification-evidence with 14-day retention | GitHub artifact readers | contents:read, checkout credentials disabled, synthetic inputs | `.github/workflows/verify.yml:7`, `.github/workflows/verify.yml:17`, `.github/workflows/verify.yml:28`; real plans must remain private |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets are confidential plan contents, policy integrity, the exact evaluated decision and its evidence, executable authority and the separately configured deployment gate. A plan author controls resource addresses, attributes and supported metadata. A reachable HTTP client can request unauthenticated evaluation. Neither can select the executable or policy through the HTTP contract. Policy administrators, host operators, environment owners and trusted maintainers already control their respective code and execution authority and are outside isolation (`SECURITY.md:6`, `src/engine.ts:126`).

Normalization validates plan format, completeness, actions, duplicate addresses and security-relevant attributes before OPA receives normalized stdin. The subprocess uses a fixed policy snapshot and query without a shell. OPA output crosses a strict finding/result schema; undefined output fails. CLI check returns 1 for deny and 2 for invalid input or evaluation error. JSON and Markdown output preserve resource addresses, planned actions, rule IDs and exact field pointers while neutralizing review markup (`src/engine.ts:51`, `src/engine.ts:126`, `src/engine.ts:146`, `src/engine.ts:170`, `src/main.ts:18`).

Plain remote deletion of an S3 public-access-block resource denies SG002; state-only forget and known replacement final states retain their documented scope (`policy/stackguard.rego:32`). Prior protection in either tags or tags_all denies destructive changes with one pointer to the proving field (`policy/stackguard.rego:38`, `policy/stackguard.rego:45`). Native Spacelift simulation of the saved updated bundle separately confirmed SG001, SG002 and SG003 plus a safe private-ingress control; exact editor readback matched its policy fingerprint (`docs/spacelift-hardening-verification.json:1`). These synthetic native simulations do not represent applied infrastructure.

Policy scope is deliberately narrow: active managed AWS security groups, S3 public-access blocks, S3 ACLs, protected deletion/forget tags and unsupported-type rejection. Data/no-op/read changes are outside active enforcement; terraform_data is supported. Unknown security attributes deny, but harmless computed descriptions do not become security findings. Aggregates of narrower CIDRs, runtime drift and full provider semantics are outside the implemented rules (`policy/stackguard.rego:4`, `policy/stackguard.rego:59`, `policy/stackguard.rego:90`).

Spacelift isolates policy modules. The authoritative hosted deployment artifact is the single generated bundle, not two separately attached source packages. Its input.terraform envelope is independently validated before mapping into bundled core rules (`scripts/build-spacelift.ts:3`, `integrations/spacelift/policy.rego:160`, `integrations/spacelift/policy.rego:178`, `integrations/spacelift/policy.rego:195`).

Runtime verification context, recorded separately in `docs/spacelift-verification.json:1`: a dedicated hosted stack using OpenTofu 1.13.2 in the Terraform vendor and AWS provider 6.20.0 denied the public-ingress fixture with SG001. The private-CIDR comparison passed plan checks, reached UNCONFIRMED and was discarded without applying. Dummy provider credentials and no cloud integration were used. This proves those hosted plan-policy decisions at the recorded commit; it does not verify a real AWS deployment, branch protection, all Spacelift workflows or future stack configuration.

Reports hash JSON.stringify of parsed input and the exact policy bytes used. The JSON digest is not the binary .tfplan digest. An apply pipeline must separately bind approved JSON to the exact binary plan and enforce the gate before apply. No such apply pipeline or branch protection is installed by this repository. The report's pinned_distribution string does not authenticate an arbitrary OPA override (`src/engine.ts:158`, `src/engine.ts:164`, `README.md:64`).

Private paths, key/environment files and snapshots are excluded from build context, but arbitrary sensitive plan filenames still need operator-controlled placement (`.dockerignore:11`). Direct evaluate callers own their input-byte budget; HTTP/CLI ingestion have separate limits. The web evaluator has no authenticated multi-tenant storage. External runner resource budgets and mandatory policy attachment remain platform/operator responsibilities. No certification, general cloud posture guarantee or production throughput claim is made.

## Attack Surface, Mitigations, and Attacker Stories

These scenarios are review hypotheses, not validated findings.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High | Incomplete or malformed plan is accepted as clean | A consuming deployment gate trusts the result | Unsafe deployment within covered scope | Format/completeness/action/address checks and fail-closed OPA output | Preserve negative tests and mandatory gate consumption | `src/engine.ts:51`, `src/engine.ts:146` |
| High | Hosted adapter is deployed without its core rules | Operator attaches source fragments independently | Missing external enforcement | One generated self-contained bundle, bundle-only tests, native hosted denial | Attach exactly the reviewed bundle and verify each intended stack | `scripts/build-spacelift.ts:3`, `integrations/spacelift/policy.rego:190` |
| High | Approved JSON is swapped before applying another binary plan | External pipeline permits artifact substitution | Deployment outside reviewed change | Exact parsed-plan and policy evidence; no false binary binding claim | Bind binary and JSON artifacts in the consuming apply workflow | `src/engine.ts:158`, `README.md:64` |
| Medium | Plan strings inject markup or mentions into exported review | Reviewer or external publisher renders the export | Misleading review or unwanted mentions | Review neutralization, structured finding output | Preserve plain-data rendering and explicit publication authority | `src/engine.ts:170` |
| Medium | Submitted plan consumes shared evaluator resources | Reachable listener or broad input | Availability degradation | Ingress and subprocess limits, bounded output, container limits | Apply deployment concurrency limits; avoid public demo exposure | `src/io.ts:10`, `src/engine.ts:135`, `compose.yaml:10` |
| Medium | Real plan values enter public artifacts | Operator supplies sensitive plans to public export paths | Confidentiality loss | Synthetic CI inputs and build exclusions | Keep real plan artifacts private and separately authorize publication | `.github/workflows/verify.yml:29`, `.dockerignore:11` |
| Low | Trusted executable override is described as verified distribution | Operator chooses another binary | Misleading provenance | Explicit trusted-override limitation; installer verifies only its pinned download | Authenticate overrides operationally and record their actual identity | `src/engine.ts:126`, `src/engine.ts:164` |

## Severity Calibration (Critical, High, Medium, Low)

Critical requires a demonstrated broad authority compromise or widespread deployment impact with concrete external prerequisites; malformed local demo JSON alone is insufficient. High applies to a reachable bypass of a mandatory deployment gate or approved-artifact binding in an actual consuming workflow. Medium covers bounded confidentiality, availability or review-integrity effects. Low covers constrained local defects and misleading metadata without new authority. A trusted policy administrator changing policy is already-authorized control. Hosted acceptance of two fixtures narrows uncertainty for those decisions and does not establish coverage of every resource type or deployment path.

Repository: https://github.com/jayekwere/stackguard
Version: e803602d0c514196db494705e45655fc0d10ca33
