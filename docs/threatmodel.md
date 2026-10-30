# StackGuard threat model

## Overview

Intended use: the runnable repository implementation and its documented local demo. The user requested an open-source implementation with honest security scope. This model describes inspected source, not a security certification or a claim of complete audit coverage.

Data flow: Terraform JSON --> Zod normalization --> private policy snapshot --> OPA --> evidence report --> CLI exit gate.

| Component/source | Responsibility |
| --- | --- |
| `src/main.ts:5` | CLI check/demo/serve, exit 0/1/2 |
| `src/engine.ts:51` | Terraform evidence normalization and action/value validation |
| `src/engine.ts:126` | Bounded OPA invocation using exact policy bytes |
| `policy/spacelift.rego:4` | Separate fail-closed Spacelift envelope adapter |
| `src/io.ts:21` | Loopback HTTP workbench and fixed static asset mapping |

| Deployment or workflow | Resource/configuration and effective location | Readers, writers or recipients | Enforcing control or unknown |
| --- | --- | --- | --- |
| CLI/web policy process | OPA override or .tools/opa; fixed policy/stackguard.rego copied into a private OS temporary directory | Trusted operator and OPA; normalized plan travels on stdin | No shell, 10-second timeout, 2 MiB output bound; policy snapshot removed after use |
| Web listener | HOST or 127.0.0.1; PORT or 8080 | Reachable clients, no accounts | Host allowlist, same-origin POST, JSON content type and 1 MiB streaming limit |
| Spacelift gate | Both policy packages attached by an operator; input.terraform envelope | External policy runner | Local adapter tests exist; real stack attachment remains unverified |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets: Plan decision integrity, resource-address evidence, policy bytes and plan/policy identity. Real plan data is confidential even when marked sensitive by Terraform.

Untrusted JSON passes known-field and semantic validation before a fixed OPA query. Imported Terraform metadata is retained but does not select executables or policy paths. The environment-controlled executable and repository policy are trusted operator configuration. A client cannot choose them through HTTP. The Spacelift adapter has its own input rejection rules and invokes the same policy package.

Host administrators, private configuration owners and trusted repository maintainers can alter code, files and private state. They are trusted. An ordinary input author does not gain those capabilities by supplying JSON. Public demo credentials represent synthetic roles in one trusted local demonstration. The local stateless TypeScript evaluators do not establish authenticated service tenancy; the Python services derive tenancy from trusted identities. External assertions retain their stated trust prerequisites.

No apply pipeline, branch protection, live AWS account, or real Spacelift stack has been verified. Policy scope is deliberately narrow. Combined narrower public CIDRs, runtime drift and full provider semantics are outside the current rule set.

## Attack Surface, Mitigations, and Attacker Stories

These are threat scenarios and review obligations, not reported vulnerabilities. Priority describes plausible impact if the named control fails in its stated deployment. The source table above identifies the actual consumers and controls.

| Priority | Scenario and potential capability gain | Existing source-established controls | Additional mitigation or prerequisite |
| --- | --- | --- | --- |
| High | A plan author supplies unknown or malformed security attributes to obtain an allow. | Schema/action checks and SG004/SG007/SG008 reject or deny; unassessed changed managed types deny. | Enforce the exact approved plan artifact in the consuming pipeline. |
| High | A malformed Spacelift envelope is mistaken for an empty clean plan. | Adapter explicitly denies invalid, incomplete, duplicated and inconsistent changes; negative adapter tests run real OPA. | Validate stack attachment and real policy input before deployment. |
| Medium | A remote client consumes local evaluation resources or accesses plan data. | Loopback default, host/origin controls, size and subprocess bounds; no authenticated remote service. | Keep loopback exposure and private input files. |
| Low | Markup in an address alters a rendered review. | Review Markdown neutralizes markup and mentions; browser uses textContent. | Retain output encoding in new renderers. |

## Severity Calibration (Critical, High, Medium, Low)

Critical would require a credible unauthenticated path to broad privileged external execution or equivalent cross-tenant compromise. This model does not establish such a path. A fictional sandbox state change is not critical cloud compromise.

High includes a reachable authorization, approval or gate bypass that grants a materially new capability over another tenant or a deployment decision, with the required privileged consuming workflow present. An input author changing their own local file is a counterexample.

Medium includes bounded local denial of service, decision-fidelity loss or evidence misbinding under realistic deployment prerequisites. Merely changing trusted policy as its administrator is a counterexample.

Low includes limited presentation/integrity confusion without a new privileged operation. A string that is safely rendered as text is controlled behavior, not an injection finding. Confidence depends on source and executable evidence, independently of impact.

One fresh-context independent read-only architecture review informed this model. Source changed during construction; the parent rechecked the controls and source anchors after the reported discrepancies were fixed. Verified negatives are recorded in tests and verification artifacts. External account behavior remains unverified wherever stated.

Repository: https://github.com/jayekwere/stackguard
Version: 0dd8bf06d25c990875bce1d46eccaebbd8a97b5c
