# Contracts

Runtime schemas are authoritative. The exported schema documents Terraform plan version 1.2 input structure. Normalization also validates lifecycle action sequences, required before/after values, unique resource addresses and supported security attribute shapes. Rego applies coverage, unknown-value and policy rules. The standalone Spacelift envelope has its own validation. This stateless local evaluator has no account, tenant store or role-transition schema. See the README and negative tests.
