package spacelift
import rego.v1

valid_envelope if {
  is_object(input.terraform)
  is_array(input.terraform.resource_changes)
  object.get(input.terraform,"errored",false) == false
  object.get(input.terraform,"complete",true) != false
  object.get(input.terraform,"deferred_changes",[]) == []
}
object_or_null(value) if { is_object(value) }
object_or_null(value) if { value == null }
valid_change(r) if {
  is_string(r.address)
  is_string(r.type)
  r.mode in {"managed","data"}
  r.change.actions in [["no-op"],["read"],["create"],["update"],["delete"],["forget"],["create","delete"],["delete","create"]]
  object_or_null(r.change.before)
  object_or_null(r.change.after)
  is_object(object.get(r.change,"after_unknown",{}))
}
deny contains "SG000: Invalid or incomplete Spacelift plan envelope" if { not valid_envelope }
deny contains "SG000: Invalid resource change" if { some r in input.terraform.resource_changes; not valid_change(r) }
deny contains "SG000: Planned values are missing" if { some r in input.terraform.resource_changes; some a in r.change.actions; a in {"create","update"}; r.change.after == null }
deny contains "SG000: Previous values are missing" if { some r in input.terraform.resource_changes; "delete" in r.change.actions; r.change.before == null }

# Evaluate alongside stackguard.rego. The adapter accepts the documented plan envelope.
normalized := {"schema_version":"1.0","changes":[{
  "address":r.address,"type":r.type,"mode":r.mode,"actions":r.change.actions,
  "before":r.change.before,"after":r.change.after,"unknown":object.get(r.change,"after_unknown",{}),
  "path":sprintf("/terraform/resource_changes/%d/change",[i])
} | some i; r := input.terraform.resource_changes[i]]}
deny contains sprintf("%s: %s (%s)",[f.rule,f.message,f.address]) if {
  findings := data.stackguard.deny with input as normalized
  some f in findings
}

deny contains "SG000: Duplicate resource address" if { some i, j; i < j; input.terraform.resource_changes[i].address == input.terraform.resource_changes[j].address }
