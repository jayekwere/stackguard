package spacelift
import rego.v1

supported := {"aws_security_group", "aws_s3_bucket_public_access_block", "aws_s3_bucket_acl", "terraform_data"}
active(c) if { c.mode == "managed"; c.actions != ["no-op"]; c.actions != ["read"] }
item(c, rule, path, message) := {"rule":rule,"address":c.address,"path":sprintf("%s%s", [c.path,path]),"message":message,"actions":c.actions}

stackguard_deny contains item(c,"SG001",sprintf("/after/ingress/%d/cidr_blocks/%d",[i,j]),"Public ingress requires review") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some i; ingress := c.after.ingress[i]
  some j; cidr := object.get(ingress,"cidr_blocks",[])[j]
  net.cidr_contains(cidr,"0.0.0.0/0")
}
stackguard_deny contains item(c,"SG001",sprintf("/after/ingress/%d/ipv6_cidr_blocks/%d",[i,j]),"Public IPv6 ingress requires review") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some i; ingress := c.after.ingress[i]
  some j; cidr := object.get(ingress,"ipv6_cidr_blocks",[])[j]
  net.cidr_contains(cidr,"::/0")
}
stackguard_deny contains item(c,"SG002",sprintf("/after/%s",[key]),"All S3 public access block controls must be true") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_s3_bucket_public_access_block"
  c.after != null
  some key in ["block_public_acls","block_public_policy","ignore_public_acls","restrict_public_buckets"]
  object.get(c.after,key,false) != true
}
stackguard_deny contains item(c,"SG002","/actions","Deleting an S3 public access block requires a separately reviewed teardown") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_s3_bucket_public_access_block"
  c.actions == ["delete"]
}
protected_tag(c, key) if {
  tags := object.get(c.before,key,{})
  is_object(tags)
  object.get(tags,"stackguard_protected","false") == "true"
}
protection_key(c) := "tags" if { protected_tag(c,"tags") }
protection_key(c) := "tags_all" if { not protected_tag(c,"tags"); protected_tag(c,"tags_all") }
stackguard_deny contains item(c,"SG003",sprintf("/before/%s/stackguard_protected",[key]),"Deleting or forgetting a protected resource requires a separately reviewed change") if {
  some c in normalized.changes
  active(c)
  some action in c.actions
  action in {"delete","forget"}
  key := protection_key(c)
}
is_unknown(value) if { walk(value, [_, leaf]); leaf == true }
is_unknown(value) if {
  walk(value, [_, leaf])
  not is_boolean(leaf)
  not is_array(leaf)
  not is_object(leaf)
}
stackguard_deny contains item(c,"SG004",sprintf("/after_unknown/%s",[key]),"Security relevant attribute is unknown") if {
  some c in normalized.changes
  active(c)
  c.type != "terraform_data"
  some key in ["acl","block_public_acls","block_public_policy","ignore_public_acls","restrict_public_buckets"]
  is_unknown(object.get(c.unknown,key,false))
}
stackguard_deny contains item(c,"SG004","/after_unknown/ingress","Ingress security attributes are unknown") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  value := object.get(c.unknown,"ingress",false)
  is_unknown(value)
  not is_array(value)
}
stackguard_deny contains item(c,"SG004",sprintf("/after_unknown/ingress/%d",[i]),"Ingress entry is unknown") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some i; entry := c.unknown.ingress[i]
  is_unknown(entry)
  not is_object(entry)
}
stackguard_deny contains item(c,"SG004",sprintf("/after_unknown/ingress/%d/%s",[i,key]),"Ingress security attribute is unknown") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some i; entry := c.unknown.ingress[i]
  some key in ["cidr_blocks","ipv6_cidr_blocks","from_port","to_port","protocol","self","security_groups","prefix_list_ids"]
  is_unknown(object.get(entry,key,false))
}
stackguard_deny contains item(c,"SG005","/after","Resource type has no reviewed policy coverage") if {
  some c in normalized.changes
  active(c)
  not c.type in supported
}
stackguard_deny contains item(c,"SG006","/after/acl","Public S3 ACL is prohibited") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_s3_bucket_acl"
  c.after.acl in {"public-read","public-read-write","authenticated-read"}
}
stackguard_deny contains item(c,"SG007","/after","Required policy attributes are absent or malformed") if {
  some c in normalized.changes
  active(c)
  c.after != null
  c.type == "aws_security_group"
  not is_array(object.get(c.after,"ingress",null))
}
stackguard_deny contains item(c,"SG007","/after/acl","Required ACL attribute is absent or malformed") if {
  some c in normalized.changes
  active(c)
  c.after != null
  c.type == "aws_s3_bucket_acl"
  not is_string(object.get(c.after,"acl",null))
}

stackguard_deny contains item(c,"SG008","/after/ingress","Ingress entry is malformed") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  not is_object(rule)
}
stackguard_deny contains item(c,"SG008","/after/ingress","Ingress CIDR collection is malformed") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  some key in ["cidr_blocks","ipv6_cidr_blocks"]
  value := object.get(rule,key,[])
  not is_array(value)
}
stackguard_deny contains item(c,"SG008","/after/ingress","Ingress CIDR is malformed") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  some key in ["cidr_blocks","ipv6_cidr_blocks"]
  some cidr in object.get(rule,key,[])
  not net.cidr_is_valid(cidr)
}

stackguard_deny contains item(c,"SG008","/after/ingress","Ingress CIDR uses the wrong address family") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  some cidr in object.get(rule,"cidr_blocks",[])
  not net.cidr_contains("0.0.0.0/0",cidr)
}
stackguard_deny contains item(c,"SG008","/after/ingress","Ingress CIDR uses the wrong address family") if {
  some c in normalized.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  some cidr in object.get(rule,"ipv6_cidr_blocks",[])
  not net.cidr_contains("::/0",cidr)
}


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
deny contains "SG000: Previous values are missing" if { some r in input.terraform.resource_changes; some action in r.change.actions; action in {"delete","forget"}; r.change.before == null }
deny contains "SG000: State removal has planned values" if { some r in input.terraform.resource_changes; r.change.actions in [["delete"],["forget"]]; r.change.after != null }

# Source adapter for local evaluation. Build the standalone hosted bundle before attaching.
normalized := {"schema_version":"1.0","changes":[{
  "address":r.address,"type":r.type,"mode":r.mode,"actions":r.change.actions,
  "before":r.change.before,"after":r.change.after,"unknown":object.get(r.change,"after_unknown",{}),
  "path":sprintf("/terraform/resource_changes/%d/change",[i])
} | some i; r := input.terraform.resource_changes[i]]}
deny contains sprintf("%s: %s (%s)",[f.rule,f.message,f.address]) if {
  findings := stackguard_deny
  some f in findings
}

deny contains "SG000: Duplicate resource address" if { some i, j; i < j; input.terraform.resource_changes[i].address == input.terraform.resource_changes[j].address }
