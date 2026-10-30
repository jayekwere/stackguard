package stackguard
import rego.v1

supported := {"aws_security_group", "aws_s3_bucket_public_access_block", "aws_s3_bucket_acl", "terraform_data"}
active(c) if { c.mode == "managed"; c.actions != ["no-op"]; c.actions != ["read"] }
item(c, rule, path, message) := {"rule":rule,"address":c.address,"path":sprintf("%s%s", [c.path,path]),"message":message}

deny contains item(c,"SG001","/after/ingress","Public ingress requires review") if {
  some c in input.changes
  active(c)
  c.type == "aws_security_group"
  some ingress in c.after.ingress
  some cidr in object.get(ingress,"cidr_blocks",[])
  cidr == "0.0.0.0/0"
}
deny contains item(c,"SG001","/after/ingress","Public IPv6 ingress requires review") if {
  some c in input.changes
  active(c)
  c.type == "aws_security_group"
  some ingress in c.after.ingress
  "::/0" in object.get(ingress,"ipv6_cidr_blocks",[])
}
deny contains item(c,"SG002","/after","All S3 public access block controls must be true") if {
  some c in input.changes
  active(c)
  c.type == "aws_s3_bucket_public_access_block"
  c.after != null
  some key in ["block_public_acls","block_public_policy","ignore_public_acls","restrict_public_buckets"]
  object.get(c.after,key,false) != true
}
deny contains item(c,"SG003","/before","Destroying a protected resource requires a separately reviewed change") if {
  some c in input.changes
  active(c)
  "delete" in c.actions
  object.get(object.get(c.before,"tags",{}),"stackguard_protected","false") == "true"
}
deny contains item(c,"SG004","/after_unknown","Security relevant attributes are unknown") if {
  some c in input.changes
  active(c)
  c.type != "terraform_data"
  c.unknown != {}
  some key in ["ingress","acl","block_public_acls","block_public_policy","ignore_public_acls","restrict_public_buckets"]
  value := object.get(c.unknown,key,false)
  value != false
  value != []
  value != {}
}
deny contains item(c,"SG005","/after","Resource type has no reviewed policy coverage") if {
  some c in input.changes
  active(c)
  not c.type in supported
}
deny contains item(c,"SG006","/after/acl","Public S3 ACL is prohibited") if {
  some c in input.changes
  active(c)
  c.type == "aws_s3_bucket_acl"
  c.after.acl in {"public-read","public-read-write","authenticated-read"}
}
deny contains item(c,"SG007","/after","Required policy attributes are absent or malformed") if {
  some c in input.changes
  active(c)
  c.after != null
  c.type == "aws_security_group"
  not is_array(object.get(c.after,"ingress",null))
}
deny contains item(c,"SG007","/after/acl","Required ACL attribute is absent or malformed") if {
  some c in input.changes
  active(c)
  c.after != null
  c.type == "aws_s3_bucket_acl"
  not is_string(object.get(c.after,"acl",null))
}

deny contains item(c,"SG008","/after/ingress","Ingress entry is malformed") if {
  some c in input.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  not is_object(rule)
}
deny contains item(c,"SG008","/after/ingress","Ingress CIDR collection is malformed") if {
  some c in input.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  some key in ["cidr_blocks","ipv6_cidr_blocks"]
  value := object.get(rule,key,[])
  not is_array(value)
}
deny contains item(c,"SG008","/after/ingress","Ingress CIDR is malformed") if {
  some c in input.changes
  active(c)
  c.type == "aws_security_group"
  some rule in c.after.ingress
  some key in ["cidr_blocks","ipv6_cidr_blocks"]
  some cidr in object.get(rule,key,[])
  not net.cidr_is_valid(cidr)
}
