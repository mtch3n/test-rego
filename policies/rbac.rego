package policies.rbac

import data.acls

default allow := false

default is_admin := false

allow {
	some role_name, policy_name, rule

	user_has_role[role_name]

	policy := acls.role_grants[role_name].policies[policy_name]

	r := acls.policies[policy].rules[rule]

	r.effect == "allow"
	contains(r.verbs, input.verb)
	glob.match(r.path, [], input.path)
}

is_admin {
	u := acls.user_roles[input.user].roles[_]
	u == "admin"
}

user_has_role[role_name] {
	role_name := acls.user_roles[input.user].roles[_]
}

test_roles[ur]{
    ur := acls.user_roles[_].roles[_]
}

test_roles2[ur2]{
    ur2 := data.acls.user_roles[_].roles[_]
}

contains(d, elem) {
	d[_] = elem
}
