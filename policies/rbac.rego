package policies.rbac

default allow := false

default is_admin := false

allow {
	some role_name, policy_name, rule

	user_has_role[role_name]

	policy := data.role_grants[role_name].policies[policy_name]

	r := data.policies[policy].rules[rule]

	r.effect == "allow"
	contains(r.verbs, input.verb)
	glob.match(r.path, [], input.path)
}

is_admin {
	u := data.user_roles[input.user].roles[_]
	u == "admin"
}

user_has_role[role_name] {
	role_name := data.user_roles[input.user].roles[_]
}

test_roles[ur]{
    ur := data.user_roles[_].roles[_]
}

contains(d, elem) {
	d[_] = elem
}
