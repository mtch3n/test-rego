package policies.rbac

import data.values.rbac

default allow := false

default is_admin := false

allow {
	some role_name, policy_name, rule

	user_has_role[role_name]

	policy := rbac.role_grants[role_name].policies[policy_name]

	r := rbac.policies[policy].rules[rule]

	r.effect == "allow"
	contains(r.verbs, input.verb)
	glob.match(r.path, [], input.path)
}

is_admin {
	u := rbac.user_roles[input.user].roles[_]
	u == "admin"
}

user_has_role[role_name] {
	role_name := rbac.user_roles[input.user].roles[_]
}

contains(d, elem) {
	d[_] = elem
}
