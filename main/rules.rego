package main

import data.policies.rbac

default allow := false

allow {
	rbac.allow == true
}
