package socket

import future.keywords

default allow := false

policy_without_selectors(policy) := object.remove(policy, ["selectors"])

is_subset(super, sub) if {
	sub_set := {value | some value, _ in sub}
	super_set := {value | some value, _ in super}
	c := sub_set & super_set
	c == sub_set
}

matching_policies contains policy if {
	some p in data.policies
	some selectorset in p.selectors
	is_subset(input.selectors, selectorset)

	policy := object.remove(object.union(p, {"matched_selectors": selectorset}), ["selectors"])
}

matching_policies_wo_egresses contains policy if {
	some p in matching_policies
	policy := object.remove(p, ["egress"])
}

# egresses contains result if {
# 	some p in matching_policies
# 	not p.egress
# 	result := {"policy": object.remove(p, ["egress", "selectors"])}
# }

# egresses contains result if {
# 	some p in matching_policies
# 	count(p.egress) == 0
# 	result := {"policy": object.remove(p, ["egress", "selectors"])}
# }

egresses contains result if {
	some p in matching_policies
	some k, egress in p.egress
	some selectorset in egress.selectors
	is_subset(input.remote.selectors, selectorset)

	e := object.union(object.remove(egress, ["selectors"]), {"matched_selectors": selectorset})
	result := object.union(object.remove(p, ["egress", "selectors"]), {"egress": e})
}

allow := {"policies_with_egress": egresses, "policies": matching_policies_wo_egresses}
