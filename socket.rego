package socket

import future.keywords

default allow := false

replacements[key] := value if {
	some k, _ in input.labels

	s := split(k, ":")

	key := concat("", ["[[", concat(":", array.slice(s, 0, count(s) - 1)), "]]"])
	value := s[count(s) - 1]
}

egress_replacements[key] := value if {
	some k, _ in input.remote.labels

	s := split(k, ":")

	key := concat("", ["[[", concat(":", array.slice(s, 0, count(s) - 1)), "]]"])
	value := s[count(s) - 1]
}

replace_selectors(p, _) := policy if {
	not p.certificate.workloadID
	policy := p
}

replace_selectors(p, r) := policy if {
	p.certificate.workloadID

	wid := strings.replace_n(r, p.certificate.workloadID)

	spiffe_id_path_regex := `^(?:\/?(?:(?:[[:alnum:]][a-z0-9\-_]*[[:alnum:]]|[[:alnum:]]+)\.)*(?:[a-z-_0-9]*[[:alnum:]]))*$`

	policy := object.union(
		p,
		{"certificate": {
			"workloadID": wid,
			"workloadIDIsValid": regex.match(spiffe_id_path_regex, wid),
		}},
	)
}

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
	is_subset(input.labels, selectorset)

	policy := replace_selectors(
		object.remove(
			object.union(
				p,
				{"matched_selectors": selectorset},
			),
			["selectors"],
		),
		replacements,
	)
}

matching_policies_wo_egresses contains policy if {
	some p in matching_policies
	policy := object.remove(p, ["egress"])
}

egresses contains result if {
	some p in matching_policies
	some k, egress in p.egress
	some selectorset in egress.selectors
	is_subset(input.remote.labels, selectorset)

	e := replace_selectors(
		object.union(
			object.remove(egress, ["selectors"]),
			{"matched_selectors": selectorset},
		),
		object.union(replacements, egress_replacements),
	)
	result := object.union(object.remove(p, ["egress", "selectors"]), {"egress": e})
}

allow := {"policies_with_egress": egresses, "policies": matching_policies_wo_egresses}
