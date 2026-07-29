# Authorization for agent tool calls and network egress.
#
# deny_reasons is the single source of truth; allow is its negation. This
# guarantees the rule reported in the audit log is genuinely the reason the
# request failed, rather than a parallel set of rules that can drift.
package warden.authz

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny_reasons) == 0

# R0 — input recognition. Without these, "allow unless a rule objects" is not
# deny-by-default: an input that matches no rule produces no deny reasons and
# is therefore allowed. An empty input {} evaluated to allow:true before these
# rules existed. Anything whose shape we do not recognize is denied here.
# Written as conjoined negated equalities, NOT as `not X in {A, B}`. Those are
# not equivalent: when X is undefined, `not X in {...}` does not fire, so the
# missing-field case — the exact case these rules exist to catch — would slip
# through. Verified with `opa eval` on 0.70.0: the set form yields [] where the
# equality form yields ["fired"].
deny_reasons contains "input.malformed" if {
	not input.action.type == "tool_call"
	not input.action.type == "egress"
}

deny_reasons contains "input.malformed" if {
	not input.target.kind == "doc"
	not input.target.kind == "db"
	not input.target.kind == "http"
	not input.target.kind == "mail"
}

# R1 — shape validation. Every rule below assumes a well-formed input, and in
# Rego that assumption is dangerous: a reference to a missing field is
# undefined, an undefined body contributes no deny reason, and the rule that
# depended on it silently does not fire. Omitting `task_state` alone was enough
# to disable the pii_sink rule entirely. Validate the shape once here so the
# authorization rules can rely on it.
#
# `not is_string(input.principal.purpose)` (the brief's literal form) has the
# same defect R0 already found in `not X in {...}`, one level deeper: is_*()
# are ordinary builtin calls, and a builtin call is simply never invoked when
# one of its arguments is undefined — the call expression itself becomes
# undefined, not false, and `not` over that does not fire. Verified with `opa
# eval` on 0.70.0 against all ten fields: every `not is_string(...)` /
# `not is_array(...)` / `not is_number(...)` / `not data.purposes[...]` check
# silently failed to fire whenever the underlying field was entirely absent
# (as opposed to present-but-wrong-type, which they do catch). Wrapping the
# call in `==` does not help either — `type_name(x) == "string"` has the same
# undefined-argument problem, because the LHS is still a call.
# The `default X := null / X := input....` pair below is not a call: it is
# Rego's rule-level default mechanism, which substitutes null precisely when
# the primary definition is undefined for any reason at any depth. Each type
# check below runs against that always-defined accessor instead of the raw
# path, so a wrong-type value and a wholly absent field are caught the same
# way.
default safe_purpose := null

safe_purpose := input.principal.purpose

default safe_allowed_tools := null

safe_allowed_tools := input.principal.allowed_tools

default safe_counterparties := null

safe_counterparties := input.principal.counterparties

default safe_data_classes_held := null

safe_data_classes_held := input.task_state.data_classes_held

default safe_rows_returned_so_far := null

safe_rows_returned_so_far := input.task_state.rows_returned_so_far

default safe_action_tool := null

safe_action_tool := input.action.tool

default safe_target_host := null

safe_target_host := input.target.host

default safe_target_estimated_rows := null

safe_target_estimated_rows := input.target.estimated_rows

default safe_target_recipients := null

safe_target_recipients := input.target.recipients

deny_reasons contains "input.malformed" if not is_string(safe_purpose)

deny_reasons contains "input.malformed" if not is_array(safe_allowed_tools)

deny_reasons contains "input.malformed" if not is_array(safe_counterparties)

deny_reasons contains "input.malformed" if not is_array(safe_data_classes_held)

deny_reasons contains "input.malformed" if not is_number(safe_rows_returned_so_far)

# An unknown purpose has no allowlist, so nothing could be checked against it.
deny_reasons contains "input.malformed" if not data.purposes[safe_purpose]

deny_reasons contains "input.malformed" if {
	input.action.type == "tool_call"
	not is_string(safe_action_tool)
}

deny_reasons contains "input.malformed" if {
	input.target.kind == "http"
	not is_string(safe_target_host)
}

deny_reasons contains "input.malformed" if {
	input.target.kind == "db"
	not is_number(safe_target_estimated_rows)
}

deny_reasons contains "input.malformed" if {
	input.target.kind == "mail"
	not is_array(safe_target_recipients)
}

# R1b — tool/target agreement and value sanity. Two more fail-opens lived here.
#
# First: R5's row check keys off `action.tool`, but the estimated_rows shape
# check above keys off `target.kind == "db"`. A `query_customers` call carrying
# a `doc` target therefore skipped validation AND left R5's arithmetic
# undefined, so an unbounded read was approved. Pin each tool to its target.
#
# Second: `is_number` accepts negatives, and the bound is a sum. A negative
# `rows_returned_so_far` made the total smaller than the limit — a 5,000,000
# row read evaluated to allow. Counts are cardinalities; they cannot be
# negative.
#
# Written against the safe_* accessors, which are always defined, so the
# negated-equality form is reliable here.
expected_target_kind := {
	"read_document": "doc",
	"query_customers": "db",
	"http_fetch": "http",
	"send_email": "mail",
}

deny_reasons contains "input.malformed" if {
	input.action.type == "tool_call"
	not safe_action_tool == "read_document"
	not safe_action_tool == "query_customers"
	not safe_action_tool == "http_fetch"
	not safe_action_tool == "send_email"
}

deny_reasons contains "input.malformed" if {
	input.action.type == "tool_call"
	expected := expected_target_kind[safe_action_tool]
	not input.target.kind == expected
}

# Egress is by definition a network action, so it must carry an http target.
# Without this, `{"type": "egress"}` with a `db` target sailed past everything:
# R2/R5 key off `tool_call`, R3/R4 key off `target.kind == "http"`, so a
# 5,000,000,000-row db "egress" with an empty capability set was approved. The
# same held for a `mail` target and a `doc` target — the guard is on the target
# kind, not on any one wrong kind.
deny_reasons contains "input.malformed" if {
	input.action.type == "egress"
	not input.target.kind == "http"
}

# The taint check is `"pii" in data_classes_held`, which is exact-match on
# elements. A nested array [["pii"]] therefore holds PII without matching, and
# egress to an unapproved sink was allowed. Entries must be strings.
deny_reasons contains "input.malformed" if {
	some entry in safe_data_classes_held
	not is_string(entry)
}

deny_reasons contains "input.malformed" if {
	is_number(safe_rows_returned_so_far)
	safe_rows_returned_so_far < 0
}

deny_reasons contains "input.malformed" if {
	is_number(safe_target_estimated_rows)
	safe_target_estimated_rows < 0
}

# R2 — the tool must be in the token's capability set.
deny_reasons contains "tools.allowed" if {
	input.action.type == "tool_call"
	not input.action.tool in input.principal.allowed_tools
}

# R3 — network destinations must be allowlisted for this purpose.
deny_reasons contains "egress.allowlist" if {
	input.target.kind == "http"
	not input.target.host in data.purposes[input.principal.purpose].egress_allow
}

# R4 — a task holding PII may only reach approved sinks. This is a data-flow
# control: it does not care what the destination's reputation is.
deny_reasons contains "egress.pii_sink" if {
	input.target.kind == "http"
	"pii" in input.task_state.data_classes_held
	not input.target.host in data.purposes[input.principal.purpose].pii_approved_sinks
}

# R5 — blast radius. Accumulates across the whole task, so many small reads
# hit the same ceiling as one large one.
deny_reasons contains "rows.bounded" if {
	input.action.tool == "query_customers"
	total := input.task_state.rows_returned_so_far + input.target.estimated_rows
	total > data.limits.max_rows_per_task
}

# R6 — mail may only go to counterparties the task declared up front.
deny_reasons contains "mail.counterparty" if {
	input.action.tool == "send_email"
	some recipient in input.target.recipients
	not recipient in input.principal.counterparties
}
