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
