# Authorization for agent tool calls and network egress.
#
# deny_reasons is the single source of truth; allow is its negation. This
# guarantees the rule reported in the audit log is genuinely the reason the
# request failed, rather than a parallel set of rules that can drift.
package warden.authz

# `if`, `contains`, `in` and `every` are the default language from OPA v1.0
# onward; `import future.keywords.*` was the 0.x opt-in and is obsolete.
# `import rego.v1` is the migration form: it enables all of them, REJECTS the
# pre-1.0 syntax they replaced, and is accepted as a no-op by OPA 1.x — so this
# file is valid on the pinned engine and on every version after it.
import rego.v1

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

default safe_target_subjects := null

safe_target_subjects := input.target.subjects

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

# R7 depends on this being an array. An absent or wrong-typed `subjects` would
# make `some subject in safe_target_subjects` iterate nothing, so the rule
# would not fire and the read would be approved -- the same fail-open shape as
# the six before it. Validated rather than defaulted, so a broker that stops
# sending the field is a loud denial and not a silent hole.
deny_reasons contains "input.malformed" if {
	input.target.kind == "db"
	not is_array(safe_target_subjects)
}

deny_reasons contains "input.malformed" if {
	input.target.kind == "mail"
	not is_array(safe_target_recipients)
}

# R1b — tool/target agreement and value sanity. Three fail-opens lived here.
#
# First: R5's row check used to key off `action.tool`, but the estimated_rows
# shape check above keys off `target.kind == "db"`. A db-reading tool call
# carrying a mismatched, non-db target therefore skipped validation AND left
# R5's arithmetic undefined, so an unbounded read was approved. Pin each
# tool to its target.
#
# Second: `is_number` accepts negatives, and the bound is a sum. A negative
# `rows_returned_so_far` made the total smaller than the limit — a 5,000,000
# row read evaluated to allow. Counts are cardinalities; they cannot be
# negative.
#
# Third — the pairing check below now reads "each tool's target" from the
# deployment's declared catalog (data.tools) instead of a literal map. The
# literal tool-name-to-target-kind map that lived here was the last place
# the product knew a tool name, and replacing it is where this
# generalization can fail open. The obvious spelling DOES:
#
#   expected := data.tools[safe_action_tool].target_kind
#   not input.target.kind == expected
#
# `:=` with an undefined right-hand side makes the assignment undefined, so
# the body is undefined and the rule contributes NO deny reason -- the exact
# shape the R1c comment below documents. Measured on OPA 1.19.0 against the
# shipped data.json before `tools` existed: combined with R5 keyed on target
# kind, a 5,000,000-row read carrying a mislabelled target evaluated to
# allow:true with an empty deny_reasons set. Only the rule-level `default`
# mechanism substitutes reliably when the primary definition is undefined at
# any depth.
#
# Written against the safe_* accessors, which are always defined, so the
# negated-equality form is reliable here.
#
# is_object and is_string below are belt-and-braces, not independently
# necessary today: deleting either one alone left `opa test` at 53/53. Every
# malformed-catalog shape in the suite (array, absent tool, null entry,
# misspelled key) already makes the *lookup itself* undefined -- data.tools
# indexed by a string when it is an array, or a missing key, or `.target_kind`
# on `null` -- so safe_tool_catalog / safe_expected_target_kind fall back to
# their `default` regardless of these two calls. Nor does a DEFINED
# wrong-type target_kind need is_string: tried a catalog entry with
# target_kind 42, is_string deleted -- the pairing rule below still denied,
# because R0 guarantees input.target.kind is always a string and Rego never
# considers a string equal to a number. Given R0's invariant, is_string(kind)
# has no case left to catch. They stay because they keep these two accessors
# honest to the file's safe_* idiom -- an always-defined value of the
# DECLARED type, not just any defined value -- which is what the rest of this
# file relies on to reason about each accessor locally, without re-deriving
# what upstream rules already guarantee.
default safe_tool_catalog := {}

safe_tool_catalog := catalog if {
	catalog := data.tools
	is_object(catalog)
}

default safe_expected_target_kind := null

safe_expected_target_kind := kind if {
	kind := safe_tool_catalog[safe_action_tool].target_kind
	is_string(kind)
}

# The PAIRING rule below is what actually catches an undeclared tool today,
# on its own: safe_expected_target_kind defaults to null for any tool not in
# the catalog, and R0 (top of file) already guarantees input.target.kind is
# one of doc/db/http/mail and therefore never null -- so a valid target kind
# can never equal null, and the pairing rule fires without help. Verified by
# deleting the is_string rule immediately below, on its own: opa test stayed
# at 53/53, including the undeclared-tool test.
#
# The is_string rule is kept anyway, as defense in depth against that R0
# coupling being weakened later (a target kind added without updating R0,
# say), not because it is doing the work today. Together the two rules
# REPLACE the four-name allowlist that used to live here, with no tool name
# embedded in either.
#
# The tool_call guard is load-bearing on both rules: egress carries no
# action.tool, so safe_action_tool is null and an ungated rule denies every
# CONNECT.
deny_reasons contains "input.malformed" if {
	input.action.type == "tool_call"
	not is_string(safe_expected_target_kind)
}

deny_reasons contains "input.malformed" if {
	input.action.type == "tool_call"
	not input.target.kind == safe_expected_target_kind
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

# R1c — the same undefined-propagation defect, on the `data` side this time.
# R0/R1/R1b validate the *input* exhaustively; nothing validated `data`, and
# the three rules below dereference it. A missing key there is undefined, the
# enclosing body is undefined, no deny reason is produced, and the request is
# allowed. Verified with `opa eval` against the real authz.rego: dropping
# `limits` approved a 5,000,000-row read; dropping `pii_approved_sinks`
# approved PII to an unapproved host; dropping `egress_allow` approved a host
# never allowlisted; mapping a purpose to `null` approved all three — every one
# `allow:true` with an empty deny_reasons set, so the audit log records a clean
# allow rather than an error.
#
# Note `not host in <undefined collection>` does NOT fire, exactly as
# `not <undefined> in {...}` does not: membership is a builtin call, and a
# builtin is never invoked when an argument is undefined. The allowlists are
# not saved by negation-as-failure any more than the row limit is.
#
# No test could have caught this: every case in authz_test.rego mocks both
# `data.purposes` and `data.limits`, so the shipped data.json shape is never
# exercised. Today that file is correct and mounted read-only, but a purpose
# added without `pii_approved_sinks` silently disables the control this whole
# project exists to demonstrate — for that purpose only, with no error.
#
# Fixed the same way the input side was: always-defined accessors with
# fail-closed defaults. An absent or wrong-typed allowlist becomes the empty
# set, so nothing is allowlisted and the existing rule denies under its own
# correct reason. The type guard matters as much as the default — Rego compares
# across types by total ordering, so a string "50" limit would make
# `total > limit` false and fail open just as silently.
default safe_egress_allow := []

safe_egress_allow := hosts if {
	hosts := data.purposes[input.principal.purpose].egress_allow
	is_array(hosts)
}

default safe_pii_approved_sinks := []

safe_pii_approved_sinks := hosts if {
	hosts := data.purposes[input.principal.purpose].pii_approved_sinks
	is_array(hosts)
}

# -1, not 0: with no configured limit, no read is permitted at all.
default safe_max_rows_per_task := -1

safe_max_rows_per_task := limit if {
	limit := data.limits.max_rows_per_task
	is_number(limit)
}

# R2 — the tool must be in the token's capability set.
deny_reasons contains "tools.allowed" if {
	input.action.type == "tool_call"
	not input.action.tool in input.principal.allowed_tools
}

# R3 — network destinations must be allowlisted for this purpose.
deny_reasons contains "egress.allowlist" if {
	input.target.kind == "http"
	not input.target.host in safe_egress_allow
}

# R4 — a task holding PII may only reach approved sinks. This is a data-flow
# control: it does not care what the destination's reputation is.
deny_reasons contains "egress.pii_sink" if {
	input.target.kind == "http"
	"pii" in input.task_state.data_classes_held
	not input.target.host in safe_pii_approved_sinks
}

# R5 — blast radius. Accumulates across the whole task, so many small reads
# hit the same ceiling as one large one.
#
# Keyed on target kind, not tool name. Safe ONLY because R1b now denies,
# unconditionally and fail-closed, any tool_call whose target.kind disagrees
# with the deployment's catalog -- see safe_expected_target_kind above. If
# that guarantee weakens, this rule stops firing on a mislabelled call and
# nothing else catches it.
#
# It also closes a hole the tool-name form had: a SECOND database tool
# escaped the row budget entirely, because this named exactly one.
deny_reasons contains "rows.bounded" if {
	input.target.kind == "db"
	total := input.task_state.rows_returned_so_far + input.target.estimated_rows
	total > safe_max_rows_per_task
}

# R7 — scope. R5 bounds how MANY customer records a task may read; this bounds
# WHICH. A task for one declared customer could read another, undeclared
# customer's record one row at a time: inside the budget, inside policy,
# recorded as a clean allow. `counterparties` governed mail alone and never
# applied to reads, which is least privilege on quantity but not on subject.
#
# Only applies when the task declared its subjects. A token naming no
# counterparties has no subject scope to enforce, and R5 remains its only read
# control -- that is explicit, not an oversight.
#
# `"*"` is the broker's marker for a read that reaches an unbounded set (filter
# by plan, or no filter). It can never appear in a counterparty list, so such a
# read is out of scope by construction rather than by a second rule. Deliberately
# ranked BELOW rows.bounded in the reported-rule precedence, so a bulk read is
# still reported as the volume breach it primarily is.
#
# Keyed on target kind for the same reason as R5, and with the same
# dependency on R1b.
deny_reasons contains "rows.scope" if {
	input.target.kind == "db"
	count(safe_counterparties) > 0
	some subject in safe_target_subjects
	not subject in safe_counterparties
}

# R6 — mail may only go to counterparties the task declared up front.
#
# Keyed on target kind for the same reason as R5, and with the same
# dependency on R1b.
deny_reasons contains "mail.counterparty" if {
	input.target.kind == "mail"
	some recipient in input.target.recipients
	not recipient in input.principal.counterparties
}
