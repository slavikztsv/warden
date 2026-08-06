package warden.authz_test

import data.warden.authz
import rego.v1

# NOTE: named `mock_data`, not `test_data` — `opa test` auto-discovers any
# top-level rule whose name is prefixed `test_` as a test case to run, and an
# object-valued rule fails that check. `test_data` would be silently reported
# as a failing test rather than used as a fixture.
mock_data := {
    "purposes": {"support-triage": {
        "egress_allow": ["docstore.internal", "api.anthropic.com"],
        "pii_approved_sinks": ["mailer.internal"],
    }},
    "limits": {"max_rows_per_task": 50},
    "tools": {
        "read_document": {"target_kind": "doc"},
        "query_customers": {"target_kind": "db"},
        "http_fetch": {"target_kind": "http"},
        "send_email": {"target_kind": "mail"},
    },
}

principal := {
    "agent_id": "triage-bot",
    "task_id": "4711",
    "purpose": "support-triage",
    "allowed_tools": ["read_document", "query_customers", "http_fetch"],
    "counterparties": ["customer:8812"],
}

clean_state := {"data_classes_held": [], "rows_charged_so_far": 0}

tainted_state := {"data_classes_held": ["pii"], "rows_charged_so_far": 1}

test_allows_a_permitted_tool if {
    authz.allow with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "read_document"},
        "target": {"kind": "doc"},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_a_tool_outside_the_token if {
    "tools.allowed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "send_email"},
        "target": {"kind": "mail", "recipients": ["customer:8812"]},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_an_unlisted_host if {
    "egress.allowlist" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "http_fetch"},
        "target": {"kind": "http", "host": "attacker.example", "port": 443},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# The rule that carries the demo: an allowlisted host, denied because the
# task is holding PII and this host is not an approved sink.
test_denies_pii_to_an_allowlisted_but_unapproved_sink if {
    reasons := authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "http_fetch"},
        "target": {"kind": "http", "host": "docstore.internal", "port": 443},
        "task_state": tainted_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits

    "egress.pii_sink" in reasons
    not "egress.allowlist" in reasons
}

test_allows_pii_to_an_approved_sink if {
    authz.allow with input as {
        "principal": principal,
        "action": {"type": "egress"},
        "target": {"kind": "http", "host": "mailer.internal", "port": 443},
        "task_state": tainted_state,
    }
        with data.purposes as {"support-triage": {
            "egress_allow": ["mailer.internal"],
            "pii_approved_sinks": ["mailer.internal"],
        }}
        with data.limits as {"max_rows_per_task": 50}
}

test_denies_a_bulk_read if {
    "rows.bounded" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["*"], "estimated_rows": 10312},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# Fifty one-row reads must hit the same ceiling as one fifty-row read.
test_row_bound_accumulates_across_the_task if {
    "rows.bounded" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["*"], "estimated_rows": 1},
        "task_state": {"data_classes_held": ["pii"], "rows_charged_so_far": 50},
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_allows_a_read_inside_the_bound if {
    authz.allow with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["customer:8812"], "estimated_rows": 1},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_mail_to_an_undeclared_recipient if {
    "mail.counterparty" in authz.deny_reasons with input as {
        "principal": {
            "agent_id": "triage-bot",
            "task_id": "4711",
            "purpose": "support-triage",
            "allowed_tools": ["send_email"],
            "counterparties": ["customer:8812"],
        },
        "action": {"type": "tool_call", "tool": "send_email"},
        "target": {"kind": "mail", "recipients": ["attacker@evil.example"]},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_everything_by_default if {
    not authz.allow with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "rm_minus_rf"},
        "target": {"kind": "doc"},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# R0 — the inversion (allow := no deny reasons) is not deny-by-default on its
# own. These three inputs all evaluated to allow:true before the recognition
# rules existed, which would have let a caller bypass the capability check by
# omitting a single field.
test_denies_an_action_with_no_type if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"tool": "send_email"},
        "target": {"kind": "mail", "recipients": []},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_an_egress_with_no_target_kind if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "egress"},
        "target": {},
        "task_state": tainted_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_a_completely_empty_input if {
    not authz.allow with input as {}
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# R1 — each of these omits exactly one field, and each one silently disabled
# the rule that depended on it before shape validation existed. The pii_sink
# case is the worst: dropping task_state defeated the control the whole
# project exists to demonstrate.
test_denies_when_task_state_is_missing if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "http_fetch"},
        "target": {"kind": "http", "host": "docstore.internal", "port": 443},
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_when_allowed_tools_is_missing if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": {"purpose": "support-triage", "counterparties": []},
        "action": {"type": "tool_call", "tool": "send_email"},
        "target": {"kind": "mail", "recipients": []},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_a_db_read_with_no_row_estimate if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["*"]},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_an_http_target_with_no_host if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "http_fetch"},
        "target": {"kind": "http", "port": 443},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# An egress action with a non-http target bypassed every rule at once.
test_denies_an_egress_with_a_db_target if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": {"purpose": "support-triage", "allowed_tools": [], "counterparties": []},
        "action": {"type": "egress"},
        "target": {"kind": "db", "subjects": ["*"], "estimated_rows": 5000000000},
        "task_state": tainted_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# [["pii"]] holds PII but does not match the exact-element `in` check.
test_denies_nested_data_classes if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "http_fetch"},
        "target": {"kind": "http", "host": "docstore.internal", "port": 443},
        "task_state": {"data_classes_held": [["pii"]], "rows_charged_so_far": 0},
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# R1b — a tool paired with the wrong target skipped the row check entirely.
test_denies_query_customers_with_a_non_db_target if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "doc"},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# A negative counter made the sum smaller than the bound: 5,000,000 rows
# approved because the task claimed to have already read minus five billion.
test_denies_a_negative_row_counter if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["*"], "estimated_rows": 5000000},
        "task_state": {"data_classes_held": [], "rows_charged_so_far": -4999999950},
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_a_negative_row_estimate if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["*"], "estimated_rows": -999999999},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# R1c — the data document was never validated, and all three rules that
# dereference it failed open when their key was absent. These mock a
# deliberately incomplete `data` rather than an incomplete input.
test_denies_a_bulk_read_when_the_row_limit_is_missing if {
    "rows.bounded" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["*"], "estimated_rows": 5000000},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as {}
}

test_denies_pii_when_the_approved_sink_list_is_missing if {
    "egress.pii_sink" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "http_fetch"},
        "target": {"kind": "http", "host": "docstore.internal", "port": 443},
        "task_state": tainted_state,
    }
        with data.purposes as {"support-triage": {"egress_allow": ["docstore.internal"]}}
        with data.limits as mock_data.limits
}

test_denies_a_host_when_the_egress_allowlist_is_missing if {
    "egress.allowlist" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "http_fetch"},
        "target": {"kind": "http", "host": "attacker.example", "port": 443},
        "task_state": clean_state,
    }
        with data.purposes as {"support-triage": {"pii_approved_sinks": ["mailer.internal"]}}
        with data.limits as mock_data.limits
}

test_denies_an_unknown_purpose if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": {
            "purpose": "no-such-purpose",
            "allowed_tools": ["read_document"],
            "counterparties": [],
        },
        "action": {"type": "tool_call", "tool": "read_document"},
        "target": {"kind": "doc"},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# --- Shipped-configuration tests -------------------------------------------
#
# Every test above overrides `data` with a mock, which is precisely why none
# of them could catch a defect in policies/data.json itself. These deliberately
# do NOT override it: they run the real rules against the real shipped bundle.
#
# The defect they close: data.json listed `mailer.internal` in BOTH
# `egress_allow` and `pii_approved_sinks`. Rule 6 (mail.counterparty) only
# guards `target.kind == "mail"`, so a PII-tainted
# `http_fetch("http://mailer.internal/send", body=<the PII>)` is
# `target.kind == "http"`, allowlisted, and PII-approved — it evaluated to
# allow with an EMPTY deny_reasons set. The counterparty control was
# bypassable with the demo's own token, using the demo's own tools.
#
# The configuration now states a much simpler and far more defensible
# property: PII never leaves over HTTP at all. It leaves only through the mail
# tool, to counterparties the task declared up front, where rule 6 governs it.

shipped_principal := {
	"agent_id": "triage-bot",
	"task_id": "4711",
	"purpose": "support-triage",
	"allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
	"counterparties": ["customer:8812"],
}

test_shipped_data_denies_pii_over_http_to_the_mail_host if {
	reasons := authz.deny_reasons with input as {
		"principal": shipped_principal,
		"action": {"type": "tool_call", "tool": "http_fetch"},
		"target": {"kind": "http", "host": "mailer.internal", "port": 80, "path": "/send"},
		"task_state": tainted_state,
	}

	count(reasons) > 0
	not authz.allow with input as {
		"principal": shipped_principal,
		"action": {"type": "tool_call", "tool": "http_fetch"},
		"target": {"kind": "http", "host": "mailer.internal", "port": 80, "path": "/send"},
		"task_state": tainted_state,
	}
}

# The general form of the same property, asserted against every host the
# shipped bundle allowlists rather than against one hand-picked name: a
# tainted task reaching ANY allowlisted host over HTTP is denied under
# egress.pii_sink. Adding a host to egress_allow can never again open an
# HTTP exfil path for PII without this test failing.
# Every allowlisted host refuses PII EXCEPT the model endpoint, which is an
# explicit, tested concession (see the data-boundary test below). Written as a
# sweep over the real bundle rather than one hand-picked name so a host added
# to egress_allow cannot quietly become a PII sink too.
non_pii_hosts := {host |
	some host in data.purposes["support-triage"].egress_allow
	not host in data.purposes["support-triage"].pii_approved_sinks
}

test_shipped_data_denies_pii_to_every_allowlisted_host_but_the_model if {
	count(non_pii_hosts) > 0
	every host in non_pii_hosts {
		"egress.pii_sink" in authz.deny_reasons with input as {
			"principal": shipped_principal,
			"action": {"type": "tool_call", "tool": "http_fetch"},
			"target": {"kind": "http", "host": host, "port": 443, "path": "/"},
			"task_state": tainted_state,
		}
	}
}

# Exactly one PII-approved sink, and it is the model endpoint. This is the
# smallest possible concession: a remote-model agent cannot read a customer
# record and then reason about it without that record entering its conversation
# history, so the provider is inside the data boundary or the agent is useless
# after its first PII read. Pinned at one so the list cannot grow unnoticed.
test_shipped_data_approves_exactly_one_http_sink_for_pii if {
	data.purposes["support-triage"].pii_approved_sinks == ["generativelanguage.googleapis.com"]
}

# Rule 4 guards `target.kind == "http"`, so removing every approved HTTP sink
# must leave the mail path untouched: a tainted task can still email a
# declared counterparty. Without this, the fix above would silently break the
# demo's closing beat — the task completing despite containment.
test_shipped_data_still_allows_tainted_mail_to_a_declared_counterparty if {
	authz.allow with input as {
		"principal": shipped_principal,
		"action": {"type": "tool_call", "tool": "send_email"},
		"target": {"kind": "mail", "recipients": ["customer:8812"]},
		"task_state": tainted_state,
	}
}

test_shipped_data_still_denies_tainted_mail_to_an_undeclared_counterparty if {
	"mail.counterparty" in authz.deny_reasons with input as {
		"principal": shipped_principal,
		"action": {"type": "tool_call", "tool": "send_email"},
		"target": {"kind": "mail", "recipients": ["attacker@evil.example"]},
		"task_state": tainted_state,
	}
}

# The demo's load-bearing denial, against the shipped bundle rather than a
# mock: docstore.internal IS allowlisted, and only the taint rule stops it.
test_shipped_data_denies_the_tainted_fallback_to_the_docstore if {
	reasons := authz.deny_reasons with input as {
		"principal": shipped_principal,
		"action": {"type": "tool_call", "tool": "http_fetch"},
		"target": {"kind": "http", "host": "docstore.internal", "port": 80, "path": "/feedback"},
		"task_state": tainted_state,
	}

	"egress.pii_sink" in reasons
	not "egress.allowlist" in reasons
}

# Positive control: an untainted fetch to an allowlisted host still works, so
# the tests above are not passing because everything is denied.
test_shipped_data_allows_an_untainted_fetch_to_an_allowlisted_host if {
	authz.allow with input as {
		"principal": shipped_principal,
		"action": {"type": "tool_call", "tool": "http_fetch"},
		"target": {"kind": "http", "host": "docstore.internal", "port": 80, "path": "/docs/x"},
		"task_state": clean_state,
	}
}

# The agent reaches its model provider only because that host is a declared
# destination for this purpose — switching model vendors is a policy change,
# which is the correct amount of friction. It is NOT a pii_approved_sink:
# an agent holding customer data cannot post it to the model endpoint either.
# (test_shipped_data_denies_pii_to_every_allowlisted_host already covers the
# tainted case for every host in the bundle, including this one.)
test_shipped_data_allows_the_model_endpoint_when_untainted if {
	authz.allow with input as {
		"principal": shipped_principal,
		"action": {"type": "egress"},
		"target": {"kind": "http", "host": "generativelanguage.googleapis.com", "port": 443, "path": "", "estimated_rows": 0, "recipients": []},
		"task_state": clean_state,
	}
}

test_shipped_data_denies_an_undeclared_model_endpoint if {
	"egress.allowlist" in authz.deny_reasons with input as {
		"principal": shipped_principal,
		"action": {"type": "egress"},
		"target": {"kind": "http", "host": "api.openai.com", "port": 443, "path": "", "estimated_rows": 0, "recipients": []},
		"task_state": clean_state,
	}
}

# The model endpoint is a PII-approved sink, and that is a DECISION rather than
# an oversight. A remote-model agent cannot read a customer record and then
# think about it without the record entering its conversation history, so the
# provider is either inside the data boundary or the agent stops working the
# moment it touches PII. Discovered by running a live model under the protected
# profile: the taint rule denied the agent's own next model call.
#
# This test exists so the entry cannot be removed accidentally, and so anyone
# reading the bundle sees that it was chosen.
test_shipped_data_treats_the_model_endpoint_as_inside_the_data_boundary if {
	authz.allow with input as {
		"principal": shipped_principal,
		"action": {"type": "egress"},
		"target": {"kind": "http", "host": "generativelanguage.googleapis.com", "port": 443, "path": "", "estimated_rows": 0, "recipients": []},
		"task_state": tainted_state,
	}
}

# The concession is scoped to the model endpoint alone. Every other allowlisted
# host still refuses PII — the demo's fallback beat depends on it.
test_shipped_data_does_not_extend_the_concession_to_other_hosts if {
	"egress.pii_sink" in authz.deny_reasons with input as {
		"principal": shipped_principal,
		"action": {"type": "tool_call", "tool": "http_fetch"},
		"target": {"kind": "http", "host": "docstore.internal", "port": 80, "path": "/feedback", "estimated_rows": 0, "recipients": []},
		"task_state": tainted_state,
	}
}


# --- R7: scope. R5 bounds how many records a read returns; R7 bounds which. ---
#
# The gap these close was found by running the scenario, not by reading the
# rules: a support-triage task for customer:8812 read three other customers'
# records one at a time, every one inside the budget and recorded as a clean
# allow.

test_denies_a_read_of_an_undeclared_subject if {
    "rows.scope" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["customer:9999"], "estimated_rows": 1},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_allows_a_read_of_the_declared_subject if {
    authz.allow with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["customer:8812"], "estimated_rows": 1},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# One in-scope subject does not launder an out-of-scope one alongside it.
test_denies_a_read_mixing_declared_and_undeclared_subjects if {
    "rows.scope" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {
            "kind": "db",
            "subjects": ["customer:8812", "customer:9999"],
            "estimated_rows": 2,
        },
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# "*" is the broker's marker for a read reaching an unbounded set. It can never
# appear in a counterparty list, so it is out of scope by construction.
test_denies_an_unbounded_read_as_out_of_scope if {
    "rows.scope" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["*"], "estimated_rows": 3},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# A token naming no subjects has no subject scope to enforce; R5 remains its
# only read control. Explicit, so that nobody later reads the absence as a bug.
test_scope_does_not_apply_when_no_counterparties_are_declared if {
    not "rows.scope" in authz.deny_reasons with input as {
        "principal": object.union(principal, {"counterparties": []}),
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": ["customer:9999"], "estimated_rows": 1},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# The fail-open shape that bit six times: an absent array makes `some x in ...`
# iterate nothing, so the rule never fires. It must be a malformed input, not a
# quiet allow.
test_a_db_target_without_subjects_is_malformed if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "estimated_rows": 1},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_a_db_target_with_wrong_typed_subjects_is_malformed if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "subjects": "customer:8812", "estimated_rows": 1},
        "task_state": clean_state,
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

# --- R1b: the tool/target map comes from the deployment's catalog ----------
#
# A correct data.tools mock in every case would reintroduce the blindness the
# R1c comment describes, on a new key: verified that the mechanical mock edit
# yields opa test PASS 44/44 over a policy that approves the mislabelled
# 5,000,000-row read below at runtime. These mock the catalog BROKEN, the way
# the existing R1c tests above mock an incomplete `data`.

mislabelled_db_read := {
    "principal": {
        "agent_id": "a", "task_id": "t", "purpose": "support-triage",
        "allowed_tools": ["query_customers"], "counterparties": [],
    },
    "action": {"type": "tool_call", "tool": "query_customers", "args_digest": "x"},
    "target": {
        "kind": "doc", "host": "", "port": 0, "path": "",
        "estimated_rows": 5000000, "recipients": [], "subjects": [],
    },
    "task_state": {"data_classes_held": [], "rows_charged_so_far": 0},
}

test_absent_tool_catalog_denies if {
    "input.malformed" in authz.deny_reasons with input as mislabelled_db_read
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_empty_tool_catalog_denies if {
    "input.malformed" in authz.deny_reasons with input as mislabelled_db_read
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
        with data.tools as {}
}

test_tool_absent_from_the_catalog_denies if {
    "input.malformed" in authz.deny_reasons with input as mislabelled_db_read
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
        with data.tools as {"read_document": {"target_kind": "doc"}}
}

test_null_catalog_entry_denies if {
    "input.malformed" in authz.deny_reasons with input as mislabelled_db_read
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
        with data.tools as {"query_customers": null}
}

test_array_catalog_denies if {
    "input.malformed" in authz.deny_reasons with input as mislabelled_db_read
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
        with data.tools as ["query_customers"]
}

# A hyphen is a natural TOML-to-JSON transcription slip, and it is the shape
# that fails OPEN with the naive accessor.
test_misspelled_target_kind_key_denies if {
    "input.malformed" in authz.deny_reasons with input as mislabelled_db_read
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
        with data.tools as {"query_customers": {"target-kind": "db"}}
}

# An undeclared tool must be malformed even under a PERFECTLY CORRECT catalog.
# This is what the deleted four-name allowlist did; nothing else covers it.
test_undeclared_tool_denies_under_a_correct_catalog if {
    "input.malformed" in authz.deny_reasons with input as object.union(
        mislabelled_db_read,
        {"action": {"type": "tool_call", "tool": "exfiltrate", "args_digest": "x"}},
    )
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
        with data.tools as mock_data.tools
}

# Egress carries no action.tool, so safe_action_tool is null. An ungated rule
# makes every CONNECT malformed and the agent loses all model-API egress.
allowlisted_egress := {
    "principal": principal,
    "action": {"type": "egress"},
    "target": {
        "kind": "http", "host": "docstore.internal", "port": 443, "path": "",
        "estimated_rows": 0, "recipients": [],
    },
    "task_state": clean_state,
}

test_egress_is_unaffected_by_the_catalog if {
    authz.allow with input as allowlisted_egress
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
        with data.tools as {}
}

test_egress_is_unaffected_by_an_absent_catalog if {
    authz.allow with input as allowlisted_egress
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}
