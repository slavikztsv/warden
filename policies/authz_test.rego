package warden.authz_test

import data.warden.authz
import future.keywords.every
import future.keywords.if
import future.keywords.in

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
}

principal := {
    "agent_id": "triage-bot",
    "task_id": "4711",
    "purpose": "support-triage",
    "allowed_tools": ["read_document", "query_customers", "http_fetch"],
    "counterparties": ["customer:8812"],
}

clean_state := {"data_classes_held": [], "rows_returned_so_far": 0}

tainted_state := {"data_classes_held": ["pii"], "rows_returned_so_far": 1}

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
        "target": {"kind": "db", "estimated_rows": 10312},
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
        "target": {"kind": "db", "estimated_rows": 1},
        "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 50},
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_allows_a_read_inside_the_bound if {
    authz.allow with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "estimated_rows": 1},
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
        "target": {"kind": "db"},
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
        "target": {"kind": "db", "estimated_rows": 5000000000},
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
        "task_state": {"data_classes_held": [["pii"]], "rows_returned_so_far": 0},
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
        "target": {"kind": "db", "estimated_rows": 5000000},
        "task_state": {"data_classes_held": [], "rows_returned_so_far": -4999999950},
    }
        with data.purposes as mock_data.purposes
        with data.limits as mock_data.limits
}

test_denies_a_negative_row_estimate if {
    "input.malformed" in authz.deny_reasons with input as {
        "principal": principal,
        "action": {"type": "tool_call", "tool": "query_customers"},
        "target": {"kind": "db", "estimated_rows": -999999999},
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
        "target": {"kind": "db", "estimated_rows": 5000000},
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
test_shipped_data_denies_pii_to_every_allowlisted_host if {
	every host in data.purposes["support-triage"].egress_allow {
		"egress.pii_sink" in authz.deny_reasons with input as {
			"principal": shipped_principal,
			"action": {"type": "tool_call", "tool": "http_fetch"},
			"target": {"kind": "http", "host": host, "port": 443, "path": "/"},
			"task_state": tainted_state,
		}
	}
}

test_shipped_data_approves_no_http_sink_for_pii if {
	count(data.purposes["support-triage"].pii_approved_sinks) == 0
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
