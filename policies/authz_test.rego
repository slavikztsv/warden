package warden.authz_test

import data.warden.authz
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
