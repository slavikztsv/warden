from __future__ import annotations

import sqlite3

import pytest

from broker.adapters.sql import SqlAdapter
from broker.config.loader import ConfigError

BINDING = {
    "table": "customers",
    "columns": ["id", "name", "email", "plan", "balance"],
    "subject_column": "id",
    "subject_prefix": "customer:",
    "subject_type": "integer",
    "default_column": "plan",
    "unfiltered": ["", "all", "*"],
    "data_class": "pii",
}


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "customers.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT,"
        " plan TEXT, balance REAL)"
    )
    connection.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?)",
        [(8810 + i, f"P{i}", f"p{i}@example.invalid",
          "pro" if i % 2 else "free", 1.0 * i) for i in range(10)],
    )
    connection.commit()
    connection.close()
    return path


def adapter(db, **overrides):
    return SqlAdapter(binding={**BINDING, "db": str(db), **overrides}, client=None)


def test_describe_returns_the_true_cardinality_not_a_capped_one(db):
    """Bounded means no rows materialise, NOT that the count is capped. A
    LIMIT-wrapped count would print rows≈51 where the demo prints rows≈10312
    while rows.bounded still fires -- no test would notice."""
    assert adapter(db).describe({"filter": "all"}).estimated_rows == 10


def test_describe_materialises_no_rows(db, monkeypatch):
    """The security property, asserted directly rather than via the integer.

    sqlite3.Connection is a non-heap C type in this interpreter: neither the
    class nor an instance accepts attribute assignment (`list.append = ...`
    fails the same way), so `execute` cannot be spied by patching it in
    place. sqlite3.connect is an ordinary module attribute, so the spy wraps
    the connection there instead -- same observation, different seam.
    """
    executed = []
    real_connect = sqlite3.connect

    class SpyConnection:
        def __init__(self, real):
            self._real = real

        def execute(self, sql, *args):
            executed.append(sql)
            return self._real.execute(sql, *args)

        def close(self):
            return self._real.close()

    def spy_connect(*args, **kwargs):
        return SpyConnection(real_connect(*args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", spy_connect)
    adapter(db).describe({"filter": "all"})
    assert executed and all("COUNT(" in sql for sql in executed), executed
    assert not any("SELECT \"id\"" in sql for sql in executed), executed


def test_subject_filter_names_one_bounded_subject(db):
    target = adapter(db).describe({"filter": "id=8812"})
    assert target.estimated_rows == 1
    assert target.subjects == ("customer:8812",)


def test_every_other_filter_reaches_an_unbounded_set(db):
    for expression in ("all", "", "*", "pro"):
        assert adapter(db).describe({"filter": expression}).subjects == ("*",)


def test_the_default_column_carries_a_bare_token(db):
    assert adapter(db).describe({"filter": "pro"}).estimated_rows == 5


def test_a_malformed_subject_value_raises_value_error(db):
    """app.py maps ValueError to input.malformed. Any other exception lands
    in the backend-fault branch, which audits nothing at all."""
    with pytest.raises(ValueError):
        adapter(db).describe({"filter": "id=not-a-number"})


def test_execute_returns_the_declared_columns_and_data_class(db):
    result = adapter(db).execute({"filter": "id=8812"})
    import json
    rows = json.loads(result.content)
    assert rows == [{"id": 8812, "name": "P2", "email": "p2@example.invalid",
                     "plan": "free", "balance": 2.0}]
    assert result.rows == 1
    assert result.data_class == "pii"


def test_describe_and_execute_agree_on_the_row_count(db):
    """They must, or a decision is made about one set and taken over another."""
    for expression in ("all", "pro", "id=8812"):
        assert (adapter(db).describe({"filter": expression}).estimated_rows
                == adapter(db).execute({"filter": expression}).rows)


@pytest.mark.parametrize("key,value", [
    ("table", "customers; DROP TABLE customers"),
    ("table", 'customers" --'),
    ("subject_column", "id OR 1=1"),
    ("default_column", "plan;--"),
])
def test_a_non_identifier_binding_is_rejected_at_load(db, key, value):
    """Identifiers cannot be bound parameters, so they are validated once at
    construction rather than sanitised at every use."""
    with pytest.raises(ConfigError, match=key):
        adapter(db, **{key: value})


def test_a_non_identifier_column_is_rejected_at_load(db):
    with pytest.raises(ConfigError, match="columns"):
        adapter(db, columns=["id", "name); DROP TABLE customers; --"])


def test_target_kind_is_db(db):
    assert adapter(db).target_kind == "db"
