"""Synthetic customer records. No real personal data ever enters this repo."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL,
    email   TEXT NOT NULL,
    plan    TEXT NOT NULL,
    balance REAL NOT NULL
);
"""


def seed_customers(path: Path, count: int = 10312) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA)
        connection.execute("DELETE FROM customers")
        rows = [
            (
                8812 + offset,
                f"Synthetic Person {offset:05d}",
                f"person{offset:05d}@example.invalid",
                ["free", "pro", "enterprise"][offset % 3],
                round(10.0 + offset * 1.37, 2),
            )
            for offset in range(count)
        ]
        connection.executemany(
            "INSERT INTO customers (id, name, email, plan, balance) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        connection.commit()
    finally:
        connection.close()
