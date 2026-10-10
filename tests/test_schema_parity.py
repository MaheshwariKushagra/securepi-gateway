#!/usr/bin/env python3
"""
SecurePi Gateway - schema.sql and SCHEMA_MIGRATIONS agree (Audit10Oct Q2).

There are two schema authorities: app/schema.sql builds a fresh database,
and app/ingest.py's SCHEMA_MIGRATIONS brings an older live database up to
date. Every change has to be made in both. These tests fail if one is
forgotten: whatever a migration adds must already be in a fresh schema, and
running the migrations on a fresh database must change nothing.

Run via `make test`, or directly: python3 -m unittest tests.test_schema_parity -v
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402  (also puts app/ on the path)

import ingest  # noqa: E402


def _schema(conn):
    return sorted((r[0], r[1], r[2]) for r in conn.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL"))


class SchemaParityTests(unittest.TestCase):
    def test_everything_a_migration_adds_is_in_a_fresh_schema(self):
        conn = fixtures.temp_db()
        checked = 0
        for stmt in ingest.SCHEMA_MIGRATIONS:
            stmt = " ".join(stmt.split())
            m = re.match(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", stmt)
            if m:
                columns = [r[1] for r in conn.execute("PRAGMA table_info(%s)" % m.group(1))]
                self.assertIn(m.group(2), columns, stmt)
                checked += 1
                continue
            m = re.match(r"CREATE (?:UNIQUE )?(TABLE|INDEX) IF NOT EXISTS (\w+)", stmt)
            if m:
                found = conn.execute("SELECT 1 FROM sqlite_master WHERE type=? AND name=?",
                                     (m.group(1).lower(), m.group(2))).fetchone()
                self.assertIsNotNone(found, stmt)
                checked += 1
        self.assertGreater(checked, 10)

    def test_migrating_a_fresh_database_changes_nothing(self):
        conn = fixtures.temp_db()
        before = _schema(conn)
        ingest.apply_migrations(conn)
        self.assertEqual(_schema(conn), before)


if __name__ == "__main__":
    unittest.main()
