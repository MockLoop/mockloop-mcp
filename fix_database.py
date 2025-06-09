#!/usr/bin/env python3
# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Fix the database migration issue by ensuring the base request_logs table is created.
"""

from pathlib import Path
import sqlite3
import sys

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def fix_database(db_path):
    """Fix the database by ensuring all tables are created properly."""

    # Connect to database
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Check existing tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = {row[0] for row in cursor.fetchall()}

    # If request_logs table doesn't exist, create it manually
    if "request_logs" not in existing_tables:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                process_time_ms INTEGER,
                client_host TEXT,
                client_port TEXT,
                headers TEXT,
                query_params TEXT,
                request_body TEXT,
                response_body TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_id TEXT,
                test_scenario TEXT,
                correlation_id TEXT,
                user_agent TEXT,
                response_size INTEGER,
                is_admin BOOLEAN DEFAULT 0
            )
        """)
        conn.commit()

    # Check final state
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    {row[0] for row in cursor.fetchall()}

    conn.close()
    return True


if __name__ == "__main__":
    # Fix the test database
    db_path = Path("generated_mocks/final_integration_test_server/db/request_logs.db")
    if db_path.exists():
        fix_database(db_path)
    else:
        pass
