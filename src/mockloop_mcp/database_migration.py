"""
Database migration utilities for MockLoop MCP servers.
Provides schema versioning and migration capabilities.
"""

from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Any


class DatabaseMigrator:
    """Handles database schema migrations for MockLoop servers."""

    def __init__(self, db_path: str):
        """Initialize the migrator with a database path."""
        self.db_path = Path(db_path)
        self.migrations = self._get_migrations()

    def _get_migrations(self) -> dict[int, dict[str, Any]]:
        """Define all available migrations."""
        return {
            0: {
                "description": "Create base request_logs table",
                "sql": [
                    """CREATE TABLE IF NOT EXISTS request_logs (
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
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )"""
                ],
            },
            1: {
                "description": "Add Phase 1 enhancement columns",
                "sql": [
                    "ALTER TABLE request_logs ADD COLUMN session_id TEXT",
                    "ALTER TABLE request_logs ADD COLUMN test_scenario TEXT",
                    "ALTER TABLE request_logs ADD COLUMN correlation_id TEXT",
                    "ALTER TABLE request_logs ADD COLUMN user_agent TEXT",
                    "ALTER TABLE request_logs ADD COLUMN response_size INTEGER",
                    "ALTER TABLE request_logs ADD COLUMN is_admin BOOLEAN DEFAULT 0",
                ],
            },
            2: {
                "description": "Create test sessions table",
                "sql": [
                    """CREATE TABLE IF NOT EXISTS test_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT UNIQUE NOT NULL,
                        name TEXT,
                        description TEXT,
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ended_at TIMESTAMP,
                        metadata TEXT,
                        total_requests INTEGER DEFAULT 0,
                        success_rate REAL DEFAULT 0.0
                    )"""
                ],
            },
            3: {
                "description": "Create performance metrics table",
                "sql": [
                    """CREATE TABLE IF NOT EXISTS performance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        endpoint TEXT NOT NULL,
                        method TEXT NOT NULL,
                        avg_response_time REAL,
                        min_response_time REAL,
                        max_response_time REAL,
                        request_count INTEGER,
                        error_count INTEGER,
                        time_window TEXT
                    )"""
                ],
            },
            4: {
                "description": "Create mock scenarios table (Phase 2 preparation)",
                "sql": [
                    """CREATE TABLE IF NOT EXISTS mock_scenarios (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        description TEXT,
                        config TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )"""
                ],
            },
            5: {
                "description": "Create enhanced performance metrics table (Phase 2 Part 4)",
                "sql": [
                    """CREATE TABLE IF NOT EXISTS performance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_id INTEGER,
                        response_time_ms REAL NOT NULL,
                        memory_usage_mb REAL,
                        cpu_usage_percent REAL,
                        database_queries INTEGER DEFAULT 0,
                        cache_hits INTEGER DEFAULT 0,
                        cache_misses INTEGER DEFAULT 0,
                        request_size_bytes INTEGER DEFAULT 0,
                        response_size_bytes INTEGER DEFAULT 0,
                        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (request_id) REFERENCES request_logs (id)
                    )"""
                ],
            },
            6: {
                "description": "Create enhanced test sessions table (Phase 2 Part 4)",
                "sql": [
                    """CREATE TABLE IF NOT EXISTS test_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT UNIQUE NOT NULL,
                        scenario_name TEXT,
                        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        end_time TIMESTAMP,
                        total_requests INTEGER DEFAULT 0,
                        avg_response_time REAL DEFAULT 0.0,
                        status TEXT DEFAULT 'active',
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )"""
                ],
            },
            7: {
                "description": "Create MCP audit logging tables for compliance tracking",
                "sql": [
                    """DROP TABLE IF EXISTS mcp_audit_logs""",
                    """CREATE TABLE IF NOT EXISTS mcp_audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT UNIQUE NOT NULL,
                        session_id TEXT NOT NULL,
                        user_id TEXT,
                        timestamp TEXT NOT NULL,
                        operation_type TEXT NOT NULL,
                        operation_name TEXT NOT NULL,
                        operation_version TEXT,
                        input_parameters TEXT,
                        output_data TEXT,
                        execution_time_ms REAL,
                        memory_usage_mb REAL,
                        cpu_usage_percent REAL,
                        data_sources TEXT,
                        content_hash TEXT,
                        data_classification TEXT,
                        retention_policy TEXT,
                        context_state_before TEXT,
                        context_state_after TEXT,
                        error_details TEXT,
                        compliance_tags TEXT,
                        gdpr_applicable BOOLEAN DEFAULT 0,
                        ccpa_applicable BOOLEAN DEFAULT 0,
                        data_subject_id TEXT,
                        processing_purpose TEXT,
                        legal_basis TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP
                    )""",
                    """CREATE INDEX IF NOT EXISTS idx_mcp_audit_session
                       ON mcp_audit_logs(session_id)""",
                    """CREATE INDEX IF NOT EXISTS idx_mcp_audit_timestamp
                       ON mcp_audit_logs(timestamp)""",
                    """CREATE INDEX IF NOT EXISTS idx_mcp_audit_operation
                       ON mcp_audit_logs(operation_type, operation_name)""",
                    """CREATE INDEX IF NOT EXISTS idx_mcp_audit_user
                       ON mcp_audit_logs(user_id)""",
                    """CREATE INDEX IF NOT EXISTS idx_mcp_audit_expires
                       ON mcp_audit_logs(expires_at)""",
                    """DROP TABLE IF EXISTS mcp_data_lineage""",
                    """CREATE TABLE IF NOT EXISTS mcp_data_lineage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        source_identifier TEXT NOT NULL,
                        source_metadata TEXT,
                        transformation_applied TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (entry_id) REFERENCES mcp_audit_logs (entry_id)
                    )""",
                    """DROP TABLE IF EXISTS mcp_compliance_events""",
                    """CREATE TABLE IF NOT EXISTS mcp_compliance_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        regulation TEXT NOT NULL,
                        compliance_status TEXT NOT NULL,
                        details TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (entry_id) REFERENCES mcp_audit_logs (entry_id)
                    )""",
                ],
            },
            8: {
                "description": "Create SchemaPin integration tables",
                "sql": [
                    """CREATE TABLE IF NOT EXISTS schemapin_key_pins (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tool_id TEXT UNIQUE NOT NULL,
                        domain TEXT NOT NULL,
                        public_key_pem TEXT NOT NULL,
                        pinned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_verified TIMESTAMP,
                        verification_count INTEGER DEFAULT 0,
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""",
                    """CREATE TABLE IF NOT EXISTS schemapin_verification_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT NOT NULL,
                        tool_id TEXT NOT NULL,
                        domain TEXT,
                        verification_result TEXT NOT NULL,
                        signature_valid BOOLEAN,
                        key_pinned BOOLEAN,
                        policy_action TEXT,
                        error_details TEXT,
                        execution_time_ms REAL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (entry_id) REFERENCES mcp_audit_logs (entry_id)
                    )""",
                    """CREATE INDEX IF NOT EXISTS idx_schemapin_tool_id ON schemapin_key_pins(tool_id)""",
                    """CREATE INDEX IF NOT EXISTS idx_schemapin_domain ON schemapin_key_pins(domain)""",
                    """CREATE INDEX IF NOT EXISTS idx_schemapin_verification_entry ON schemapin_verification_logs(entry_id)""",
                    """CREATE INDEX IF NOT EXISTS idx_schemapin_verification_tool ON schemapin_verification_logs(tool_id)""",
                ],
            },
        }

    def get_current_version(self) -> int:
        """Get the current database schema version."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Check if schema_version table exists
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='schema_version'
            """)

            if not cursor.fetchone():
                # Schema version table doesn't exist, create it
                cursor.execute("""
                    CREATE TABLE schema_version (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        description TEXT
                    )
                """)
                conn.commit()
                conn.close()
                return 0

            # Get the latest version
            cursor.execute("SELECT MAX(version) FROM schema_version")
            result = cursor.fetchone()
            version = result[0] if result and result[0] is not None else 0

            conn.close()
            return version

        except Exception:
            return 0

    def apply_migrations(self, target_version: int | None = None) -> bool:
        """
        Apply migrations up to the target version.

        Args:
            target_version: Version to migrate to. If None, applies all available migrations.

        Returns:
            True if successful, False otherwise.
        """
        current_version = self.get_current_version()

        if target_version is None:
            target_version = max(self.migrations.keys()) if self.migrations else 0

        if current_version >= target_version:
            return True

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Apply migrations in order, starting from current version
            # If current_version is 0 and we have migration 0, apply it
            start_version = current_version if current_version > 0 else 0
            for version in range(start_version, target_version + 1):
                if version not in self.migrations:
                    continue

                migration = self.migrations[version]

                try:
                    # Execute all SQL statements for this migration
                    for sql_statement in migration["sql"]:
                        # Special handling for ALTER TABLE statements
                        if sql_statement.strip().upper().startswith("ALTER TABLE"):
                            # Check if table exists before altering
                            table_name = sql_statement.split()[2]  # Extract table name

                            # Validate table name to prevent SQL injection
                            if not table_name.isidentifier():
                                raise ValueError(f"Invalid table name: {table_name}")

                            cursor.execute(
                                """
                                SELECT name FROM sqlite_master
                                WHERE type='table' AND name=?
                            """,
                                (table_name,),
                            )

                            if not cursor.fetchone():
                                continue

                            # Check if column already exists
                            if "ADD COLUMN" in sql_statement.upper():
                                column_name = (
                                    sql_statement.split("ADD COLUMN")[1]
                                    .strip()
                                    .split()[0]
                                )

                                # Validate column name to prevent SQL injection
                                if not column_name.isidentifier():
                                    raise ValueError(
                                        f"Invalid column name: {column_name}"
                                    )

                                # Use safe PRAGMA query with validated table name
                                cursor.execute(f"PRAGMA table_info({table_name})")
                                existing_columns = {col[1] for col in cursor.fetchall()}

                                if column_name in existing_columns:
                                    continue

                        cursor.execute(sql_statement)

                    # Record the migration
                    cursor.execute(
                        "INSERT INTO schema_version (version, description) VALUES (?, ?)",
                        (version, migration["description"]),
                    )

                    conn.commit()

                except Exception:
                    conn.rollback()
                    conn.close()
                    return False

            conn.close()
            return True

        except Exception:
            return False

    def rollback_migration(self, target_version: int) -> bool:
        """
        Rollback to a specific version (limited support).

        Note: This is a basic implementation. Complex rollbacks may require
        manual intervention or data backup/restore.
        """
        current_version = self.get_current_version()

        if target_version >= current_version:
            return False

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Remove migration records for versions above target
            cursor.execute(
                "DELETE FROM schema_version WHERE version > ?", (target_version,)
            )

            conn.commit()
            conn.close()

            return True

        except Exception:
            return False

    def get_migration_status(self) -> dict[str, Any]:
        """Get detailed migration status information."""
        current_version = self.get_current_version()
        available_migrations = list(self.migrations.keys())
        latest_available = max(available_migrations) if available_migrations else 0

        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get applied migrations
            cursor.execute(
                "SELECT version, applied_at, description FROM schema_version ORDER BY version"
            )
            applied_migrations = [dict(row) for row in cursor.fetchall()]

            conn.close()

        except Exception:
            applied_migrations = []

        return {
            "current_version": current_version,
            "latest_available": latest_available,
            "needs_migration": current_version < latest_available,
            "applied_migrations": applied_migrations,
            "available_migrations": [
                {
                    "version": v,
                    "description": self.migrations[v]["description"],
                    "applied": v <= current_version,
                }
                for v in sorted(available_migrations)
            ],
        }

    def backup_database(self, backup_path: str | None = None) -> str:
        """Create a backup of the database before migration."""
        if backup_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.db_path.stem}_backup_{timestamp}.db"

        backup_path = Path(backup_path)

        try:
            # Simple file copy for SQLite
            import shutil

            shutil.copy2(self.db_path, backup_path)
            return str(backup_path)

        except Exception:
            raise


def migrate_database(db_path: str, target_version: int | None = None) -> bool:
    """
    Convenience function to migrate a database.

    Args:
        db_path: Path to the SQLite database
        target_version: Version to migrate to (None for latest)

    Returns:
        True if successful, False otherwise
    """
    migrator = DatabaseMigrator(db_path)
    return migrator.apply_migrations(target_version)


def get_database_status(db_path: str) -> dict[str, Any]:
    """
    Get migration status for a database.

    Args:
        db_path: Path to the SQLite database

    Returns:
        Dictionary with migration status information
    """
    migrator = DatabaseMigrator(db_path)
    return migrator.get_migration_status()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        sys.exit(1)

    db_path = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "status"

    migrator = DatabaseMigrator(db_path)

    if command == "status":
        status = migrator.get_migration_status()

    elif command == "migrate":
        target_version = int(sys.argv[3]) if len(sys.argv) > 3 else None
        success = migrator.apply_migrations(target_version)
        sys.exit(0 if success else 1)

    elif command == "rollback":
        if len(sys.argv) < 4:
            sys.exit(1)
        target_version = int(sys.argv[3])
        success = migrator.rollback_migration(target_version)
        sys.exit(0 if success else 1)

    elif command == "backup":
        backup_path = sys.argv[3] if len(sys.argv) > 3 else None
        try:
            result_path = migrator.backup_database(backup_path)
        except Exception:
            sys.exit(1)

    else:
        sys.exit(1)
