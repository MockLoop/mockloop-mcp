"""
SchemaPin Audit Logging Module

Provides audit logging capabilities for SchemaPin verification events.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, UTC
from typing import Any

from .config import VerificationResult

logger = logging.getLogger(__name__)


class SchemaPinAuditLogger:
    """SchemaPin-specific audit logging for MockLoop integration."""

    def __init__(self, db_path: str = "mcp_audit.db"):
        """Initialize audit logger with database path."""
        self.db_path = db_path
        self._ensure_tables_exist()

    def _ensure_tables_exist(self) -> None:
        """Ensure SchemaPin audit tables exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if schemapin_verification_logs table exists
                cursor.execute("""
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='schemapin_verification_logs'
                """)

                if not cursor.fetchone():
                    # Create the table if it doesn't exist
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS schemapin_verification_logs (
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
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)

                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_schemapin_verification_entry
                        ON schemapin_verification_logs(entry_id)
                    """)

                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_schemapin_verification_tool
                        ON schemapin_verification_logs(tool_id)
                    """)

                    conn.commit()
        except Exception:
            logger.exception("Failed to ensure SchemaPin audit tables exist")

    async def log_verification_attempt(self, tool_id: str, domain: str | None,
                                     result: VerificationResult, execution_time_ms: float) -> None:
        """
        Log SchemaPin verification attempts.

        Args:
            tool_id: Tool identifier
            domain: Domain being verified
            result: Verification result
            execution_time_ms: Execution time in milliseconds
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO schemapin_verification_logs
                    (entry_id, tool_id, domain, verification_result, signature_valid,
                     key_pinned, policy_action, execution_time_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    tool_id,
                    domain,
                    "success" if result.valid else "failure",
                    result.valid,
                    result.key_pinned,
                    "allow" if result.valid else "block",
                    execution_time_ms
                ))
                conn.commit()
        except Exception:
            logger.exception("Failed to log verification attempt")

    async def log_verification_error(self, tool_id: str, domain: str | None, error: str) -> None:
        """
        Log SchemaPin verification errors.

        Args:
            tool_id: Tool identifier
            domain: Domain being verified
            error: Error message
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO schemapin_verification_logs
                    (entry_id, tool_id, domain, verification_result, signature_valid,
                     key_pinned, policy_action, error_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    tool_id,
                    domain,
                    "error",
                    False,
                    False,
                    "error",
                    error
                ))
                conn.commit()
        except Exception:
            logger.exception("Failed to log verification error")

    async def log_key_pinning_event(self, tool_id: str, domain: str,
                                   public_key: str, action: str) -> None:
        """
        Log key pinning events (pin, update, revoke).

        Args:
            tool_id: Tool identifier
            domain: Domain the key belongs to
            public_key: Public key being pinned
            action: Action being performed (pin, update, revoke)
        """
        try:
            # For now, log as a verification event with special metadata
            # In a full implementation, this might have its own table
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO schemapin_verification_logs
                    (entry_id, tool_id, domain, verification_result, signature_valid,
                     key_pinned, policy_action, error_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    tool_id,
                    domain,
                    f"key_{action}",
                    True,
                    action == "pin",
                    action,
                    json.dumps({
                        "action": action,
                        "public_key_hash": hash(public_key),  # Don't store full key
                        "timestamp": datetime.now(UTC).isoformat()
                    })
                ))
                conn.commit()
        except Exception:
            logger.exception("Failed to log key pinning event")

    async def log_policy_decision(self, tool_id: str, policy_action: str,
                                reason: str, policy_mode: str) -> None:
        """
        Log policy enforcement decisions.

        Args:
            tool_id: Tool identifier
            policy_action: Action taken by policy
            reason: Reason for the decision
            policy_mode: Policy mode in effect
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO schemapin_verification_logs
                    (entry_id, tool_id, verification_result, policy_action, error_details)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    tool_id,
                    f"policy_{policy_action}",
                    policy_action,
                    json.dumps({
                        "reason": reason,
                        "policy_mode": policy_mode,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
                ))
                conn.commit()
        except Exception:
            logger.exception("Failed to log policy decision")

    def get_verification_stats(self, start_date: str | None = None,
                             end_date: str | None = None) -> dict[str, Any]:
        """
        Get verification statistics for a date range.

        Args:
            start_date: Start date in ISO format
            end_date: End date in ISO format

        Returns:
            Dictionary with verification statistics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Use parameterized queries to avoid SQL injection
                if start_date and end_date:
                    base_query = """
                        SELECT
                            COUNT(*) as total_verifications,
                            SUM(CASE WHEN signature_valid = 1 THEN 1 ELSE 0 END) as successful_verifications,
                            SUM(CASE WHEN signature_valid = 0 THEN 1 ELSE 0 END) as failed_verifications,
                            COUNT(DISTINCT tool_id) as unique_tools,
                            COUNT(DISTINCT domain) as unique_domains
                        FROM schemapin_verification_logs
                        WHERE created_at BETWEEN ? AND ?
                    """
                    policy_query = """
                        SELECT
                            policy_action,
                            COUNT(*) as count
                        FROM schemapin_verification_logs
                        WHERE created_at BETWEEN ? AND ?
                        GROUP BY policy_action
                    """
                    params = [start_date, end_date]
                else:
                    base_query = """
                        SELECT
                            COUNT(*) as total_verifications,
                            SUM(CASE WHEN signature_valid = 1 THEN 1 ELSE 0 END) as successful_verifications,
                            SUM(CASE WHEN signature_valid = 0 THEN 1 ELSE 0 END) as failed_verifications,
                            COUNT(DISTINCT tool_id) as unique_tools,
                            COUNT(DISTINCT domain) as unique_domains
                        FROM schemapin_verification_logs
                    """
                    policy_query = """
                        SELECT
                            policy_action,
                            COUNT(*) as count
                        FROM schemapin_verification_logs
                        GROUP BY policy_action
                    """
                    params = []

                cursor.execute(base_query, params)
                stats = dict(cursor.fetchone())

                # Get policy action breakdown
                cursor.execute(policy_query, params)

                policy_stats = {row["policy_action"]: row["count"] for row in cursor.fetchall()}
                stats["policy_breakdown"] = policy_stats

                return stats
        except Exception:
            logger.exception("Failed to get verification stats")
            return {}
