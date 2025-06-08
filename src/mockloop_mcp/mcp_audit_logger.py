"""
MCP Audit Logger Module

Provides comprehensive audit logging capabilities for MCP (Model Context Protocol) operations.
Tracks tool executions, data access, compliance requirements, and performance metrics.
"""

import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union
import hashlib
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class MCPOperationType(Enum):
    """Enumeration of MCP operation types for audit logging."""

    TOOL_EXECUTION = "tool_execution"
    RESOURCE_ACCESS = "resource_access"
    CONTEXT_OPERATION = "context_operation"
    PROMPT_EXECUTION = "prompt_execution"
    SERVER_OPERATION = "server_operation"


class MCPAuditLogger:
    """
    Comprehensive audit logger for MCP operations.

    Provides detailed logging of tool executions, data access patterns,
    compliance tracking, and performance monitoring for MCP servers.
    """

    def __init__(
        self,
        db_path: str = "mcp_audit.db",
        session_id: str | None = None,
        user_id: str | None = None,
        enable_performance_tracking: bool = True,
        enable_content_hashing: bool = True,
        auto_log_session: bool = False,
    ):
        """
        Initialize the MCP audit logger.

        Args:
            db_path: Path to the SQLite database file
            session_id: Unique session identifier
            user_id: User identifier for the session
            enable_performance_tracking: Enable performance metrics collection
            enable_content_hashing: Enable content hashing for integrity verification
            auto_log_session: Whether to automatically log session start/end
        """
        self.db_path = Path(db_path)
        self.session_id = session_id or str(uuid.uuid4())
        self.user_id = user_id or "anonymous"
        self.enable_performance_tracking = enable_performance_tracking
        self.enable_content_hashing = enable_content_hashing
        self.auto_log_session = auto_log_session

        # Initialize database
        self._init_database()

        # Log session start if enabled
        if self.auto_log_session:
            self._log_session_start()

    def _init_database(self) -> None:
        """Initialize the audit database with required tables and handle schema migrations."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Create mcp_audit_logs table (main audit table)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_audit_logs (
                        entry_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        user_id TEXT,
                        timestamp TEXT NOT NULL,
                        operation_type TEXT NOT NULL,
                        operation_name TEXT NOT NULL,
                        input_parameters TEXT,
                        output_data TEXT,
                        execution_time_ms REAL,
                        data_sources TEXT,
                        compliance_tags TEXT,
                        processing_purpose TEXT,
                        legal_basis TEXT,
                        content_hash TEXT,
                        gdpr_applicable BOOLEAN DEFAULT FALSE,
                        ccpa_applicable BOOLEAN DEFAULT FALSE,
                        data_subject_id TEXT,
                        context_state_before TEXT,
                        context_state_after TEXT,
                        expires_at TEXT,
                        retention_policy TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Create mcp_data_lineage table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_data_lineage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT NOT NULL,
                        source_uri TEXT NOT NULL,
                        source_type TEXT,
                        source_identifier TEXT,
                        source_metadata TEXT,
                        transformation_applied TEXT,
                        destination_uri TEXT,
                        transformation_type TEXT,
                        data_flow_direction TEXT,
                        timestamp TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (entry_id) REFERENCES mcp_audit_logs (entry_id)
                    )
                """)

                # Create mcp_compliance_events table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mcp_compliance_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        compliance_framework TEXT NOT NULL,
                        event_details TEXT,
                        risk_level TEXT,
                        mitigation_actions TEXT,
                        timestamp TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Check table schemas and handle migrations
                self._handle_schema_migrations(cursor)

                # Create indexes for better performance
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_session ON mcp_audit_logs(session_id)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_operation ON mcp_audit_logs(operation_type)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_mcp_audit_logs_timestamp ON mcp_audit_logs(timestamp)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_mcp_data_lineage_entry ON mcp_data_lineage(entry_id)"
                )

                # Check if session_id column exists in mcp_compliance_events before creating index
                cursor.execute("PRAGMA table_info(mcp_compliance_events)")
                compliance_columns = [column[1] for column in cursor.fetchall()]
                if "session_id" in compliance_columns:
                    cursor.execute(
                        "CREATE INDEX IF NOT EXISTS idx_mcp_compliance_events_session ON mcp_compliance_events(session_id)"
                    )

                conn.commit()

        except Exception:
            logger.exception("Failed to initialize audit database")
            raise

    def _handle_schema_migrations(self, cursor) -> None:
        """Handle database schema migrations for backward compatibility."""
        try:
            # Check mcp_data_lineage table schema
            cursor.execute("PRAGMA table_info(mcp_data_lineage)")
            lineage_columns = [column[1] for column in cursor.fetchall()]

            # If source_uri column doesn't exist, recreate the table
            if "source_uri" not in lineage_columns:
                logger.info("Migrating mcp_data_lineage table schema")

                # Backup existing data if any
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_data_lineage'"
                )
                if cursor.fetchone():
                    cursor.execute(
                        "ALTER TABLE mcp_data_lineage RENAME TO mcp_data_lineage_backup"
                    )

                # Create new table with correct schema
                cursor.execute("""
                    CREATE TABLE mcp_data_lineage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT NOT NULL,
                        source_uri TEXT NOT NULL,
                        source_type TEXT,
                        source_identifier TEXT,
                        source_metadata TEXT,
                        transformation_applied TEXT,
                        destination_uri TEXT,
                        transformation_type TEXT,
                        data_flow_direction TEXT,
                        timestamp TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (entry_id) REFERENCES mcp_audit_logs (entry_id)
                    )
                """)

                # Try to migrate data from backup if it exists and has compatible columns
                try:
                    cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_data_lineage_backup'"
                    )
                    if cursor.fetchone():
                        cursor.execute("PRAGMA table_info(mcp_data_lineage_backup)")
                        backup_columns = [column[1] for column in cursor.fetchall()]

                        # Find common columns for migration
                        common_columns = set(backup_columns) & set(lineage_columns)
                        if common_columns and "entry_id" in common_columns:
                            # Validate column names to prevent SQL injection
                            valid_columns = {
                                "id",
                                "entry_id",
                                "source_uri",
                                "source_type",
                                "source_identifier",
                                "source_metadata",
                                "transformation_applied",
                                "destination_uri",
                                "transformation_type",
                                "data_flow_direction",
                                "timestamp",
                                "created_at",
                            }
                            safe_columns = [
                                col for col in common_columns if col in valid_columns
                            ]
                            if safe_columns:
                                columns_str = ", ".join(safe_columns)
                                # Safe SQL construction with validated column names from database schema
                                sql_query = f"""
                                    INSERT INTO mcp_data_lineage ({columns_str})
                                    SELECT {columns_str} FROM mcp_data_lineage_backup
                                """  # noqa: S608
                                cursor.execute(sql_query)

                        # Drop backup table
                        cursor.execute("DROP TABLE mcp_data_lineage_backup")
                except Exception as e:
                    logger.warning(f"Could not migrate data from backup table: {e}")
                    # Continue without migration - better to have working schema

        except Exception as e:
            logger.warning(f"Schema migration failed: {e}")
            # Continue - the CREATE TABLE IF NOT EXISTS should handle basic cases

    def _log_session_start(self) -> None:
        """Log the start of a new audit session."""
        try:
            # Create a session start entry in the audit logs
            self.log_tool_execution(
                tool_name="session_start",
                input_parameters={
                    "session_id": self.session_id,
                    "user_id": self.user_id,
                },
                processing_purpose="session_management",
                legal_basis="legitimate_interests",
            )
        except Exception:
            logger.exception("Failed to log session start")

    def log_tool_execution(
        self,
        tool_name: str,
        input_parameters: dict[str, Any] | None = None,
        execution_result: dict[str, Any] | None = None,
        execution_time_ms: float | None = None,
        data_sources: list[str] | None = None,
        compliance_tags: list[str] | None = None,
        processing_purpose: str | None = None,
        legal_basis: str | None = None,
        user_id: str | None = None,
        gdpr_applicable: bool = False,
        ccpa_applicable: bool = False,
        data_subject_id: str | None = None,
        retention_policy: str | None = None,
    ) -> str:
        """
        Log a tool execution event.

        Args:
            tool_name: Name of the MCP tool being executed
            input_parameters: Input parameters passed to the tool
            execution_result: Result returned by the tool
            execution_time_ms: Execution time in milliseconds
            data_sources: List of data sources accessed
            compliance_tags: Compliance-related tags
            processing_purpose: Purpose of data processing
            legal_basis: Legal basis for data processing
            error_details: Error details if execution failed
            user_id: Override user ID for this operation
            gdpr_applicable: Whether GDPR applies to this operation
            ccpa_applicable: Whether CCPA applies to this operation
            data_subject_id: ID of the data subject if applicable

        Returns:
            Unique entry ID for the logged event
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()  # noqa: UP017

        # Generate content hash if enabled
        content_hash = None
        if self.enable_content_hashing:
            content_data = {
                "tool_name": tool_name,
                "input_parameters": input_parameters,
                "execution_result": execution_result,
            }
            content_hash = hashlib.sha256(
                json.dumps(content_data, sort_keys=True).encode()
            ).hexdigest()

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Insert audit log entry
                cursor.execute(
                    """
                    INSERT INTO mcp_audit_logs (
                        entry_id, session_id, user_id, timestamp, operation_type,
                        operation_name, input_parameters, output_data, execution_time_ms,
                        data_sources, compliance_tags, processing_purpose,
                        legal_basis, content_hash, gdpr_applicable, ccpa_applicable,
                        data_subject_id, retention_policy
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        entry_id,
                        self.session_id,
                        user_id or self.user_id,
                        timestamp,
                        MCPOperationType.TOOL_EXECUTION.value,
                        tool_name,
                        json.dumps(input_parameters) if input_parameters else None,
                        json.dumps(execution_result) if execution_result else None,
                        execution_time_ms,
                        json.dumps(data_sources) if data_sources else None,
                        json.dumps(compliance_tags) if compliance_tags else None,
                        processing_purpose,
                        legal_basis,
                        content_hash,
                        gdpr_applicable,
                        ccpa_applicable,
                        data_subject_id,
                        retention_policy,
                    ),
                )

                # Log data lineage if data sources are provided
                if data_sources:
                    for source in data_sources:
                        cursor.execute(
                            """
                            INSERT INTO mcp_data_lineage (
                                entry_id, source_uri, source_type, source_identifier,
                                source_metadata, transformation_applied, transformation_type,
                                data_flow_direction, timestamp
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                            (
                                entry_id,
                                source,
                                "external_api",
                                source,
                                json.dumps({"tool_name": tool_name}),
                                "tool_execution",
                                "tool_execution",
                                "input",
                                timestamp,
                            ),
                        )

                conn.commit()

        except Exception:
            logger.exception("Failed to log tool execution")
            raise

        return entry_id

    def log_resource_access(
        self,
        resource_uri: str,
        access_type: str,
        metadata: dict[str, Any] | None = None,
        content_preview: str | None = None,
        data_sources: list[str] | None = None,
        compliance_tags: list[str] | None = None,
        processing_purpose: str | None = None,
        legal_basis: str | None = None,
        user_id: str | None = None,
        gdpr_applicable: bool = False,
        ccpa_applicable: bool = False,
        data_subject_id: str | None = None,
        retention_policy: str | None = None,
        execution_time_ms: float | None = None,
    ) -> str:
        """
        Log a resource access event.

        Args:
            resource_uri: URI of the resource being accessed
            access_type: Type of access (read, write, delete, etc.)
            metadata: Resource metadata
            content_preview: Preview of resource content
            data_sources: List of data sources accessed
            compliance_tags: Compliance-related tags
            processing_purpose: Purpose of data processing
            legal_basis: Legal basis for data processing
            user_id: Override user ID for this operation
            gdpr_applicable: Whether GDPR applies to this operation
            ccpa_applicable: Whether CCPA applies to this operation
            data_subject_id: ID of the data subject if applicable

        Returns:
            Unique entry ID for the logged event
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()  # noqa: UP017

        # Generate content hash if enabled
        content_hash = None
        if self.enable_content_hashing and content_preview:
            content_hash = hashlib.sha256(content_preview.encode()).hexdigest()

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Insert audit log entry
                cursor.execute(
                    """
                    INSERT INTO mcp_audit_logs (
                        entry_id, session_id, user_id, timestamp, operation_type,
                        operation_name, input_parameters, output_data,
                        data_sources, compliance_tags, processing_purpose,
                        legal_basis, content_hash, gdpr_applicable, ccpa_applicable,
                        data_subject_id, retention_policy
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        entry_id,
                        self.session_id,
                        user_id or self.user_id,
                        timestamp,
                        MCPOperationType.RESOURCE_ACCESS.value,
                        f"resource_access_{access_type}",
                        json.dumps(
                            {
                                "uri": resource_uri,
                                "access_type": access_type,
                                "execution_time_ms": execution_time_ms,
                            }
                        ),
                        json.dumps(
                            {"metadata": metadata, "content_preview": content_preview}
                        ),
                        json.dumps(data_sources) if data_sources else None,
                        json.dumps(compliance_tags) if compliance_tags else None,
                        processing_purpose,
                        legal_basis,
                        content_hash,
                        gdpr_applicable,
                        ccpa_applicable,
                        data_subject_id,
                        retention_policy,
                    ),
                )

                # Log data lineage
                cursor.execute(
                    """
                    INSERT INTO mcp_data_lineage (
                        entry_id, source_uri, source_type, source_identifier,
                        source_metadata, transformation_applied, transformation_type,
                        data_flow_direction, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        entry_id,
                        resource_uri,
                        "resource",
                        resource_uri,
                        json.dumps(metadata) if metadata else None,
                        "resource_access",
                        "resource_access",
                        access_type,
                        timestamp,
                    ),
                )

                conn.commit()

        except Exception:
            logger.exception("Failed to log resource access")
            raise

        return entry_id

    def log_context_operation(
        self,
        operation_type: str,
        context_key: str,
        state_before: dict[str, Any] | None = None,
        state_after: dict[str, Any] | None = None,
        compliance_tags: list[str] | None = None,
        processing_purpose: str | None = None,
        legal_basis: str | None = None,
        user_id: str | None = None,
    ) -> str:
        """
        Log a context operation event.

        Args:
            operation_type: Type of context operation (set, get, update, delete)
            context_key: Key of the context being operated on
            state_before: Context state before the operation
            state_after: Context state after the operation
            compliance_tags: Compliance-related tags
            processing_purpose: Purpose of data processing
            legal_basis: Legal basis for data processing
            user_id: Override user ID for this operation

        Returns:
            Unique entry ID for the logged event
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()  # noqa: UP017

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Insert audit log entry
                cursor.execute(
                    """
                    INSERT INTO mcp_audit_logs (
                        entry_id, session_id, user_id, timestamp, operation_type,
                        operation_name, input_parameters, context_state_before,
                        context_state_after, compliance_tags, processing_purpose,
                        legal_basis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        entry_id,
                        self.session_id,
                        user_id or self.user_id,
                        timestamp,
                        MCPOperationType.CONTEXT_OPERATION.value,
                        f"context_{operation_type}",
                        json.dumps(
                            {"context_key": context_key, "operation": operation_type}
                        ),
                        json.dumps(state_before) if state_before else None,
                        json.dumps(state_after) if state_after else None,
                        json.dumps(compliance_tags) if compliance_tags else None,
                        processing_purpose,
                        legal_basis,
                    ),
                )

                conn.commit()

        except Exception:
            logger.exception("Failed to log context operation")
            raise

        return entry_id

    def log_prompt_invocation(
        self,
        prompt_name: str,
        input_parameters: dict[str, Any] | None = None,
        execution_result: dict[str, Any] | None = None,
        execution_time_ms: float | None = None,
        data_sources: list[str] | None = None,
        compliance_tags: list[str] | None = None,
        processing_purpose: str | None = None,
        legal_basis: str | None = None,
        user_id: str | None = None,
        gdpr_applicable: bool = False,
        ccpa_applicable: bool = False,
        data_subject_id: str | None = None,
        retention_policy: str | None = None,
        generated_output: Any = None,
    ) -> str:
        """
        Log a prompt invocation event.

        Args:
            prompt_name: Name of the prompt being invoked
            input_parameters: Input parameters passed to the prompt
            execution_result: Result returned by the prompt
            execution_time_ms: Execution time in milliseconds
            data_sources: List of data sources accessed
            compliance_tags: Compliance-related tags
            processing_purpose: Purpose of data processing
            legal_basis: Legal basis for data processing
            user_id: Override user ID for this operation
            gdpr_applicable: Whether GDPR applies to this operation
            ccpa_applicable: Whether CCPA applies to this operation
            data_subject_id: ID of the data subject if applicable
            retention_policy: Data retention policy
            generated_output: Output generated by the prompt (alternative to execution_result)

        Returns:
            Unique entry ID for the logged event
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()  # noqa: UP017

        # Use generated_output if provided, otherwise use execution_result
        output_data = (
            generated_output if generated_output is not None else execution_result
        )

        # Generate content hash if enabled
        content_hash = None
        if self.enable_content_hashing:
            content_data = {
                "prompt_name": prompt_name,
                "input_parameters": input_parameters,
                "output_data": output_data,
            }
            content_hash = hashlib.sha256(
                json.dumps(content_data, sort_keys=True).encode()
            ).hexdigest()

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Insert audit log entry
                cursor.execute(
                    """
                    INSERT INTO mcp_audit_logs (
                        entry_id, session_id, user_id, timestamp, operation_type,
                        operation_name, input_parameters, output_data, execution_time_ms,
                        data_sources, compliance_tags, processing_purpose,
                        legal_basis, content_hash, gdpr_applicable, ccpa_applicable,
                        data_subject_id, retention_policy
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        entry_id,
                        self.session_id,
                        user_id or self.user_id,
                        timestamp,
                        MCPOperationType.PROMPT_EXECUTION.value,
                        prompt_name,
                        json.dumps(input_parameters) if input_parameters else None,
                        json.dumps(output_data) if output_data else None,
                        execution_time_ms,
                        json.dumps(data_sources) if data_sources else None,
                        json.dumps(compliance_tags) if compliance_tags else None,
                        processing_purpose,
                        legal_basis,
                        content_hash,
                        gdpr_applicable,
                        ccpa_applicable,
                        data_subject_id,
                        retention_policy,
                    ),
                )

                # Log data lineage if data sources are provided
                if data_sources:
                    for source in data_sources:
                        cursor.execute(
                            """
                            INSERT INTO mcp_data_lineage (
                                entry_id, source_uri, source_type, source_identifier,
                                source_metadata, transformation_applied, transformation_type,
                                data_flow_direction, timestamp
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                            (
                                entry_id,
                                source,
                                "prompt_source",
                                source,
                                json.dumps({"prompt_name": prompt_name}),
                                "prompt_execution",
                                "prompt_execution",
                                "input",
                                timestamp,
                            ),
                        )

                conn.commit()

        except Exception:
            logger.exception("Failed to log prompt invocation")
            raise

        return entry_id

    def query_audit_logs(
        self,
        operation_type: str | None = None,
        user_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Query audit logs with optional filters.

        Args:
            operation_type: Filter by operation type
            user_id: Filter by user ID
            start_time: Filter by start time (ISO format)
            end_time: Filter by end time (ISO format)
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of audit log entries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Build query with filters
                query = "SELECT * FROM mcp_audit_logs WHERE 1=1"
                params = []

                if operation_type:
                    query += " AND operation_type = ?"
                    params.append(operation_type)

                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()

                # Convert to list of dictionaries
                return [dict(row) for row in rows]

        except Exception:
            logger.exception("Failed to query audit logs")
            return []

    def cleanup_expired_logs(self) -> int:
        """
        Clean up expired audit logs.

        Returns:
            Number of deleted log entries
        """
        try:
            current_time = datetime.now(timezone.utc).isoformat()  # noqa: UP017

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Delete expired logs
                cursor.execute(
                    """
                    DELETE FROM mcp_audit_logs
                    WHERE expires_at IS NOT NULL AND expires_at < ?
                """,
                    (current_time,),
                )

                deleted_count = cursor.rowcount
                conn.commit()

                return deleted_count

        except Exception:
            logger.exception("Failed to cleanup expired logs")
            return 0

    def get_session_summary(self) -> dict[str, Any]:
        """Get a summary of the current audit session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Get session statistics
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) as total_operations,
                        COUNT(CASE WHEN operation_type = ? THEN 1 END) as tool_executions,
                        COUNT(CASE WHEN operation_type = ? THEN 1 END) as resource_accesses,
                        COUNT(CASE WHEN operation_type = ? THEN 1 END) as context_operations,
                        MIN(timestamp) as session_start,
                        MAX(timestamp) as last_activity
                    FROM mcp_audit_logs
                    WHERE session_id = ?
                """,
                    (
                        MCPOperationType.TOOL_EXECUTION.value,
                        MCPOperationType.RESOURCE_ACCESS.value,
                        MCPOperationType.CONTEXT_OPERATION.value,
                        self.session_id,
                    ),
                )

                stats = cursor.fetchone()

                return {
                    "session_id": self.session_id,
                    "user_id": self.user_id,
                    "total_operations": stats["total_operations"],
                    "tool_executions": stats["tool_executions"],
                    "resource_accesses": stats["resource_accesses"],
                    "context_operations": stats["context_operations"],
                    "session_start": stats["session_start"],
                    "last_activity": stats["last_activity"],
                }

        except Exception as e:
            logger.exception("Failed to get session summary")
            return {"error": str(e)}

    def close_session(self) -> None:
        """Close the current audit session."""
        try:
            # Log session end
            self.log_tool_execution(
                tool_name="session_end",
                input_parameters={"session_id": self.session_id},
                processing_purpose="session_management",
                legal_basis="legitimate_interests",
            )
        except Exception:
            logger.exception("Failed to close session")


def create_audit_logger(
    db_path: str = "mcp_audit.db",
    session_id: str | None = None,
    user_id: str | None = None,
    enable_performance_tracking: bool = True,
    enable_content_hashing: bool = True,
) -> MCPAuditLogger:
    """
    Create and configure an MCP audit logger instance.

    Args:
        db_path: Path to the SQLite database file
        session_id: Unique session identifier
        user_id: User identifier for the session
        enable_performance_tracking: Enable performance metrics collection
        enable_content_hashing: Enable content hashing for integrity verification

    Returns:
        Configured MCPAuditLogger instance
    """
    return MCPAuditLogger(
        db_path=db_path,
        session_id=session_id,
        user_id=user_id,
        enable_performance_tracking=enable_performance_tracking,
        enable_content_hashing=enable_content_hashing,
    )
