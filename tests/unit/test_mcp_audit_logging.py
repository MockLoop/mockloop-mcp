# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Unit tests for MCP audit logging infrastructure.

Tests the comprehensive MCP logging system including:
- MCP Audit Logger functionality
- MCP Compliance Reporter functionality
- Database schema and migrations
- Audit decorators and integration
"""

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch


# Import the modules to test
from src.mockloop_mcp.mcp_audit_logger import (
    MCPAuditLogger,
    MCPOperationType,
)
from src.mockloop_mcp.mcp_compliance import (
    MCPComplianceReporter,
    ComplianceRegulation,
    ReportFormat,
)
from src.mockloop_mcp.database_migration import DatabaseMigrator


class TestMCPAuditLogger(unittest.TestCase):
    """Test cases for MCP Audit Logger."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_audit.db"
        self.logger = MCPAuditLogger(
            db_path=str(self.db_path),
            session_id="test_session_123",
            user_id="test_user",
            enable_performance_tracking=True,
            enable_content_hashing=True,
        )

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_database_initialization(self):
        """Test that the audit database is properly initialized."""
        # Check that database file exists
        self.assertTrue(self.db_path.exists())

        # Check that required tables exist
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            # Check mcp_audit_logs table
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='mcp_audit_logs'
            """)
            self.assertIsNotNone(cursor.fetchone())

            # Check mcp_data_lineage table
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='mcp_data_lineage'
            """)
            self.assertIsNotNone(cursor.fetchone())

            # Check mcp_compliance_events table
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='mcp_compliance_events'
            """)
            self.assertIsNotNone(cursor.fetchone())

    def test_log_tool_execution(self):
        """Test logging of MCP tool execution."""
        # Log a tool execution
        entry_id = self.logger.log_tool_execution(
            tool_name="test_tool",
            input_parameters={"param1": "value1", "param2": 42},
            execution_result={"status": "success", "result": "test_result"},
            execution_time_ms=150.5,
            data_sources=["source1", "source2"],
            compliance_tags=["test", "mcp_tool"],
            processing_purpose="testing",
            legal_basis="legitimate_interests",
        )

        # Verify the entry was logged
        self.assertIsNotNone(entry_id)

        # Query the database to verify the log entry
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM mcp_audit_logs WHERE entry_id = ?
            """,
                (entry_id,),
            )

            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(
                row["operation_type"], MCPOperationType.TOOL_EXECUTION.value
            )
            self.assertEqual(row["operation_name"], "test_tool")
            self.assertEqual(row["session_id"], "test_session_123")
            self.assertEqual(row["user_id"], "test_user")
            self.assertEqual(row["execution_time_ms"], 150.5)
            self.assertEqual(row["processing_purpose"], "testing")
            self.assertEqual(row["legal_basis"], "legitimate_interests")

            # Check input parameters
            input_params = json.loads(row["input_parameters"])
            self.assertEqual(input_params["param1"], "value1")
            self.assertEqual(input_params["param2"], 42)

            # Check output data
            output_data = json.loads(row["output_data"])
            self.assertEqual(output_data["status"], "success")
            self.assertEqual(output_data["result"], "test_result")

            # Check data sources
            data_sources = json.loads(row["data_sources"])
            self.assertEqual(data_sources, ["source1", "source2"])

            # Check compliance tags
            compliance_tags = json.loads(row["compliance_tags"])
            self.assertEqual(compliance_tags, ["test", "mcp_tool"])

    def test_log_resource_access(self):
        """Test logging of MCP resource access."""
        entry_id = self.logger.log_resource_access(
            resource_uri="file:///test/resource.txt",
            access_type="read",
            metadata={"size": 1024, "type": "text"},
            content_preview="Sample content...",
            data_sources=["file:///test/resource.txt"],
            compliance_tags=["resource_access"],
            processing_purpose="data_processing",
            gdpr_applicable=True,
        )

        # Verify the entry was logged
        self.assertIsNotNone(entry_id)

        # Query the database to verify the log entry
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM mcp_audit_logs WHERE entry_id = ?
            """,
                (entry_id,),
            )

            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(
                row["operation_type"], MCPOperationType.RESOURCE_ACCESS.value
            )
            self.assertEqual(row["operation_name"], "resource_access_read")
            self.assertTrue(row["gdpr_applicable"])

            # Check input parameters
            input_params = json.loads(row["input_parameters"])
            self.assertEqual(input_params["uri"], "file:///test/resource.txt")
            self.assertEqual(input_params["access_type"], "read")

    def test_log_context_operation(self):
        """Test logging of MCP context operations."""
        state_before = {"key1": "old_value"}
        state_after = {"key1": "new_value", "key2": "added_value"}

        entry_id = self.logger.log_context_operation(
            operation_type="update",
            context_key="test_context",
            state_before=state_before,
            state_after=state_after,
            compliance_tags=["context_management"],
        )

        # Verify the entry was logged
        self.assertIsNotNone(entry_id)

        # Query the database to verify the log entry
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM mcp_audit_logs WHERE entry_id = ?
            """,
                (entry_id,),
            )

            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(
                row["operation_type"], MCPOperationType.CONTEXT_OPERATION.value
            )
            self.assertEqual(row["operation_name"], "context_update")

            # Check context states
            context_before = json.loads(row["context_state_before"])
            context_after = json.loads(row["context_state_after"])
            self.assertEqual(context_before, state_before)
            self.assertEqual(context_after, state_after)

    def test_content_hashing(self):
        """Test content hashing functionality."""
        # Log an entry with content that should be hashed
        entry_id = self.logger.log_tool_execution(
            tool_name="hash_test",
            input_parameters={"data": "test_content"},
            execution_result={"output": "processed_content"},
        )

        # Query the database to check content hash
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT content_hash FROM mcp_audit_logs WHERE entry_id = ?
            """,
                (entry_id,),
            )

            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertIsNotNone(row["content_hash"])
            self.assertEqual(len(row["content_hash"]), 64)  # SHA-256 hash length

    def test_query_audit_logs(self):
        """Test querying audit logs with filters."""
        # Create multiple log entries
        self.logger.log_tool_execution(
            tool_name="tool1", input_parameters={"test": "data1"}, user_id="user1"
        )

        self.logger.log_tool_execution(
            tool_name="tool2", input_parameters={"test": "data2"}, user_id="user2"
        )

        self.logger.log_resource_access(
            resource_uri="file:///test.txt", access_type="read", user_id="user1"
        )

        # Query all logs
        all_logs = self.logger.query_audit_logs()
        self.assertEqual(len(all_logs), 3)

        # Query logs by operation type
        tool_logs = self.logger.query_audit_logs(
            operation_type=MCPOperationType.TOOL_EXECUTION.value
        )
        self.assertEqual(len(tool_logs), 2)

        # Query logs by user
        user1_logs = self.logger.query_audit_logs(user_id="user1")
        self.assertEqual(len(user1_logs), 2)

    def test_cleanup_expired_logs(self):
        """Test cleanup of expired audit logs."""
        # Create a log entry with past expiration
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            # Insert a log entry that's already expired
            past_time = datetime.now(timezone.utc).replace(year=2020).isoformat()  # noqa: UP017
            cursor.execute(
                """
                INSERT INTO mcp_audit_logs (
                    entry_id, session_id, timestamp, operation_type,
                    operation_name, input_parameters, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    "expired_entry",
                    "test_session",
                    past_time,
                    "test_operation",
                    "test_tool",
                    "{}",
                    past_time,
                ),
            )
            conn.commit()

        # Run cleanup
        deleted_count = self.logger.cleanup_expired_logs()
        self.assertEqual(deleted_count, 1)

        # Verify the expired log was deleted
        remaining_logs = self.logger.query_audit_logs()
        expired_entries = [
            log for log in remaining_logs if log["entry_id"] == "expired_entry"
        ]
        self.assertEqual(len(expired_entries), 0)


class TestMCPComplianceReporter(unittest.TestCase):
    """Test cases for MCP Compliance Reporter."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_audit.db"
        self.reports_dir = Path(self.temp_dir) / "reports"

        # Initialize audit logger first
        self.audit_logger = MCPAuditLogger(
            db_path=str(self.db_path), session_id="test_session", user_id="test_user"
        )

        # Initialize compliance reporter
        self.reporter = MCPComplianceReporter(
            audit_db_path=str(self.db_path), reports_output_dir=str(self.reports_dir)
        )

        # Create some test audit data
        self._create_test_audit_data()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_audit_data(self):
        """Create test audit data for compliance testing."""
        # Create various types of audit entries
        self.audit_logger.log_tool_execution(
            tool_name="gdpr_tool",
            input_parameters={"personal_data": "test@example.com"},
            gdpr_applicable=True,
            data_subject_id="subject_123",
            processing_purpose="email_processing",
            legal_basis="consent",
        )

        self.audit_logger.log_resource_access(
            resource_uri="database://users/personal_info",
            access_type="read",
            ccpa_applicable=True,
            processing_purpose="analytics",
            legal_basis="legitimate_interests",
        )

        self.audit_logger.log_context_operation(
            operation_type="set",
            context_key="user_preferences",
            state_after={"privacy_level": "high"},
            processing_purpose="personalization",
        )

    def test_generate_gdpr_compliance_report(self):
        """Test generation of GDPR compliance report."""
        report = self.reporter.generate_compliance_report(
            regulation=ComplianceRegulation.GDPR,
            include_violations=True,
            include_recommendations=True,
        )

        # Verify report structure
        self.assertEqual(report.regulation, "gdpr")
        self.assertGreater(report.total_operations, 0)
        self.assertGreater(report.data_subjects_count, 0)
        self.assertIn("consent", report.legal_bases)
        self.assertIn("email_processing", report.processing_purposes)

    def test_generate_ccpa_compliance_report(self):
        """Test generation of CCPA compliance report."""
        report = self.reporter.generate_compliance_report(
            regulation=ComplianceRegulation.CCPA,
            include_violations=True,
            include_recommendations=True,
        )

        # Verify report structure
        self.assertEqual(report.regulation, "ccpa")
        self.assertGreater(report.total_operations, 0)

    def test_export_audit_logs_json(self):
        """Test exporting audit logs in JSON format."""
        export_path = self.reporter.export_audit_logs(
            export_format=ReportFormat.JSON, include_sensitive_data=False
        )

        # Verify export file exists
        self.assertTrue(Path(export_path).exists())

        # Verify JSON content
        with open(export_path) as f:
            exported_data = json.load(f)

        self.assertIsInstance(exported_data, list)
        self.assertGreater(len(exported_data), 0)

        # Verify sensitive data is redacted
        for entry in exported_data:
            if "input_parameters" in entry:
                self.assertEqual(entry["input_parameters"], "[REDACTED]")

    def test_export_audit_logs_csv(self):
        """Test exporting audit logs in CSV format."""
        export_path = self.reporter.export_audit_logs(
            export_format=ReportFormat.CSV, include_sensitive_data=False
        )

        # Verify export file exists
        self.assertTrue(Path(export_path).exists())

        # Verify CSV content
        import csv

        with open(export_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertGreater(len(rows), 0)
        self.assertIn("entry_id", rows[0])
        self.assertIn("operation_type", rows[0])

    def test_data_lineage_report(self):
        """Test generation of data lineage report."""
        lineage_report = self.reporter.generate_data_lineage_report()

        # Verify report structure
        self.assertIn("lineage_entries", lineage_report)
        self.assertIn("source_statistics", lineage_report)
        self.assertIn("total_entries", lineage_report)
        self.assertIn("unique_sources", lineage_report)

        # Verify we have lineage data
        self.assertGreater(lineage_report["total_entries"], 0)

    def test_retention_compliance_check(self):
        """Test retention compliance checking."""
        compliance_check = self.reporter.check_retention_compliance()

        # Verify report structure
        self.assertIn("expired_logs", compliance_check)
        self.assertIn("retention_distribution", compliance_check)
        self.assertIn("compliance_status", compliance_check)

        # Should be compliant since we just created the data
        self.assertEqual(compliance_check["compliance_status"], "compliant")

    def test_privacy_impact_assessment(self):
        """Test Privacy Impact Assessment generation."""
        pia_report = self.reporter.generate_privacy_impact_assessment(
            processing_purpose="email_processing",
            data_types=["email", "personal_identifiers"],
        )

        # Verify PIA structure
        self.assertIn("assessment_id", pia_report)
        self.assertIn("processing_purpose", pia_report)
        self.assertIn("data_types", pia_report)
        self.assertIn("risk_analysis", pia_report)
        self.assertIn("recommendations", pia_report)
        self.assertIn("compliance_status", pia_report)

        self.assertEqual(pia_report["processing_purpose"], "email_processing")
        self.assertEqual(pia_report["data_types"], ["email", "personal_identifiers"])

    def test_purge_expired_data_dry_run(self):
        """Test purging expired data in dry run mode."""
        # First, create an expired entry
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            past_time = datetime.now(timezone.utc).replace(year=2020).isoformat()  # noqa: UP017
            cursor.execute(
                """
                INSERT INTO mcp_audit_logs (
                    entry_id, session_id, timestamp, operation_type,
                    operation_name, input_parameters, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    "expired_test",
                    "test_session",
                    past_time,
                    "test_operation",
                    "test_tool",
                    "{}",
                    past_time,
                ),
            )
            conn.commit()

        # Run dry run purge
        purge_result = self.reporter.purge_expired_data(dry_run=True)

        # Verify dry run results
        self.assertTrue(purge_result["dry_run"])
        self.assertEqual(purge_result["expired_logs_found"], 1)
        self.assertEqual(purge_result["logs_deleted"], 0)

        # Verify data still exists
        logs = self.audit_logger.query_audit_logs()
        expired_entries = [log for log in logs if log["entry_id"] == "expired_test"]
        self.assertEqual(len(expired_entries), 1)


class TestDatabaseMigration(unittest.TestCase):
    """Test cases for database migration with MCP audit tables."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_migration.db"
        self.migrator = DatabaseMigrator(str(self.db_path))

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_mcp_audit_migration(self):
        """Test that MCP audit tables are created by migration."""
        # Apply all migrations
        success = self.migrator.apply_migrations()
        self.assertTrue(success)

        # Verify MCP audit tables exist
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            # Check for MCP audit tables
            mcp_tables = ["mcp_audit_logs", "mcp_data_lineage", "mcp_compliance_events"]

            for table_name in mcp_tables:
                cursor.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name=?
                """,
                    (table_name,),
                )
                result = cursor.fetchone()
                self.assertIsNotNone(result, f"Table {table_name} should exist")

    def test_migration_status_with_mcp_tables(self):
        """Test migration status includes MCP audit migration."""
        # Apply migrations
        self.migrator.apply_migrations()

        # Get migration status
        status = self.migrator.get_migration_status()

        # Verify MCP audit migration is included
        mcp_migration = None
        for migration in status["available_migrations"]:
            if "MCP audit logging" in migration["description"]:
                mcp_migration = migration
                break

        self.assertIsNotNone(mcp_migration, "MCP audit migration should be available")
        self.assertTrue(
            mcp_migration["applied"], "MCP audit migration should be applied"
        )


class TestMCPAuditDecorator(unittest.TestCase):
    """Test cases for MCP audit decorator integration."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_decorator.db"

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("src.mockloop_mcp.main.MCP_AUDIT_DB_PATH")
    @patch("src.mockloop_mcp.main.get_audit_logger")
    def test_mcp_audit_decorator(self, mock_get_logger, mock_db_path):
        """Test MCP audit decorator functionality."""
        # Setup mock
        mock_db_path.return_value = str(self.db_path)
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        mock_logger.log_tool_execution.return_value = "test_entry_id"

        # Import the decorator after patching
        from src.mockloop_mcp.main import mcp_audit_tool

        # Create a test function with the decorator
        @mcp_audit_tool("test_tool")
        async def test_function(param1, param2="default"):
            return {"result": "success", "data": f"{param1}_{param2}"}

        # Test successful execution
        import asyncio

        result = asyncio.run(test_function("test_value", param2="custom"))

        # Verify the function executed correctly
        self.assertEqual(result["result"], "success")
        self.assertEqual(result["data"], "test_value_custom")

        # Verify audit logging was called
        self.assertEqual(
            mock_logger.log_tool_execution.call_count, 2
        )  # Start and completion

        # Check the first call (start)
        start_call = mock_logger.log_tool_execution.call_args_list[0]
        self.assertEqual(start_call[1]["tool_name"], "test_tool")
        self.assertIn("param2", start_call[1]["input_parameters"])

        # Check the second call (completion)
        completion_call = mock_logger.log_tool_execution.call_args_list[1]
        self.assertEqual(completion_call[1]["tool_name"], "test_tool_completion")

    @patch("src.mockloop_mcp.main.get_audit_logger")
    def test_mcp_audit_decorator_error_handling(self, mock_get_logger):
        """Test MCP audit decorator error handling."""
        # Setup mock
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        mock_logger.log_tool_execution.return_value = "test_entry_id"

        # Import the decorator after patching
        from src.mockloop_mcp.main import mcp_audit_tool

        # Create a test function that raises an exception
        @mcp_audit_tool("error_tool")
        async def error_function():
            raise ValueError("Test error")

        # Test error handling
        import asyncio

        with self.assertRaises(ValueError):
            asyncio.run(error_function())

        # Verify error logging was called
        self.assertEqual(
            mock_logger.log_tool_execution.call_count, 2
        )  # Start and error

        # Check the error call
        error_call = mock_logger.log_tool_execution.call_args_list[1]
        self.assertEqual(error_call[1]["tool_name"], "error_tool_error")
        self.assertEqual(error_call[1]["error_details"], "Test error")


if __name__ == "__main__":
    unittest.main()
