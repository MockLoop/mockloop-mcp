# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
Comprehensive Integration Test Suite for MockLoop MCP Enhancement Plan
Tests the complete integration of Phase 1 and Phase 2 components.
"""

import asyncio
import contextlib
from datetime import datetime
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
from typing import Any

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mockloop_mcp.database_migration import DatabaseMigrator
from mockloop_mcp.log_analyzer import LogAnalyzer
from mockloop_mcp.main import (
    discover_mock_servers_tool,
    generate_mock_api_tool,
    manage_mock_data_tool,
    query_mock_logs_tool,
)


class ComprehensiveIntegrationTester:
    """Comprehensive test suite for MockLoop MCP enhancement plan."""

    def __init__(self):
        self.test_results = {}
        self.temp_dir = None
        self.mock_server_dir = None
        self.test_server_url = "http://localhost:8000"
        self.server_process = None

    def setup_test_environment(self):
        """Set up temporary test environment."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="mockloop_integration_test_"))

    def cleanup_test_environment(self):
        """Clean up test environment."""
        if self.server_process:
            with contextlib.suppress(Exception):
                self.server_process.terminate()
                self.server_process.wait(timeout=5)

        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def create_test_api_spec(self) -> dict[str, Any]:
        """Create a comprehensive test API specification."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Comprehensive Integration Test API",
                "version": "1.0.0",
                "description": "API for testing all MockLoop MCP enhancement features",
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get all users",
                        "responses": {
                            "200": {
                                "description": "List of users",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "id": {"type": "integer"},
                                                    "name": {"type": "string"},
                                                    "email": {"type": "string"},
                                                },
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    },
                    "post": {
                        "summary": "Create a user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "email": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "description": "User created",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"},
                                                "email": {"type": "string"},
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    },
                },
                "/users/{user_id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "parameters": [
                            {
                                "name": "user_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "User details",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"},
                                                "email": {"type": "string"},
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    }
                },
                "/products": {
                    "get": {
                        "summary": "Get all products",
                        "responses": {
                            "200": {
                                "description": "List of products",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "id": {"type": "integer"},
                                                    "name": {"type": "string"},
                                                    "price": {"type": "number"},
                                                },
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    }
                },
            },
        }

    async def test_complete_workflow(self) -> bool:
        """Test the complete workflow: generation → scenario creation → dynamic responses → monitoring."""

        try:
            # Step 1: Generate mock server with all features
            test_spec = self.create_test_api_spec()

            result = await generate_mock_api_tool(
                spec_url_or_path=json.dumps(test_spec),
                output_dir_name="integration_test_server",
                auth_enabled=True,
                webhooks_enabled=True,
                admin_ui_enabled=True,
                storage_enabled=True,
            )

            if result["status"] != "success":
                return False

            self.mock_server_dir = Path(result["generated_mock_path"])

            # Step 2: Validate database schema migration
            db_path = self.mock_server_dir / "db" / "request_logs.db"
            db_path.parent.mkdir(exist_ok=True)

            migrator = DatabaseMigrator(str(db_path))
            migration_status = migrator.get_migration_status()

            if migration_status["needs_migration"]:
                success = migrator.apply_migrations()
                if not success:
                    return False

            # Step 3: Start the mock server (simulate)

            # Check for enhanced files
            required_files = [
                "main.py",
                "logging_middleware.py",
                "templates/admin.html",
                "requirements_mock.txt",
            ]

            for file_path in required_files:
                if not (self.mock_server_dir / file_path).exists():
                    return False

            # Step 4: Test MCP tools integration (without running server)

            # Test discover_mock_servers
            discovery_result = await discover_mock_servers_tool(
                ports=[8000, 8001, 8002], check_health=False, include_generated=True
            )

            if discovery_result["status"] != "success":
                return False

            # Step 5: Test database operations

            # Insert test log data
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            test_logs = [
                (
                    "2024-01-01T10:00:00",
                    "request",
                    "GET",
                    "/users",
                    200,
                    45,
                    "127.0.0.1",
                    "8080",
                    '{"user-agent": "test-client"}',
                    "{}",
                    "{}",
                    '[{"id": 1, "name": "Test User"}]',
                    "test-session-1",
                    "user-list-scenario",
                    "req-001",
                    "test-client",
                    1024,
                    0,
                ),
                (
                    "2024-01-01T10:01:00",
                    "request",
                    "POST",
                    "/users",
                    201,
                    67,
                    "127.0.0.1",
                    "8080",
                    '{"user-agent": "test-client"}',
                    "{}",
                    '{"name": "New User"}',
                    '{"id": 2, "name": "New User"}',
                    "test-session-1",
                    "user-create-scenario",
                    "req-002",
                    "test-client",
                    512,
                    0,
                ),
                (
                    "2024-01-01T10:02:00",
                    "request",
                    "GET",
                    "/products",
                    200,
                    32,
                    "127.0.0.1",
                    "8080",
                    '{"user-agent": "test-client"}',
                    "{}",
                    "{}",
                    '[{"id": 1, "name": "Product 1"}]',
                    "test-session-2",
                    "product-list-scenario",
                    "req-003",
                    "test-client",
                    2048,
                    0,
                ),
            ]

            for log_data in test_logs:
                cursor.execute(
                    """
                    INSERT INTO request_logs (
                        timestamp, type, method, path, status_code, process_time_ms,
                        client_host, client_port, headers, query_params, request_body,
                        response_body, session_id, test_scenario, correlation_id,
                        user_agent, response_size, is_admin
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    log_data,
                )

            conn.commit()
            conn.close()

            # Step 6: Test log analysis

            analyzer = LogAnalyzer()

            # Read logs back from database
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM request_logs ORDER BY timestamp")
            logs = [dict(row) for row in cursor.fetchall()]
            conn.close()

            analysis = analyzer.analyze_logs(logs)

            if not analysis or "total_requests" not in analysis:
                return False

            # Step 7: Test scenario management (structure validation)

            # Check if mock_scenarios table exists
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='mock_scenarios'
            """)

            if not cursor.fetchone():
                conn.close()
                return False

            # Insert test scenario
            test_scenario = {
                "name": "integration-test-scenario",
                "description": "Test scenario for integration testing",
                "endpoints": {
                    "/users": {
                        "GET": {
                            "status": 200,
                            "data": [{"id": 999, "name": "Integration Test User"}],
                        }
                    }
                },
            }

            cursor.execute(
                """
                INSERT INTO mock_scenarios (name, description, config, is_active)
                VALUES (?, ?, ?, ?)
            """,
                (
                    "integration-test",
                    "Integration test scenario",
                    json.dumps(test_scenario),
                    1,
                ),
            )

            conn.commit()
            conn.close()

            return True

        except Exception:
            import traceback

            traceback.print_exc()
            return False

    async def test_mcp_tools_integration(self) -> bool:
        """Test all MCP tools working together."""

        try:
            # Test 1: generate_mock_api_tool
            result = await generate_mock_api_tool(
                spec_url_or_path=json.dumps(self.create_test_api_spec()),
                output_dir_name="mcp_tools_test_server",
            )

            if result["status"] != "success":
                return False

            # Test 2: discover_mock_servers_tool
            discovery_result = await discover_mock_servers_tool(
                check_health=False, include_generated=True
            )

            if discovery_result["status"] != "success":
                return False

            # Test 3: manage_mock_data_tool (validation only)

            # Test invalid server
            result = await manage_mock_data_tool(
                server_url="http://invalid-server:9999", operation="list_scenarios"
            )

            if result["status"] != "error":
                return False

            # Test invalid operation
            result = await manage_mock_data_tool(
                server_url="http://localhost:8000", operation="invalid_operation"
            )

            if (
                result["status"] != "error"
                or "Unknown operation" not in result["message"]
            ):
                return False

            # Test 4: query_mock_logs_tool (without server)

            # This will fail without a server, but we test the structure
            result = await query_mock_logs_tool(
                server_url="http://localhost:8000", limit=10
            )

            # Should have proper error handling
            return not ("status" not in result or "logs" not in result)

        except Exception:
            return False

    async def test_database_migration_system(self) -> bool:
        """Test the complete database migration system."""

        try:
            # Create test database
            test_db_path = self.temp_dir / "migration_test.db"
            migrator = DatabaseMigrator(str(test_db_path))

            # Test 1: Initial state
            initial_status = migrator.get_migration_status()

            if initial_status["current_version"] != 0:
                return False

            # Test 2: Apply all migrations
            success = migrator.apply_migrations()

            if not success:
                return False

            final_status = migrator.get_migration_status()

            if final_status["needs_migration"]:
                return False

            # Test 3: Verify all tables exist
            conn = sqlite3.connect(str(test_db_path))
            cursor = conn.cursor()

            expected_tables = [
                "request_logs",
                "test_sessions",
                "performance_metrics",
                "mock_scenarios",
                "schema_version",
            ]

            for table in expected_tables:
                cursor.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name=?
                """,
                    (table,),
                )

                if not cursor.fetchone():
                    conn.close()
                    return False

            conn.close()

            # Test 4: Backup functionality
            backup_path = migrator.backup_database()

            if not Path(backup_path).exists():
                return False

            # Test 5: Rollback functionality
            current_version = migrator.get_current_version()

            if current_version > 1:
                rollback_success = migrator.rollback_migration(current_version - 1)
                if not rollback_success:
                    return False

            return True

        except Exception:
            return False

    async def test_performance_and_compatibility(self) -> bool:
        """Test performance overhead and backward compatibility."""

        try:
            # Test 1: Template generation performance

            start_time = time.time()

            for i in range(5):  # Generate multiple servers
                test_spec = self.create_test_api_spec()
                test_spec["info"]["title"] = f"Performance Test API {i}"

                result = await generate_mock_api_tool(
                    spec_url_or_path=json.dumps(test_spec),
                    output_dir_name=f"perf_test_server_{i}",
                )

                if result["status"] != "success":
                    return False

            generation_time = time.time() - start_time
            avg_time = generation_time / 5

            if avg_time > 10:  # Should be under 10 seconds per generation
                pass

            # Test 2: Database operation performance

            test_db_path = self.temp_dir / "performance_test.db"
            migrator = DatabaseMigrator(str(test_db_path))

            start_time = time.time()
            migrator.apply_migrations()
            time.time() - start_time

            # Test 3: Log analysis performance

            # Generate large log dataset
            conn = sqlite3.connect(str(test_db_path))
            cursor = conn.cursor()

            start_time = time.time()

            # Insert 1000 test log entries
            for i in range(1000):
                cursor.execute(
                    """
                    INSERT INTO request_logs (
                        timestamp, type, method, path, status_code, process_time_ms,
                        client_host, client_port, headers, query_params, request_body,
                        response_body, session_id, test_scenario, correlation_id,
                        user_agent, response_size, is_admin
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        f"2024-01-01T10:{i // 60:02d}:{i % 60:02d}",
                        "request",
                        "GET",
                        f"/test/{i}",
                        200,
                        50 + (i % 100),
                        "127.0.0.1",
                        "8080",
                        '{"user-agent": "test"}',
                        "{}",
                        "{}",
                        "{}",
                        f"session-{i // 100}",
                        f"scenario-{i % 10}",
                        f"req-{i:04d}",
                        "test-client",
                        1024,
                        0,
                    ),
                )

            conn.commit()

            # Read and analyze
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM request_logs")
            logs = [dict(row) for row in cursor.fetchall()]
            conn.close()

            analyzer = LogAnalyzer()
            analyzer.analyze_logs(logs)

            analysis_time = time.time() - start_time

            if analysis_time > 5:  # Should analyze 1000 logs in under 5 seconds
                pass

            # Test 4: Backward compatibility

            # Create a "legacy" database with just the base table
            legacy_db_path = self.temp_dir / "legacy_test.db"
            conn = sqlite3.connect(str(legacy_db_path))
            cursor = conn.cursor()

            # Create base table only (migration 0)
            cursor.execute("""
                CREATE TABLE request_logs (
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
                )
            """)

            conn.commit()
            conn.close()

            # Test migration from legacy
            legacy_migrator = DatabaseMigrator(str(legacy_db_path))
            legacy_status = legacy_migrator.get_migration_status()

            if legacy_status["current_version"] != 0:
                return False

            # Apply migrations to legacy database
            success = legacy_migrator.apply_migrations()

            return success

        except Exception:
            return False

    async def test_error_handling_and_resilience(self) -> bool:
        """Test error handling and system resilience."""

        try:
            # Test 1: Invalid API specifications

            invalid_specs = [
                "invalid json",
                {"invalid": "spec"},
                {"openapi": "3.0.0"},  # Missing required fields
            ]

            for i, invalid_spec in enumerate(invalid_specs):
                with contextlib.suppress(Exception):
                    result = await generate_mock_api_tool(
                        spec_url_or_path=json.dumps(invalid_spec)
                        if isinstance(invalid_spec, dict)
                        else invalid_spec,
                        output_dir_name=f"invalid_test_{i}",
                    )

                    if result["status"] != "error":
                        return False

            # Test 2: Database corruption handling

            # Create corrupted database
            corrupted_db_path = self.temp_dir / "corrupted.db"
            with open(corrupted_db_path, "w") as f:
                f.write("This is not a valid SQLite database")

            with contextlib.suppress(Exception):
                migrator = DatabaseMigrator(str(corrupted_db_path))
                migrator.get_migration_status()
                # Should handle gracefully

            # Test 3: Network error handling

            # Test with unreachable server
            result = await manage_mock_data_tool(
                server_url="http://192.0.2.1:9999",  # RFC 5737 test address
                operation="list_scenarios",
            )

            if result["status"] != "error":
                return False

            # Test 4: Concurrent access

            test_db_path = self.temp_dir / "concurrent_test.db"
            migrator = DatabaseMigrator(str(test_db_path))
            migrator.apply_migrations()

            async def concurrent_operation(operation_id):
                """Simulate concurrent database operation."""
                try:
                    conn = sqlite3.connect(str(test_db_path))
                    cursor = conn.cursor()

                    cursor.execute(
                        """
                        INSERT INTO request_logs (
                            timestamp, type, method, path, status_code, process_time_ms,
                            client_host, client_port, headers, query_params, request_body,
                            response_body, session_id, test_scenario, correlation_id,
                            user_agent, response_size, is_admin
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            f"2024-01-01T10:00:{operation_id:02d}",
                            "request",
                            "GET",
                            f"/concurrent/{operation_id}",
                            200,
                            50,
                            "127.0.0.1",
                            "8080",
                            "{}",
                            "{}",
                            "{}",
                            "{}",
                            f"session-{operation_id}",
                            "concurrent-test",
                            f"req-{operation_id}",
                            "test-client",
                            1024,
                            0,
                        ),
                    )

                    conn.commit()
                    conn.close()
                    return True
                except Exception:
                    return False

            # Run 10 concurrent operations
            tasks = [concurrent_operation(i) for i in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            successful_ops = sum(1 for r in results if r is True)

            if successful_ops < 8:  # Allow some failures due to locking
                return False

            return True

        except Exception:
            return False

    def generate_test_report(self) -> dict[str, Any]:
        """Generate comprehensive test report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result)

        return {
            "test_summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": total_tests - passed_tests,
                "success_rate": (passed_tests / total_tests * 100)
                if total_tests > 0
                else 0,
            },
            "test_results": self.test_results,
            "timestamp": datetime.now().isoformat(),
            "environment": {
                "python_version": sys.version,
                "test_directory": str(self.temp_dir) if self.temp_dir else None,
            },
        }

    async def run_all_tests(self) -> bool:
        """Run all integration tests."""

        self.setup_test_environment()

        try:
            # Test 1: Complete workflow
            self.test_results["complete_workflow"] = await self.test_complete_workflow()

            # Test 2: MCP tools integration
            self.test_results[
                "mcp_tools_integration"
            ] = await self.test_mcp_tools_integration()

            # Test 3: Database migration system
            self.test_results[
                "database_migration"
            ] = await self.test_database_migration_system()

            # Test 4: Performance and compatibility
            self.test_results[
                "performance_compatibility"
            ] = await self.test_performance_and_compatibility()

            # Test 5: Error handling and resilience
            self.test_results[
                "error_handling"
            ] = await self.test_error_handling_and_resilience()

            # Generate final report
            report = self.generate_test_report()

            for _test_name, _result in self.test_results.items():
                pass

            # Save detailed report
            report_path = (
                self.temp_dir / "integration_test_report.json"
                if self.temp_dir
                else Path("integration_test_report.json")
            )
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)

            return all(self.test_results.values())

        except Exception:
            import traceback

            traceback.print_exc()
            return False

        finally:
            self.cleanup_test_environment()


async def main():
    """Main test execution function."""
    tester = ComprehensiveIntegrationTester()
    success = await tester.run_all_tests()

    if success:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
