# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
Test script to validate Phase 1 MockLoop MCP enhancements.
This script tests the new admin API endpoints and database schema migration.
"""

from pathlib import Path
import sys

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mockloop_mcp.database_migration import DatabaseMigrator
from mockloop_mcp.generator import generate_mock_api


def test_mock_generation():
    """Test generating a mock server with Phase 1 enhancements."""

    # Simple test API spec
    test_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Phase 1 Test API",
            "version": "1.0.0",
            "description": "Test API for Phase 1 enhancements",
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
                }
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
        },
    }

    # Generate the mock server
    output_dir = generate_mock_api(
        test_spec,
        mock_server_name="phase1_test_api",
        auth_enabled=True,
        webhooks_enabled=True,
        admin_ui_enabled=True,
        storage_enabled=True,
    )

    # Verify key files exist
    expected_files = [
        "main.py",
        "logging_middleware.py",
        "templates/admin.html",
        "requirements_mock.txt",
        "Dockerfile",
        "docker-compose.yml",
    ]

    for file_path in expected_files:
        full_path = output_dir / file_path
        assert full_path.exists(), f"Expected file {file_path} does not exist"

    # Check if the new admin endpoints are in main.py
    main_py_content = (output_dir / "main.py").read_text()

    required_endpoints = [
        "/api/requests",
        "/api/debug",
        "admin_app",
    ]

    for endpoint in required_endpoints:
        assert endpoint in main_py_content, (
            f"Required endpoint {endpoint} not found in main.py"
        )

    # Check if the admin UI has the new analytics tab
    admin_html_content = (output_dir / "templates" / "admin.html").read_text()

    required_ui_elements = [
        "Phase 1 Test API Admin UI",
        "Request Logs",
        "total-requests",  # ID for total requests counter
        "active-webhooks",  # ID for webhooks counter
        "Server Status",  # Server status section
    ]

    for element in required_ui_elements:
        assert element in admin_html_content, (
            f"Required UI element {element} not found in admin.html"
        )

    # Check middleware enhancements
    middleware_content = (output_dir / "logging_middleware.py").read_text()

    required_middleware_features = [
        "LoggingMiddleware",
        "request_logs",
        "sqlite3",
        "process_time",
        "client_host",
    ]

    for feature in required_middleware_features:
        assert feature in middleware_content, (
            f"Required middleware feature {feature} not found"
        )


def test_database_migration():
    """Test database migration functionality."""

    # First generate a mock server to get the directory
    test_mock_generation()

    # Simulate database path - use a test-specific path
    from tempfile import mkdtemp

    temp_dir = Path(mkdtemp())
    db_path = temp_dir / "db" / "request_logs.db"
    db_path.parent.mkdir(exist_ok=True)

    # Test migration status
    migrator = DatabaseMigrator(str(db_path))

    # Get initial status
    status = migrator.get_migration_status()
    assert isinstance(status, dict), "Migration status should be a dictionary"

    # Apply migrations
    if status["needs_migration"]:
        success = migrator.apply_migrations()
        assert success, "Migration should succeed"

    # Check final status
    final_status = migrator.get_migration_status()
    assert isinstance(final_status, dict), (
        "Final migration status should be a dictionary"
    )

    # Test backup functionality
    backup_path = migrator.backup_database()
    assert Path(backup_path).exists(), "Backup file should exist"


def test_log_analyzer_integration():
    """Test LogAnalyzer integration."""

    from mockloop_mcp.log_analyzer import LogAnalyzer, quick_analyze

    # Test with sample log data
    sample_logs = [
        {
            "id": 1,
            "timestamp": "2024-01-01T10:00:00",
            "method": "GET",
            "path": "/users",
            "status_code": 200,
            "process_time_ms": 45,
            "client_host": "127.0.0.1",
            "headers": {"user-agent": "test-client"},
            "session_id": "test-session-1",
            "test_scenario": "user_list_test",
        },
        {
            "id": 2,
            "timestamp": "2024-01-01T10:01:00",
            "method": "GET",
            "path": "/users/123",
            "status_code": 200,
            "process_time_ms": 32,
            "client_host": "127.0.0.1",
            "headers": {"user-agent": "test-client"},
            "session_id": "test-session-1",
            "test_scenario": "user_detail_test",
        },
        {
            "id": 3,
            "timestamp": "2024-01-01T10:02:00",
            "method": "POST",
            "path": "/users",
            "status_code": 400,
            "process_time_ms": 15,
            "client_host": "127.0.0.1",
            "headers": {"user-agent": "test-client"},
            "session_id": "test-session-2",
            "test_scenario": "user_create_error_test",
        },
    ]

    # Test analysis
    analyzer = LogAnalyzer()
    analysis = analyzer.analyze_logs(sample_logs)

    # Verify analysis results
    expected_keys = [
        "total_requests",
        "time_range",
        "methods",
        "status_codes",
        "endpoints",
        "performance",
        "errors",
        "patterns",
        "insights",
    ]

    for key in expected_keys:
        assert key in analysis, f"Expected key {key} not found in analysis results"

    # Test filtering
    filtered_logs = analyzer.filter_logs(sample_logs, method="GET", include_admin=False)

    assert len(filtered_logs) == 2, f"Expected 2 GET requests, got {len(filtered_logs)}"

    # Test quick analysis function
    quick_result = quick_analyze(sample_logs)
    assert "total_requests" in quick_result, (
        "Quick analysis should include total_requests"
    )


def main():
    """Run all Phase 1 integration tests."""

    # Test 1: Mock generation with new features
    test_mock_generation()

    # Test 2: Database migration
    test_database_migration()

    # Test 3: LogAnalyzer integration
    test_log_analyzer_integration()

    print("All Phase 1 integration tests passed!")


if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except Exception as e:
        print(f"Tests failed: {e}")
        sys.exit(1)
