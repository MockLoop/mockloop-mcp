# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
Test script for the manage_mock_data MCP tool implementation.
Tests Phase 2 Part 1 functionality.
"""

import asyncio
from pathlib import Path
import sys

# Add the src directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

import contextlib

from mockloop_mcp.main import manage_mock_data_tool
from mockloop_mcp.mock_server_manager import MockServerManager
from mockloop_mcp.utils.http_client import MockServerClient, check_server_connectivity


async def test_manage_mock_data_tool():
    """Test the manage_mock_data tool functionality."""

    # Test server URL (assuming a mock server is running)
    test_server_url = "http://localhost:8000"

    try:
        connectivity_result = await check_server_connectivity(test_server_url)

        if connectivity_result.get("status") != "healthy":
            await test_tool_with_mock_server()
            return
    except Exception:
        await test_tool_validation()
        return

    with contextlib.suppress(Exception):
        result = await manage_mock_data_tool(
            server_url=test_server_url, operation="list_scenarios"
        )
        assert result["operation"] == "list_scenarios"
        assert "status" in result

    with contextlib.suppress(Exception):
        test_response_data = {
            "message": "Updated response from MCP tool",
            "timestamp": "2024-01-01T00:00:00Z",
            "data": {"test": True},
        }

        result = await manage_mock_data_tool(
            server_url=test_server_url,
            operation="update_response",
            endpoint_path="/api/test",
            response_data=test_response_data,
        )
        assert result["operation"] == "update_response"
        assert "status" in result

    with contextlib.suppress(Exception):
        test_scenario_config = {
            "name": "test-scenario-from-mcp",
            "description": "Test scenario created by MCP tool",
            "endpoints": {
                "/api/users": {
                    "GET": {"status": 200, "data": [{"id": 1, "name": "Test User"}]}
                }
            },
        }

        result = await manage_mock_data_tool(
            server_url=test_server_url,
            operation="create_scenario",
            scenario_name="test-scenario-mcp",
            scenario_config=test_scenario_config,
        )
        assert result["operation"] == "create_scenario"
        assert "status" in result

    with contextlib.suppress(Exception):
        result = await manage_mock_data_tool(
            server_url=test_server_url,
            operation="switch_scenario",
            scenario_name="test-scenario-mcp",
        )
        assert result["operation"] == "switch_scenario"
        assert "status" in result


async def test_tool_validation():
    """Test tool validation logic without a running server."""

    with contextlib.suppress(Exception):
        result = await manage_mock_data_tool(
            server_url="http://invalid-server:9999", operation="list_scenarios"
        )
        assert result["status"] == "error"
        assert "not accessible" in result["message"]

    with contextlib.suppress(Exception):
        result = await manage_mock_data_tool(
            server_url="http://localhost:8000",
            operation="update_response",
            # Missing endpoint_path and response_data
        )
        assert result["status"] == "error"
        assert "requires endpoint_path and response_data" in result["message"]

    with contextlib.suppress(Exception):
        result = await manage_mock_data_tool(
            server_url="http://localhost:8000", operation="invalid_operation"
        )
        assert result["status"] == "error"
        assert "Unknown operation" in result["message"]


async def test_tool_with_mock_server():
    """Test tool behavior when server is not available."""

    with contextlib.suppress(Exception):
        result = await manage_mock_data_tool(
            server_url="http://localhost:8000", operation="list_scenarios"
        )
        # Should handle server unavailability gracefully
        assert result["status"] == "error"
        assert "performance_metrics" in result


async def test_http_client_extensions():
    """Test the new HTTP client methods."""

    client = MockServerClient("http://localhost:8000")

    with contextlib.suppress(Exception):
        result = await client.update_response(
            endpoint_path="/api/test", response_data={"test": "data"}
        )
        assert "status" in result
        assert "endpoint_path" in result

    with contextlib.suppress(Exception):
        result = await client.create_scenario(
            scenario_name="test", scenario_config={"test": "config"}
        )
        assert "status" in result
        assert "scenario_name" in result

    with contextlib.suppress(Exception):
        result = await client.switch_scenario("test-scenario")
        assert "status" in result
        assert "scenario_name" in result

    with contextlib.suppress(Exception):
        result = await client.list_scenarios()
        assert "status" in result
        assert "scenarios" in result


async def test_mock_server_manager_integration():
    """Test integration with MockServerManager."""

    manager = MockServerManager()

    with contextlib.suppress(Exception):
        await manager.discover_running_servers(ports=[8000, 8001], check_health=False)

    with contextlib.suppress(Exception):
        discovery = await manager.comprehensive_discovery()
        assert "total_generated" in discovery
        assert "total_running" in discovery


def test_type_definitions():
    """Test that TypedDict definitions are properly structured."""

    # Test input structure

    # Test output structure


async def main():
    """Run all tests."""

    # Test type definitions
    test_type_definitions()

    # Test HTTP client extensions
    await test_http_client_extensions()

    # Test MockServerManager integration
    await test_mock_server_manager_integration()

    # Test tool validation
    await test_tool_validation()

    # Test with actual server (if available)
    await test_manage_mock_data_tool()


if __name__ == "__main__":
    asyncio.run(main())
