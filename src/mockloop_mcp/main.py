# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

import argparse
import logging
import sys
import time
import uuid
from functools import wraps
from typing import Any, TypedDict

# Configure logger for this module
logger = logging.getLogger(__name__)

# Handle imports for different execution contexts
# This allows the script to be run directly (e.g., by 'mcp dev')
# or imported as part of a package.
if __package__ is None or __package__ == "":
    # Likely executed by 'mcp dev' or as a standalone script.
    # Assumes 'src/mockloop_mcp/' is in sys.path.
    from generator import APIGenerationError, generate_mock_api
    from log_analyzer import LogAnalyzer
    from mock_server_manager import MockServerManager
    from parser import APIParsingError, load_api_specification
    from mcp_audit_logger import create_audit_logger, MCPAuditLogger
    from mcp_compliance import create_compliance_reporter, MCPComplianceReporter
    from mcp_context import (
        initialize_context_manager,
        get_context_manager,
        create_test_session_context,
        create_workflow_context,
        create_agent_context,
        get_context_data,
        update_context_data,
        create_context_snapshot,
        restore_context_snapshot,
        list_contexts_by_type,
        get_global_context_data,
        update_global_context_data,
        ContextType,
        ContextStatus,
    )
    from mcp_prompts import (
        analyze_openapi_for_testing,
        generate_scenario_config,
        optimize_scenario_for_load,
        generate_error_scenarios,
        generate_security_test_scenarios,
    )

    # Import MCP Tools for automated test execution
    from mcp_tools import (
        validate_scenario_config,
        deploy_scenario,
        switch_scenario,
        list_active_scenarios,
        execute_test_plan,
        run_test_iteration,
        run_load_test,
        run_security_test,
        analyze_test_results,
        generate_test_report,
        compare_test_runs,
        get_performance_metrics,
        create_test_session,
        end_test_session,
        schedule_test_suite,
        monitor_test_progress,
    )

    # Import MCP Resources (placeholder for future community scenarios)
    from mcp_resources import (
        get_4xx_client_errors_pack,
        get_5xx_server_errors_pack,
        get_network_timeouts_pack,
        get_rate_limiting_pack,
        get_load_testing_pack,
        get_stress_testing_pack,
        get_spike_testing_pack,
        get_endurance_testing_pack,
        get_auth_bypass_pack,
        get_injection_attacks_pack,
        get_xss_attacks_pack,
        get_csrf_attacks_pack,
        get_edge_cases_pack,
        get_data_validation_pack,
        get_workflow_testing_pack,
        list_scenario_packs,
    )
    from community_scenarios import (
        get_community_architecture_info,
    )
else:
    # Imported as part of the 'src.mockloop_mcp' package.
    from .generator import APIGenerationError, generate_mock_api
    from .log_analyzer import LogAnalyzer
    from .mock_server_manager import MockServerManager
    from .parser import APIParsingError, load_api_specification
    from .mcp_audit_logger import create_audit_logger, MCPAuditLogger
    from .mcp_compliance import create_compliance_reporter, MCPComplianceReporter
    from .mcp_context import (
        initialize_context_manager,
        get_context_manager,
        create_test_session_context,
        create_workflow_context,
        create_agent_context,
        get_context_data,
        update_context_data,
        create_context_snapshot,
        restore_context_snapshot,
        list_contexts_by_type,
        get_global_context_data,
        update_global_context_data,
        ContextType,
        ContextStatus,
    )
    from .mcp_prompts import (
        analyze_openapi_for_testing,
        generate_scenario_config,
        optimize_scenario_for_load,
        generate_error_scenarios,
        generate_security_test_scenarios,
    )

    # Import MCP Tools for automated test execution
    from .mcp_tools import (
        validate_scenario_config,
        deploy_scenario,
        switch_scenario,
        list_active_scenarios,
        execute_test_plan,
        run_test_iteration,
        run_load_test,
        run_security_test,
        analyze_test_results,
        generate_test_report,
        compare_test_runs,
        get_performance_metrics,
        create_test_session,
        end_test_session,
        schedule_test_suite,
        monitor_test_progress,
    )

    # Import MCP Resources (placeholder for future community scenarios)
    from .mcp_resources import (
        get_4xx_client_errors_pack,
        get_5xx_server_errors_pack,
        get_network_timeouts_pack,
        get_rate_limiting_pack,
        get_load_testing_pack,
        get_stress_testing_pack,
        get_spike_testing_pack,
        get_endurance_testing_pack,
        get_auth_bypass_pack,
        get_injection_attacks_pack,
        get_xss_attacks_pack,
        get_csrf_attacks_pack,
        get_edge_cases_pack,
        get_data_validation_pack,
        get_workflow_testing_pack,
        list_scenario_packs,
    )
    from .community_scenarios import (
        get_community_architecture_info,
    )

# Import FastMCP and Context from the MCP SDK
from mcp.server.fastmcp import (
    FastMCP,
)
from mcp.types import TextContent

# MCP Audit Logging Configuration
MCP_AUDIT_ENABLED = True  # Can be configured via environment variable
MCP_AUDIT_DB_PATH = "mcp_audit.db"
MCP_COMPLIANCE_REPORTS_DIR = "compliance_reports"

# Global audit logger instance
_audit_logger: MCPAuditLogger | None = None
_compliance_reporter: MCPComplianceReporter | None = None

# MCP Context Management Configuration
MCP_CONTEXT_DB_PATH = "mcp_context.db"

# Global context manager instance
_context_manager = None


def get_audit_logger() -> MCPAuditLogger | None:
    """Get the global audit logger instance."""
    global _audit_logger  # noqa: PLW0603
    if _audit_logger is None and MCP_AUDIT_ENABLED:
        try:
            _audit_logger = create_audit_logger(
                db_path=MCP_AUDIT_DB_PATH,
                session_id=str(uuid.uuid4()),
                user_id="mcp_server",
                enable_performance_tracking=True,
                enable_content_hashing=True,
            )
        except Exception as e:
            logger.warning(f"Failed to initialize MCP audit logger: {e}")
    return _audit_logger


def get_compliance_reporter() -> MCPComplianceReporter | None:
    """Get the global compliance reporter instance."""
    global _compliance_reporter  # noqa: PLW0603
    if _compliance_reporter is None and MCP_AUDIT_ENABLED:
        try:
            _compliance_reporter = create_compliance_reporter(
                audit_db_path=MCP_AUDIT_DB_PATH,
                reports_output_dir=MCP_COMPLIANCE_REPORTS_DIR,
            )
        except Exception as e:
            logger.warning(f"Failed to initialize MCP compliance reporter: {e}")
    return _compliance_reporter


def get_context_manager():
    """Get the global context manager instance."""
    global _context_manager  # noqa: PLW0603
    if _context_manager is None:
        try:
            audit_logger = get_audit_logger()
            _context_manager = initialize_context_manager(
                db_path=MCP_CONTEXT_DB_PATH, audit_logger=audit_logger
            )
        except Exception as e:
            logger.warning(f"Failed to initialize MCP context manager: {e}")
            # Create a fallback context manager without audit logging
            _context_manager = initialize_context_manager(
                db_path=MCP_CONTEXT_DB_PATH, audit_logger=None
            )
    return _context_manager


def mcp_audit_tool(tool_name: str):
    """
    Decorator to add MCP audit logging to tool functions.

    Args:
        tool_name: Name of the MCP tool being audited
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            audit_logger = get_audit_logger()
            start_time = time.time()
            entry_id = None

            try:
                # Log tool execution start
                if audit_logger:
                    entry_id = audit_logger.log_tool_execution(
                        tool_name=tool_name,
                        input_parameters=kwargs,
                        data_sources=[],
                        compliance_tags=["mcp_tool"],
                        processing_purpose="mcp_tool_execution",
                        legal_basis="legitimate_interests",
                    )

                # Execute the original function
                result = await func(*args, **kwargs)

                # Log successful completion
                if audit_logger and entry_id:
                    execution_time_ms = (time.time() - start_time) * 1000
                    audit_logger.log_tool_execution(
                        tool_name=f"{tool_name}_completion",
                        input_parameters={"original_entry_id": entry_id},
                        execution_result={
                            "status": "success",
                            "result_type": type(result).__name__,
                        },
                        execution_time_ms=execution_time_ms,
                        data_sources=[],
                        compliance_tags=["mcp_tool", "completion"],
                        processing_purpose="mcp_tool_completion",
                        legal_basis="legitimate_interests",
                    )

                return result

            except Exception as e:
                # Log error
                if audit_logger and entry_id:
                    execution_time_ms = (time.time() - start_time) * 1000
                    audit_logger.log_tool_execution(
                        tool_name=f"{tool_name}_error",
                        input_parameters={"original_entry_id": entry_id},
                        execution_result={
                            "status": "error",
                            "error_type": type(e).__name__,
                        },
                        execution_time_ms=execution_time_ms,
                        data_sources=[],
                        compliance_tags=["mcp_tool", "error"],
                        processing_purpose="mcp_tool_error",
                        legal_basis="legitimate_interests",
                        error_details=str(e),
                    )
                raise

        return wrapper

    return decorator


# New TypedDict definitions for enhanced tools
class QueryMockLogsInput(TypedDict):
    server_url: str
    limit: int | None
    offset: int | None
    method: str | None
    path_pattern: str | None
    time_from: str | None
    time_to: str | None
    include_admin: bool | None
    analyze: bool | None


class QueryMockLogsOutput(TypedDict):
    status: str
    logs: list[dict[str, Any]]
    total_count: int
    analysis: dict[str, Any] | None
    message: str


class DiscoverMockServersInput(TypedDict):
    ports: list[int] | None
    check_health: bool | None
    include_generated: bool | None


class DiscoverMockServersOutput(TypedDict):
    status: str
    discovered_servers: list[dict[str, Any]]
    generated_mocks: list[dict[str, Any]]
    total_running: int
    total_generated: int
    message: str


class ManageMockDataInput(TypedDict):
    server_url: str
    operation: (
        str  # "update_response", "create_scenario", "switch_scenario", "list_scenarios"
    )
    endpoint_path: str | None
    response_data: dict[str, Any] | None
    scenario_name: str | None
    scenario_config: dict[str, Any] | None


class ManageMockDataOutput(TypedDict):
    status: str
    operation: str
    result: dict[str, Any]
    server_url: str
    message: str
    performance_metrics: dict[str, Any] | None


# Create an MCP server instance
# The name "MockLoop" will be visible in MCP clients like Claude Desktop.
server = FastMCP(
    name="MockLoop",
    description="Generates and manages mock API servers from specifications.",
    # dependencies=["fastapi", "uvicorn", "Jinja2", "PyYAML", "requests"] # Dependencies of the MCP server itself
)


@server.tool(
    name="generate_mock_api",
    description="Generates a FastAPI mock server from an API specification (e.g., OpenAPI). "
    "The mock server includes request/response logging and Docker support.",
)
@mcp_audit_tool("generate_mock_api")
async def generate_mock_api_tool(
    spec_url_or_path: str,
    output_dir_name: str | None = None,
    auth_enabled: bool = True,
    webhooks_enabled: bool = True,
    admin_ui_enabled: bool = True,
    storage_enabled: bool = True,
    business_port: int = 8000,
    admin_port: int | None = None,
    # ctx: Context # MCP Context, can be added if tool needs to report progress, etc.
) -> list[TextContent]:
    """
    MCP Tool to generate a mock API server.

    Args:
        spec_url_or_path: URL or local file path to the API specification.
        output_dir_name: Optional name for the generated mock server directory.
                         If None, a name is derived from the API title and version.
    """
    try:
        # Helper to robustly convert to boolean
        def _tool_to_bool(value: Any) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ("true", "yes", "1", "on")
            if isinstance(value, int):
                return value != 0
            return bool(value)

        # Convert boolean flags
        auth_enabled_bool = _tool_to_bool(auth_enabled)
        webhooks_enabled_bool = _tool_to_bool(webhooks_enabled)
        admin_ui_enabled_bool = _tool_to_bool(admin_ui_enabled)
        storage_enabled_bool = _tool_to_bool(storage_enabled)

        parsed_spec = load_api_specification(spec_url_or_path)

        generated_path = generate_mock_api(
            spec_data=parsed_spec,
            mock_server_name=output_dir_name,
            auth_enabled=auth_enabled_bool,
            webhooks_enabled=webhooks_enabled_bool,
            admin_ui_enabled=admin_ui_enabled_bool,
            storage_enabled=storage_enabled_bool,
            business_port=business_port,
            admin_port=admin_port,
        )

        resolved_path = str(generated_path.resolve())

        return [TextContent(
            type="text",
            text=f"Mock API server generated successfully at {resolved_path}. Navigate to this directory and use 'docker-compose up --build' to run it."
        )]

    except APIParsingError as e:
        return [TextContent(
            type="text",
            text=f"Error parsing API specification: {e}"
        )]
    except APIGenerationError as e:
        return [TextContent(
            type="text",
            text=f"Error generating mock API: {e}"
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"An unexpected error occurred: {e}"
        )]


@server.tool(
    name="query_mock_logs",
    description="Query and analyze request logs from a running MockLoop server. "
    "Supports filtering by method, path, time range, and provides optional analysis.",
)
@mcp_audit_tool("query_mock_logs")
async def query_mock_logs_tool(
    server_url: str,
    limit: int = 100,
    offset: int = 0,
    method: str | None = None,
    path_pattern: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    include_admin: bool = False,
    analyze: bool = True,
) -> QueryMockLogsOutput:
    """
    Query request logs from a MockLoop server with optional analysis.

    Args:
        server_url: URL of the mock server (e.g., "http://localhost:8000")
        limit: Maximum number of logs to return (default: 100)
        offset: Number of logs to skip for pagination (default: 0)
        method: Filter by HTTP method (e.g., "GET", "POST")
        path_pattern: Regex pattern to filter paths
        time_from: Start time filter (ISO format)
        time_to: End time filter (ISO format)
        include_admin: Include admin requests in results
        analyze: Perform analysis on the logs
    """
    try:
        # Initialize the mock server manager
        manager = MockServerManager()

        # Query logs from the server
        log_result = await manager.query_server_logs(
            server_url=server_url,
            limit=limit,
            offset=offset,
            method=method,
            path=path_pattern,
            include_admin=include_admin,
        )

        if log_result.get("status") != "success":
            return {
                "status": "error",
                "logs": [],
                "total_count": 0,
                "analysis": None,
                "message": f"Failed to query logs: {log_result.get('error', 'Unknown error')}",
            }

        logs = log_result.get("logs", [])

        # Apply additional filtering if needed
        if time_from or time_to or path_pattern:
            analyzer = LogAnalyzer()
            logs = analyzer.filter_logs(
                logs,
                method=method,
                path_pattern=path_pattern,
                time_from=time_from,
                time_to=time_to,
                include_admin=include_admin,
            )

        analysis = None
        if analyze and logs:
            analyzer = LogAnalyzer()
            analysis = analyzer.analyze_logs(logs)

        return {
            "status": "success",
            "logs": logs,
            "total_count": len(logs),
            "analysis": analysis,
            "message": f"Successfully retrieved {len(logs)} log entries from {server_url}",
        }

    except Exception as e:
        import traceback

        traceback.format_exc()
        return {
            "status": "error",
            "logs": [],
            "total_count": 0,
            "analysis": None,
            "message": f"Error querying logs: {e!s}",
        }


@server.tool(
    name="discover_mock_servers",
    description="Discover running MockLoop servers and generated mock configurations. "
    "Scans common ports and matches with generated mocks.",
)
@mcp_audit_tool("discover_mock_servers")
async def discover_mock_servers_tool(
    ports: list[int] | None = None,
    check_health: bool = True,
    include_generated: bool = True,
) -> DiscoverMockServersOutput:
    """
    Discover running mock servers and generated mock configurations.

    Args:
        ports: List of ports to scan (default: common ports 8000-8005, 3000-3001, 5000-5001)
        check_health: Perform health checks on discovered servers
        include_generated: Include information about generated but not running mocks
    """
    try:
        # Initialize the mock server manager
        manager = MockServerManager()

        if include_generated:
            # Perform comprehensive discovery
            discovery_result = await manager.comprehensive_discovery()

            return {
                "status": "success",
                "discovered_servers": discovery_result.get("matched_servers", [])
                + discovery_result.get("unmatched_running_servers", []),
                "generated_mocks": discovery_result.get("not_running_mocks", []),
                "total_running": discovery_result.get("total_running", 0),
                "total_generated": discovery_result.get("total_generated", 0),
                "message": f"Discovered {discovery_result.get('total_running', 0)} running servers "
                f"and {discovery_result.get('total_generated', 0)} generated mocks",
            }
        else:
            # Just discover running servers
            running_servers = await manager.discover_running_servers(
                ports, check_health
            )

            return {
                "status": "success",
                "discovered_servers": running_servers,
                "generated_mocks": [],
                "total_running": len(running_servers),
                "total_generated": 0,
                "message": f"Discovered {len(running_servers)} running servers",
            }

    except Exception as e:
        import traceback

        traceback.format_exc()
        return {
            "status": "error",
            "discovered_servers": [],
            "generated_mocks": [],
            "total_running": 0,
            "total_generated": 0,
            "message": f"Error discovering servers: {e!s}",
        }


@server.tool(
    name="manage_mock_data",
    description="Manage dynamic response data and scenarios for MockLoop servers. "
    "Supports updating responses, creating scenarios, switching scenarios, and listing scenarios.",
)
@mcp_audit_tool("manage_mock_data")
async def manage_mock_data_tool(
    server_url: str,
    operation: str,
    endpoint_path: str | None = None,
    response_data: dict[str, Any] | None = None,
    scenario_name: str | None = None,
    scenario_config: dict[str, Any] | None = None,
) -> ManageMockDataOutput:
    """
    Manage mock data and scenarios for dynamic response management.

    Args:
        server_url: URL of the mock server (e.g., "http://localhost:8000")
        operation: Operation to perform ("update_response", "create_scenario", "switch_scenario", "list_scenarios")
        endpoint_path: Specific endpoint to modify (required for update_response)
        response_data: New response data for updates (required for update_response)
        scenario_name: Scenario identifier (required for create_scenario, switch_scenario)
        scenario_config: Complete scenario configuration (required for create_scenario)
    """
    import time

    # Handle imports for different execution contexts
    if __package__ is None or __package__ == "":
        from utils.http_client import MockServerClient, check_server_connectivity
    else:
        from .utils.http_client import MockServerClient, check_server_connectivity

    start_time = time.time()

    try:
        # Validate server accessibility first
        connectivity_result = await check_server_connectivity(server_url)
        if connectivity_result.get("status") != "healthy":
            return {
                "status": "error",
                "operation": operation,
                "result": {},
                "server_url": server_url,
                "message": f"Server not accessible: {connectivity_result.get('error', 'Unknown error')}",
                "performance_metrics": None,
            }

        # Initialize the mock server manager for server validation
        manager = MockServerManager()

        # Validate that this is a MockLoop server
        server_status = await manager.get_server_status(server_url)
        if not server_status.get("is_mockloop_server", False):
            return {
                "status": "error",
                "operation": operation,
                "result": {},
                "server_url": server_url,
                "message": "Target server is not a MockLoop server or does not support admin operations",
                "performance_metrics": None,
            }

        # Initialize HTTP client
        client = MockServerClient(server_url)

        # Perform the requested operation
        if operation == "update_response":
            if not endpoint_path or response_data is None:
                return {
                    "status": "error",
                    "operation": operation,
                    "result": {},
                    "server_url": server_url,
                    "message": "update_response operation requires endpoint_path and response_data parameters",
                    "performance_metrics": None,
                }

            # Get current response for before/after comparison
            before_state = {}
            try:
                # Try to get current endpoint info (this would need to be implemented in the server)
                debug_info = await client.get_debug_info()
                if debug_info.get("status") == "success":
                    before_state = (
                        debug_info.get("debug_info", {})
                        .get("endpoints", {})
                        .get(endpoint_path, {})
                    )
            except Exception as e:
                logger.debug(
                    f"Failed to get before state for endpoint {endpoint_path}: {e}"
                )
                # Continue without before state if not available

            result = await client.update_response(endpoint_path, response_data)

            if result.get("status") == "success":
                # Get after state
                after_state = {}
                try:
                    debug_info = await client.get_debug_info()
                    if debug_info.get("status") == "success":
                        after_state = (
                            debug_info.get("debug_info", {})
                            .get("endpoints", {})
                            .get(endpoint_path, {})
                        )
                except Exception as e:
                    logger.debug(
                        f"Failed to get after state for endpoint {endpoint_path}: {e}"
                    )

                result["before_state"] = before_state
                result["after_state"] = after_state

                message = f"Successfully updated response for {endpoint_path}"
            else:
                message = f"Failed to update response for {endpoint_path}: {result.get('error', 'Unknown error')}"

        elif operation == "create_scenario":
            if not scenario_name or not scenario_config:
                return {
                    "status": "error",
                    "operation": operation,
                    "result": {},
                    "server_url": server_url,
                    "message": "create_scenario operation requires scenario_name and scenario_config parameters",
                    "performance_metrics": None,
                }

            result = await client.create_scenario(scenario_name, scenario_config)

            if result.get("status") == "success":
                message = f"Successfully created scenario '{scenario_name}'"
            else:
                message = f"Failed to create scenario '{scenario_name}': {result.get('error', 'Unknown error')}"

        elif operation == "switch_scenario":
            if not scenario_name:
                return {
                    "status": "error",
                    "operation": operation,
                    "result": {},
                    "server_url": server_url,
                    "message": "switch_scenario operation requires scenario_name parameter",
                    "performance_metrics": None,
                }

            # Get current scenario before switching
            current_result = await client.get_current_scenario()
            before_scenario = (
                current_result.get("current_scenario", {})
                if current_result.get("status") == "success"
                else {}
            )

            result = await client.switch_scenario(scenario_name)

            if result.get("status") == "success":
                result["before_scenario"] = before_scenario
                message = f"Successfully switched to scenario '{scenario_name}'"
                if result.get("previous_scenario"):
                    message += f" (from '{result['previous_scenario']}')"
            else:
                message = f"Failed to switch to scenario '{scenario_name}': {result.get('error', 'Unknown error')}"

        elif operation == "list_scenarios":
            result = await client.list_scenarios()

            if result.get("status") == "success":
                scenarios = result.get("scenarios", [])
                # Get current scenario info
                current_result = await client.get_current_scenario()
                if current_result.get("status") == "success":
                    result["current_scenario"] = current_result.get("current_scenario")

                message = f"Successfully retrieved {len(scenarios)} scenarios"
            else:
                message = (
                    f"Failed to list scenarios: {result.get('error', 'Unknown error')}"
                )

        else:
            return {
                "status": "error",
                "operation": operation,
                "result": {},
                "server_url": server_url,
                "message": f"Unknown operation '{operation}'. Supported operations: update_response, create_scenario, switch_scenario, list_scenarios",
                "performance_metrics": None,
            }

        # Calculate performance metrics
        end_time = time.time()
        performance_metrics = {
            "operation_time_ms": round((end_time - start_time) * 1000, 2),
            "server_response_time": connectivity_result.get(
                "response_time_ms", "unknown"
            ),
            "timestamp": time.time(),
        }

        return {
            "status": result.get("status", "unknown"),
            "operation": operation,
            "result": result,
            "server_url": server_url,
            "message": message,
            "performance_metrics": performance_metrics,
        }

    except Exception as e:
        import traceback

        traceback.format_exc()

        end_time = time.time()
        performance_metrics = {
            "operation_time_ms": round((end_time - start_time) * 1000, 2),
            "error": True,
            "timestamp": time.time(),
        }

        return {
            "status": "error",
            "operation": operation,
            "result": {},
            "server_url": server_url,
            "message": f"Error managing mock data: {e!s}",
            "performance_metrics": performance_metrics,
        }


# Register MCP Tools for automated test execution


@server.tool(
    name="validate_scenario_config",
    description="Validates scenario configuration before deployment. "
    "Performs comprehensive validation including required fields, endpoint configurations, and test parameters.",
)
@mcp_audit_tool("validate_scenario_config")
async def validate_scenario_config_tool(
    scenario_config: dict[str, Any],
    strict_validation: bool = True,
    check_endpoints: bool = True,
) -> dict[str, Any]:
    """Validate scenario configuration before deployment."""
    return await validate_scenario_config(
        scenario_config, strict_validation, check_endpoints
    )


@server.tool(
    name="deploy_scenario",
    description="Deploys scenario to MockLoop server. "
    "Validates configuration, deploys to server, and activates the scenario.",
)
@mcp_audit_tool("deploy_scenario")
async def deploy_scenario_tool(
    server_url: str,
    scenario_config: dict[str, Any],
    validate_before_deploy: bool = True,
    force_deploy: bool = False,
) -> dict[str, Any]:
    """Deploy scenario to MockLoop server."""
    return await deploy_scenario(
        server_url, scenario_config, validate_before_deploy, force_deploy
    )


@server.tool(
    name="switch_scenario",
    description="Switches active scenario on a server. "
    "Changes the currently active scenario and optionally verifies the switch was successful.",
)
@mcp_audit_tool("switch_scenario")
async def switch_scenario_tool(
    server_url: str, scenario_name: str, verify_switch: bool = True
) -> dict[str, Any]:
    """Switch active scenario on a server."""
    return await switch_scenario(server_url, scenario_name, verify_switch)


@server.tool(
    name="list_active_scenarios",
    description="Lists all active scenarios across servers. "
    "Discovers running servers and retrieves their currently active scenarios.",
)
@mcp_audit_tool("list_active_scenarios")
async def list_active_scenarios_tool(
    server_urls: list[str] | None = None, discover_servers: bool = True
) -> dict[str, Any]:
    """List all active scenarios across servers."""
    return await list_active_scenarios(server_urls, discover_servers)


@server.tool(
    name="execute_test_plan",
    description="Combines scenario generation and deployment in one operation. "
    "Analyzes OpenAPI spec, generates scenarios, deploys them, and optionally executes tests immediately.",
)
@mcp_audit_tool("execute_test_plan")
async def execute_test_plan_tool(
    openapi_spec: dict[str, Any],
    server_url: str,
    test_focus: str = "comprehensive",
    auto_generate_scenarios: bool = True,
    execute_immediately: bool = True,
) -> dict[str, Any]:
    """Execute complete test plan from OpenAPI specification."""
    return await execute_test_plan(
        openapi_spec,
        server_url,
        test_focus,
        auto_generate_scenarios,
        execute_immediately,
    )


@server.tool(
    name="run_test_iteration",
    description="Executes a single test iteration with monitoring. "
    "Runs a test iteration for a specified duration while collecting performance metrics and logs.",
)
@mcp_audit_tool("run_test_iteration")
async def run_test_iteration_tool(
    server_url: str,
    scenario_name: str,
    duration_seconds: int = 300,
    monitor_performance: bool = True,
    collect_logs: bool = True,
) -> dict[str, Any]:
    """Execute a single test iteration with monitoring."""
    return await run_test_iteration(
        server_url, scenario_name, duration_seconds, monitor_performance, collect_logs
    )


@server.tool(
    name="run_load_test",
    description="Executes load testing with configurable parameters. "
    "Performs comprehensive load testing with ramp-up, steady state, and ramp-down phases.",
)
@mcp_audit_tool("run_load_test")
async def run_load_test_tool(
    server_url: str,
    target_load: int,
    duration_seconds: int = 300,
    ramp_up_time: int = 60,
    scenario_name: str | None = None,
) -> dict[str, Any]:
    """Execute load testing with configurable parameters."""
    return await run_load_test(
        server_url, target_load, duration_seconds, ramp_up_time, scenario_name
    )


@server.tool(
    name="run_security_test",
    description="Executes security testing scenarios for vulnerability assessment. "
    "Performs comprehensive security testing including authentication, authorization, and injection attacks.",
)
@mcp_audit_tool("run_security_test")
async def run_security_test_tool(
    server_url: str,
    api_spec: dict[str, Any],
    security_focus: list[str] | None = None,
    compliance_requirements: list[str] | None = None,
    scenario_name: str | None = None,
) -> dict[str, Any]:
    """Execute security testing scenarios."""
    return await run_security_test(
        server_url, api_spec, security_focus, compliance_requirements, scenario_name
    )


@server.tool(
    name="analyze_test_results",
    description="Analyzes test results and provides comprehensive insights. "
    "Performs statistical analysis, identifies trends, and generates actionable recommendations.",
)
@mcp_audit_tool("analyze_test_results")
async def analyze_test_results_tool(
    test_results: list[dict[str, Any]],
    analysis_type: str = "comprehensive",
    include_recommendations: bool = True,
) -> dict[str, Any]:
    """Analyze test results and provide insights."""
    return await analyze_test_results(
        test_results, analysis_type, include_recommendations
    )


@server.tool(
    name="generate_test_report",
    description="Generates formatted test reports in various formats. "
    "Creates comprehensive reports with charts, analysis, and recommendations.",
)
@mcp_audit_tool("generate_test_report")
async def generate_test_report_tool(
    test_results: list[dict[str, Any]],
    report_format: str = "comprehensive",
    include_charts: bool = True,
    output_format: str = "json",
) -> dict[str, Any]:
    """Generate formatted test reports."""
    return await generate_test_report(
        test_results, report_format, include_charts, output_format
    )


@server.tool(
    name="compare_test_runs",
    description="Compares multiple test runs to identify performance changes. "
    "Performs statistical comparison and identifies regressions or improvements.",
)
@mcp_audit_tool("compare_test_runs")
async def compare_test_runs_tool(
    baseline_results: list[dict[str, Any]],
    comparison_results: list[dict[str, Any]],
    comparison_metrics: list[str] | None = None,
) -> dict[str, Any]:
    """Compare multiple test runs."""
    return await compare_test_runs(
        baseline_results, comparison_results, comparison_metrics
    )


@server.tool(
    name="get_performance_metrics",
    description="Retrieves and analyzes performance metrics from test results. "
    "Extracts key performance indicators and provides aggregated metrics.",
)
@mcp_audit_tool("get_performance_metrics")
async def get_performance_metrics_tool(
    test_results: list[dict[str, Any]],
    metric_types: list[str] | None = None,
    aggregation_method: str = "average",
) -> dict[str, Any]:
    """Get performance metrics from test results."""
    return await get_performance_metrics(test_results, metric_types, aggregation_method)


@server.tool(
    name="create_test_session",
    description="Creates a new test session for workflow management. "
    "Initializes a test session with configuration and tracking capabilities.",
)
@mcp_audit_tool("create_test_session")
async def create_test_session_tool(
    session_name: str,
    test_plan: dict[str, Any],
    session_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a new test session."""
    return await create_test_session(session_name, test_plan, session_config)


@server.tool(
    name="end_test_session",
    description="Ends a test session and generates final reports. "
    "Completes the test session, performs final analysis, and generates comprehensive reports.",
)
@mcp_audit_tool("end_test_session")
async def end_test_session_tool(
    session_id: str, generate_final_report: bool = True
) -> dict[str, Any]:
    """End a test session and generate final reports."""
    return await end_test_session(session_id, generate_final_report)


@server.tool(
    name="schedule_test_suite",
    description="Schedules automated test suite execution. "
    "Sets up automated testing schedules with configurable parameters and notifications.",
)
@mcp_audit_tool("schedule_test_suite")
async def schedule_test_suite_tool(
    test_suite: dict[str, Any],
    schedule_config: dict[str, Any],
    notification_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Schedule automated test suite execution."""
    return await schedule_test_suite(test_suite, schedule_config, notification_config)


@server.tool(
    name="monitor_test_progress",
    description="Monitors ongoing test execution and provides real-time updates. "
    "Tracks test progress, identifies issues, and provides performance insights during execution.",
)
@mcp_audit_tool("monitor_test_progress")
async def monitor_test_progress_tool(
    session_id: str, include_performance_data: bool = True, alert_on_issues: bool = True
) -> dict[str, Any]:
    """Monitor ongoing test execution."""
    return await monitor_test_progress(
        session_id, include_performance_data, alert_on_issues
    )


# Register MCP Context Management Tools for stateful testing workflows


@server.tool(
    name="create_test_session_context",
    description="Creates a new test session context for stateful testing workflows. "
    "Enables tracking of test state, variables, and progress across multiple test iterations.",
)
@mcp_audit_tool("create_test_session_context")
async def create_test_session_context_tool(
    session_name: str,
    test_plan: dict[str, Any],
    session_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a new test session context."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {
                "status": "error",
                "message": "Context manager not available",
                "context_id": None,
            }

        context_id = await create_test_session_context(
            session_name=session_name,
            test_plan=test_plan,
            session_config=session_config or {},
        )

        return {
            "status": "success",
            "message": f"Test session context '{session_name}' created successfully",
            "context_id": context_id,
            "context_type": "test_session",
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to create test session context: {e}",
            "context_id": None,
        }


@server.tool(
    name="create_workflow_context",
    description="Creates a workflow context for managing complex testing workflows. "
    "Enables coordination between multiple test sessions and cross-session data sharing.",
)
@mcp_audit_tool("create_workflow_context")
async def create_workflow_context_tool(
    workflow_name: str,
    workflow_config: dict[str, Any],
    parent_context_id: str | None = None,
) -> dict[str, Any]:
    """Create a new workflow context."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {
                "status": "error",
                "message": "Context manager not available",
                "context_id": None,
            }

        context_id = await create_workflow_context(
            workflow_name=workflow_name,
            workflow_config=workflow_config,
            parent_context_id=parent_context_id,
        )

        return {
            "status": "success",
            "message": f"Workflow context '{workflow_name}' created successfully",
            "context_id": context_id,
            "context_type": "workflow",
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to create workflow context: {e}",
            "context_id": None,
        }


@server.tool(
    name="create_agent_context",
    description="Creates an agent context for AI agent integration. "
    "Enables AI agents to maintain state and coordinate with other agents in testing workflows.",
)
@mcp_audit_tool("create_agent_context")
async def create_agent_context_tool(
    agent_name: str,
    agent_type: str,
    agent_config: dict[str, Any],
    parent_context_id: str | None = None,
) -> dict[str, Any]:
    """Create a new agent context."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {
                "status": "error",
                "message": "Context manager not available",
                "context_id": None,
            }

        context_id = await create_agent_context(
            agent_name=agent_name,
            agent_type=agent_type,
            agent_config=agent_config,
            parent_context_id=parent_context_id,
        )

        return {
            "status": "success",
            "message": f"Agent context '{agent_name}' created successfully",
            "context_id": context_id,
            "context_type": "agent",
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to create agent context: {e}",
            "context_id": None,
        }


@server.tool(
    name="get_context_data",
    description="Retrieves data from a specific context. "
    "Allows access to stored variables, state, and configuration data from any context.",
)
@mcp_audit_tool("get_context_data")
async def get_context_data_tool(
    context_id: str, keys: list[str] | None = None
) -> dict[str, Any]:
    """Get data from a context."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {
                "status": "error",
                "message": "Context manager not available",
                "data": {},
            }

        data = await get_context_data(context_id=context_id, keys=keys)

        return {
            "status": "success",
            "message": f"Retrieved data from context {context_id}",
            "data": data,
            "context_id": context_id,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get context data: {e}",
            "data": {},
        }


@server.tool(
    name="update_context_data",
    description="Updates data in a specific context. "
    "Allows modification of stored variables, state, and configuration data.",
)
@mcp_audit_tool("update_context_data")
async def update_context_data_tool(
    context_id: str, data: dict[str, Any], merge: bool = True
) -> dict[str, Any]:
    """Update data in a context."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {"status": "error", "message": "Context manager not available"}

        await update_context_data(context_id=context_id, data=data, merge=merge)

        return {
            "status": "success",
            "message": f"Updated data in context {context_id}",
            "context_id": context_id,
            "updated_keys": list(data.keys()),
        }
    except Exception as e:
        return {"status": "error", "message": f"Failed to update context data: {e}"}


@server.tool(
    name="create_context_snapshot",
    description="Creates a snapshot of a context for rollback capabilities. "
    "Enables saving context state at specific points for later restoration.",
)
@mcp_audit_tool("create_context_snapshot")
async def create_context_snapshot_tool(
    context_id: str, snapshot_name: str, description: str | None = None
) -> dict[str, Any]:
    """Create a context snapshot."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {
                "status": "error",
                "message": "Context manager not available",
                "snapshot_id": None,
            }

        snapshot_id = await create_context_snapshot(
            context_id=context_id, snapshot_name=snapshot_name, description=description
        )

        return {
            "status": "success",
            "message": f"Snapshot '{snapshot_name}' created for context {context_id}",
            "snapshot_id": snapshot_id,
            "context_id": context_id,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to create context snapshot: {e}",
            "snapshot_id": None,
        }


@server.tool(
    name="restore_context_snapshot",
    description="Restores a context from a previously created snapshot. "
    "Enables rollback to previous context states for testing and recovery.",
)
@mcp_audit_tool("restore_context_snapshot")
async def restore_context_snapshot_tool(
    context_id: str, snapshot_id: str
) -> dict[str, Any]:
    """Restore a context from a snapshot."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {"status": "error", "message": "Context manager not available"}

        await restore_context_snapshot(context_id=context_id, snapshot_id=snapshot_id)

        return {
            "status": "success",
            "message": f"Context {context_id} restored from snapshot {snapshot_id}",
            "context_id": context_id,
            "snapshot_id": snapshot_id,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to restore context snapshot: {e}",
        }


@server.tool(
    name="list_contexts_by_type",
    description="Lists all contexts of a specific type. "
    "Enables discovery and management of contexts across the testing environment.",
)
@mcp_audit_tool("list_contexts_by_type")
async def list_contexts_by_type_tool(
    context_type: str | None = None, status: str | None = None
) -> dict[str, Any]:
    """List contexts by type and status."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {
                "status": "error",
                "message": "Context manager not available",
                "contexts": [],
            }

        # Convert string to ContextType enum if provided
        context_type_enum = None
        if context_type:
            try:
                context_type_enum = ContextType(context_type.lower())
            except ValueError:
                return {
                    "status": "error",
                    "message": f"Invalid context type: {context_type}",
                    "contexts": [],
                }

        # Convert string to ContextStatus enum if provided
        status_enum = None
        if status:
            try:
                status_enum = ContextStatus(status.lower())
            except ValueError:
                return {
                    "status": "error",
                    "message": f"Invalid status: {status}",
                    "contexts": [],
                }

        contexts = await list_contexts_by_type(
            context_type=context_type_enum, status=status_enum
        )

        return {
            "status": "success",
            "message": f"Found {len(contexts)} contexts",
            "contexts": contexts,
            "filter_type": context_type,
            "filter_status": status,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to list contexts: {e}",
            "contexts": [],
        }


@server.tool(
    name="get_global_context_data",
    description="Retrieves data from the global context. "
    "Enables access to shared data across all testing sessions and workflows.",
)
@mcp_audit_tool("get_global_context_data")
async def get_global_context_data_tool(keys: list[str] | None = None) -> dict[str, Any]:
    """Get data from the global context."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {
                "status": "error",
                "message": "Context manager not available",
                "data": {},
            }

        data = await get_global_context_data(keys=keys)

        return {
            "status": "success",
            "message": "Retrieved global context data",
            "data": data,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get global context data: {e}",
            "data": {},
        }


@server.tool(
    name="update_global_context_data",
    description="Updates data in the global context. "
    "Enables modification of shared data accessible across all testing sessions and workflows.",
)
@mcp_audit_tool("update_global_context_data")
async def update_global_context_data_tool(
    data: dict[str, Any], merge: bool = True
) -> dict[str, Any]:
    """Update data in the global context."""
    try:
        context_manager = get_context_manager()
        if not context_manager:
            return {"status": "error", "message": "Context manager not available"}

        await update_global_context_data(data=data, merge=merge)

        return {
            "status": "success",
            "message": "Updated global context data",
            "updated_keys": list(data.keys()),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to update global context data: {e}",
        }


# Register MCP Prompts for AI-driven scenario generation


@server.prompt(
    name="analyze_openapi_for_testing",
    description="Analyze an OpenAPI specification to identify testable scenarios and risk areas. "
    "Generates comprehensive testing recommendations based on API structure and security configuration.",
)
async def analyze_openapi_for_testing_prompt(
    openapi_spec: dict,
    testing_focus: str = "comprehensive",
    risk_assessment: bool = True,
) -> dict:
    """
    MCP Prompt to analyze OpenAPI specifications for testing scenarios.

    Args:
        openapi_spec: The OpenAPI specification to analyze
        testing_focus: Focus area for testing ("performance", "security", "functional", "comprehensive")
        risk_assessment: Whether to include risk assessment in the analysis

    Returns:
        Structured analysis with testable scenarios and risk areas
    """
    return await analyze_openapi_for_testing(
        openapi_spec, testing_focus, risk_assessment
    )


@server.prompt(
    name="generate_scenario_config",
    description="Generate a specific scenario configuration for MockLoop testing. "
    "Creates detailed scenario configurations that can be directly used with MockLoop servers.",
)
async def generate_scenario_config_prompt(
    scenario_type: str,
    endpoints: list,
    test_parameters: dict | None = None,
    scenario_name: str | None = None,
) -> dict:
    """
    MCP Prompt to generate scenario configurations for MockLoop testing.

    Args:
        scenario_type: Type of scenario ("load_testing", "error_simulation", "security_testing", "functional_testing")
        endpoints: List of endpoint configurations
        test_parameters: Optional test parameters for the scenario
        scenario_name: Optional custom name for the scenario

    Returns:
        Complete scenario configuration ready for MockLoop
    """
    return await generate_scenario_config(
        scenario_type, endpoints, test_parameters, scenario_name
    )


@server.prompt(
    name="optimize_scenario_for_load",
    description="Optimize a scenario configuration for load testing performance. "
    "Takes a base scenario and optimizes it for high-load testing by adjusting response times and concurrency settings.",
)
async def optimize_scenario_for_load_prompt(
    base_scenario: dict, target_load: int, performance_requirements: dict | None = None
) -> dict:
    """
    MCP Prompt to optimize scenarios for load testing.

    Args:
        base_scenario: Base scenario configuration to optimize
        target_load: Target number of concurrent users
        performance_requirements: Optional performance requirements

    Returns:
        Optimized scenario configuration for load testing
    """
    return await optimize_scenario_for_load(
        base_scenario, target_load, performance_requirements
    )


@server.prompt(
    name="generate_error_scenarios",
    description="Generate error simulation scenarios for testing error handling. "
    "Creates scenarios that simulate various error conditions to test API resilience.",
)
async def generate_error_scenarios_prompt(
    api_endpoints: list, error_types: list | None = None, severity_level: str = "medium"
) -> dict:
    """
    MCP Prompt to generate error simulation scenarios.

    Args:
        api_endpoints: List of API endpoints to test
        error_types: Optional list of specific error types to simulate
        severity_level: Severity level of errors ("low", "medium", "high")

    Returns:
        Error simulation scenario configuration
    """
    return await generate_error_scenarios(api_endpoints, error_types, severity_level)


@server.prompt(
    name="generate_security_test_scenarios",
    description="Generate security testing scenarios for API vulnerability assessment. "
    "Creates scenarios that test for common security vulnerabilities and compliance with security standards.",
)
async def generate_security_test_scenarios_prompt(
    api_spec: dict,
    security_focus: list | None = None,
    compliance_requirements: list | None = None,
) -> dict:
    """
    MCP Prompt to generate security testing scenarios.

    Args:
        api_spec: OpenAPI specification to analyze for security testing
        security_focus: Optional list of security areas to focus on
        compliance_requirements: Optional list of compliance standards to test

    Returns:
        Security testing scenario configuration
    """
    return await generate_security_test_scenarios(
        api_spec, security_focus, compliance_requirements
    )


# Register MCP Resources for scenario packs


# Error Simulation Scenario Packs
@server.resource("scenario-pack://error-simulation/4xx-client-errors")
async def resource_4xx_client_errors():
    """4xx Client Error Simulation Scenario Pack"""
    return await get_4xx_client_errors_pack()


@server.resource("scenario-pack://error-simulation/5xx-server-errors")
async def resource_5xx_server_errors():
    """5xx Server Error Simulation Scenario Pack"""
    return await get_5xx_server_errors_pack()


@server.resource("scenario-pack://error-simulation/network-timeouts")
async def resource_network_timeouts():
    """Network Timeout Simulation Scenario Pack"""
    return await get_network_timeouts_pack()


@server.resource("scenario-pack://error-simulation/rate-limiting")
async def resource_rate_limiting():
    """Rate Limiting Simulation Scenario Pack"""
    return await get_rate_limiting_pack()


# Performance Testing Scenario Packs
@server.resource("scenario-pack://performance-testing/load-testing")
async def resource_load_testing():
    """Load Testing Scenario Pack"""
    return await get_load_testing_pack()


@server.resource("scenario-pack://performance-testing/stress-testing")
async def resource_stress_testing():
    """Stress Testing Scenario Pack"""
    return await get_stress_testing_pack()


@server.resource("scenario-pack://performance-testing/spike-testing")
async def resource_spike_testing():
    """Spike Testing Scenario Pack"""
    return await get_spike_testing_pack()


@server.resource("scenario-pack://performance-testing/endurance-testing")
async def resource_endurance_testing():
    """Endurance Testing Scenario Pack"""
    return await get_endurance_testing_pack()


# Security Testing Scenario Packs
@server.resource("scenario-pack://security-testing/auth-bypass")
async def resource_auth_bypass():
    """Authentication Bypass Testing Scenario Pack"""
    return await get_auth_bypass_pack()


@server.resource("scenario-pack://security-testing/injection-attacks")
async def resource_injection_attacks():
    """Injection Attack Testing Scenario Pack"""
    return await get_injection_attacks_pack()


@server.resource("scenario-pack://security-testing/xss-attacks")
async def resource_xss_attacks():
    """XSS Attack Testing Scenario Pack"""
    return await get_xss_attacks_pack()


@server.resource("scenario-pack://security-testing/csrf-attacks")
async def resource_csrf_attacks():
    """CSRF Attack Testing Scenario Pack"""
    return await get_csrf_attacks_pack()


# Business Logic Testing Scenario Packs
@server.resource("scenario-pack://business-logic/edge-cases")
async def resource_edge_cases():
    """Edge Case Testing Scenario Pack"""
    return await get_edge_cases_pack()


@server.resource("scenario-pack://business-logic/data-validation")
async def resource_data_validation():
    """Data Validation Testing Scenario Pack"""
    return await get_data_validation_pack()


@server.resource("scenario-pack://business-logic/workflow-testing")
async def resource_workflow_testing():
    """Workflow Testing Scenario Pack"""
    return await get_workflow_testing_pack()


# Resource Discovery Endpoints
@server.resource("scenario-pack://discovery/list-all")
async def resource_list_all_packs():
    """List all available scenario packs"""
    return await list_scenario_packs()


@server.resource("scenario-pack://discovery/community-info")
async def resource_community_info():
    """Community scenarios architecture information"""
    return await get_community_architecture_info()


# --- CLI for local testing of the tool logic ---
async def run_tool_from_cli(args):
    """Helper to call the tool logic for CLI testing."""
    # This simulates how the MCP server would call the tool.
    # The actual MCP server handles the async nature and context injection.

    result = await generate_mock_api_tool(
        spec_url_or_path=args.spec_source,
        output_dir_name=args.output_name,
    )
    # Extract text from TextContent for CLI display
    text_result = result[0].text if result and hasattr(result[0], 'text') else str(result)
    print(text_result)

    if "Error" in text_result:
        sys.exit(1)


async def run_tool_from_cli_enhanced(
    spec_source: str,
    output_name: str | None = None,
    auth_enabled: bool = True,
    webhooks_enabled: bool = True,
    admin_ui_enabled: bool = True,
    storage_enabled: bool = True,
    business_port: int = 8000,
    admin_port: int | None = None,
):
    """Enhanced CLI helper with full configuration options."""
    result = await generate_mock_api_tool(
        spec_url_or_path=spec_source,
        output_dir_name=output_name,
        auth_enabled=auth_enabled,
        webhooks_enabled=webhooks_enabled,
        admin_ui_enabled=admin_ui_enabled,
        storage_enabled=storage_enabled,
        business_port=business_port,
        admin_port=admin_port,
    )
    # Extract text from TextContent for CLI display
    text_result = result[0].text if result and hasattr(result[0], 'text') else str(result)
    print(text_result)

    if "Error" in text_result:
        sys.exit(1)


def main_cli():
    # Handle imports for different execution contexts
    if __package__ is None or __package__ == "":
        from __init__ import __version__
    else:
        from . import __version__

    parser = argparse.ArgumentParser(
        prog="mockloop-mcp",
        description="MockLoop MCP Server - Generate and manage mock API servers from specifications",
        epilog="For more information, visit: https://github.com/mockloop/mockloop-mcp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Add version argument
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version information and exit",
    )

    # Add mode selection arguments
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--stdio",
        action="store_true",
        help="Run in stdio mode for MCP client communication",
    )
    mode_group.add_argument(
        "--sse", action="store_true", help="Run in Server-Sent Events mode (default)"
    )
    mode_group.add_argument(
        "--cli", action="store_true", help="Run in CLI mode for direct API generation"
    )

    # CLI-specific arguments (only used when --cli is specified)
    cli_group = parser.add_argument_group("CLI mode options")
    cli_group.add_argument(
        "spec_source",
        nargs="?",
        help="URL or local file path to the API specification (required for CLI mode)",
    )
    cli_group.add_argument(
        "-o",
        "--output-name",
        help="Optional name for the generated mock server directory",
        default=None,
    )
    cli_group.add_argument(
        "--auth-enabled",
        action="store_true",
        default=True,
        help="Enable authentication middleware (default: enabled)",
    )
    cli_group.add_argument(
        "--no-auth", action="store_true", help="Disable authentication middleware"
    )
    cli_group.add_argument(
        "--webhooks-enabled",
        action="store_true",
        default=True,
        help="Enable webhook support (default: enabled)",
    )
    cli_group.add_argument(
        "--no-webhooks", action="store_true", help="Disable webhook support"
    )
    cli_group.add_argument(
        "--admin-ui-enabled",
        action="store_true",
        default=True,
        help="Enable admin UI (default: enabled)",
    )
    cli_group.add_argument(
        "--no-admin-ui", action="store_true", help="Disable admin UI"
    )
    cli_group.add_argument(
        "--storage-enabled",
        action="store_true",
        default=True,
        help="Enable storage functionality (default: enabled)",
    )
    cli_group.add_argument(
        "--no-storage", action="store_true", help="Disable storage functionality"
    )
    cli_group.add_argument(
        "--mock-port",
        type=int,
        default=8000,
        help="Port for the mock API (default: 8000)",
    )
    cli_group.add_argument(
        "--admin-port",
        type=int,
        help="Port for the admin API (if different from business port)",
    )

    # Logging and debug options
    debug_group = parser.add_argument_group("debug and logging options")
    debug_group.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    debug_group.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress non-error output"
    )
    debug_group.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )

    args = parser.parse_args()

    # Configure logging based on arguments
    log_level = getattr(logging, args.log_level.upper())
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR

    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Handle CLI mode
    if args.cli or args.spec_source:
        if not args.spec_source:
            parser.error("spec_source is required when using CLI mode")

        # Process boolean flags
        auth_enabled = args.auth_enabled and not args.no_auth
        webhooks_enabled = args.webhooks_enabled and not args.no_webhooks
        admin_ui_enabled = args.admin_ui_enabled and not args.no_admin_ui
        storage_enabled = args.storage_enabled and not args.no_storage

        import asyncio

        asyncio.run(
            run_tool_from_cli_enhanced(
                args.spec_source,
                args.output_name,
                auth_enabled,
                webhooks_enabled,
                admin_ui_enabled,
                storage_enabled,
                args.mock_port,
                args.admin_port,
            )
        )
    else:
        # Default behavior - show help if no mode specified
        parser.print_help()
        sys.exit(0)


def main():
    """Main entry point for the mockloop-mcp CLI command."""
    import sys

    # Handle version and help early for better UX
    if "--version" in sys.argv or "-V" in sys.argv:
        # Handle imports for different execution contexts
        if __package__ is None or __package__ == "":
            from __init__ import __version__
        else:
            from . import __version__
        print(f"mockloop-mcp {__version__}")
        sys.exit(0)

    if "--help" in sys.argv or "-h" in sys.argv:
        main_cli()
        return

    # Auto-detect stdio mode when run by Claude or other MCP clients
    # This happens when stdin is not a terminal (piped) and no explicit flags are given
    is_stdin_piped = not sys.stdin.isatty()
    has_explicit_flags = any(arg.startswith("-") for arg in sys.argv[1:])

    # Check for explicit mode flags
    has_stdio_flag = "--stdio" in sys.argv
    has_sse_flag = "--sse" in sys.argv
    has_cli_flag = "--cli" in sys.argv
    has_positional_args = any(not arg.startswith("-") for arg in sys.argv[1:])

    # Determine mode based on flags and context
    if has_stdio_flag or (
        is_stdin_piped and not has_explicit_flags and not has_positional_args
    ):
        # Remove --stdio from sys.argv if present
        if "--stdio" in sys.argv:
            sys.argv.remove("--stdio")

        # Run in stdio mode with full feature parity
        # Handle imports for different execution contexts
        if __package__ is None or __package__ == "":
            from stdio_server import run_stdio_server
        else:
            from .stdio_server import run_stdio_server

        import asyncio

        asyncio.run(run_stdio_server())
    elif has_cli_flag or has_positional_args:
        # CLI mode - either explicit --cli flag or positional arguments provided
        main_cli()
    elif has_sse_flag:
        # Remove --sse from sys.argv if present
        if "--sse" in sys.argv:
            sys.argv.remove("--sse")
        # Start the MCP server in SSE mode
        server.run()
    else:
        # Default behavior - show help
        main_cli()


# To run the MCP server:
# Use `mcp dev src/mockloop_mcp/main.py` or `mcp run src/mockloop_mcp/main.py`
# Or, if this file is intended to be run directly as `python src/mockloop_mcp/main.py`:
if __name__ == "__main__":
    main()
