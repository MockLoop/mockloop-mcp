# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Stdio MCP Server implementation with full feature parity to SSE mode.
This module provides all tools, prompts, and resources available in SSE mode.
"""

import asyncio
import logging
from typing import Any

from mcp.server.stdio import stdio_server
from mcp.server import Server
from mcp.types import Tool, Prompt, Resource

# Import all the tool functions from main.py
from .main import (
    # Tool functions
    generate_mock_api_tool,
    query_mock_logs_tool,
    discover_mock_servers_tool,
    manage_mock_data_tool,
    validate_scenario_config_tool,
    deploy_scenario_tool,
    switch_scenario_tool,
    list_active_scenarios_tool,
    execute_test_plan_tool,
    run_test_iteration_tool,
    run_load_test_tool,
    run_security_test_tool,
    analyze_test_results_tool,
    generate_test_report_tool,
    compare_test_runs_tool,
    get_performance_metrics_tool,
    create_test_session_tool,
    end_test_session_tool,
    schedule_test_suite_tool,
    monitor_test_progress_tool,
    create_test_session_context_tool,
    create_workflow_context_tool,
    create_agent_context_tool,
    get_context_data_tool,
    update_context_data_tool,
    create_context_snapshot_tool,
    restore_context_snapshot_tool,
    list_contexts_by_type_tool,
    get_global_context_data_tool,
    update_global_context_data_tool,
    # Prompt functions
    analyze_openapi_for_testing_prompt,
    generate_scenario_config_prompt,
    optimize_scenario_for_load_prompt,
    generate_error_scenarios_prompt,
    generate_security_test_scenarios_prompt,
    # Resource functions
    resource_4xx_client_errors,
    resource_5xx_server_errors,
    resource_network_timeouts,
    resource_rate_limiting,
    resource_load_testing,
    resource_stress_testing,
    resource_spike_testing,
    resource_endurance_testing,
    resource_auth_bypass,
    resource_injection_attacks,
    resource_xss_attacks,
    resource_csrf_attacks,
    resource_edge_cases,
    resource_data_validation,
    resource_workflow_testing,
    resource_list_all_packs,
    resource_community_info,
)

logger = logging.getLogger(__name__)


def create_stdio_server() -> Server:
    """Create and configure the stdio MCP server with all features."""
    mcp_server = Server("MockLoop")

    @mcp_server.list_tools()
    async def list_tools():
        """List all available tools."""
        return [
            Tool(
                name="generate_mock_api",
                description="Generates a FastAPI mock server from an API specification (e.g., OpenAPI). "
                "The mock server includes request/response logging and Docker support.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "spec_url_or_path": {"type": "string"},
                        "output_dir_name": {"type": "string"},
                        "auth_enabled": {"type": "boolean", "default": True},
                        "webhooks_enabled": {"type": "boolean", "default": True},
                        "admin_ui_enabled": {"type": "boolean", "default": True},
                        "storage_enabled": {"type": "boolean", "default": True},
                        "business_port": {"type": "integer", "default": 8000},
                        "admin_port": {"type": "integer"},
                    },
                    "required": ["spec_url_or_path"],
                },
            ),
            Tool(
                name="query_mock_logs",
                description="Query and analyze request logs from a running MockLoop server. "
                "Supports filtering by method, path, time range, and provides optional analysis.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                        "method": {"type": "string"},
                        "path_pattern": {"type": "string"},
                        "time_from": {"type": "string"},
                        "time_to": {"type": "string"},
                        "include_admin": {"type": "boolean", "default": False},
                        "analyze": {"type": "boolean", "default": True},
                    },
                    "required": ["server_url"],
                },
            ),
            Tool(
                name="discover_mock_servers",
                description="Discover running MockLoop servers and generated mock configurations. "
                "Scans common ports and matches with generated mocks.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ports": {"type": "array", "items": {"type": "integer"}},
                        "check_health": {"type": "boolean", "default": True},
                        "include_generated": {"type": "boolean", "default": True},
                    },
                },
            ),
            Tool(
                name="manage_mock_data",
                description="Manage dynamic response data and scenarios for MockLoop servers. "
                "Supports updating responses, creating scenarios, switching scenarios, and listing scenarios.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string"},
                        "operation": {"type": "string"},
                        "endpoint_path": {"type": "string"},
                        "response_data": {"type": "object"},
                        "scenario_name": {"type": "string"},
                        "scenario_config": {"type": "object"},
                    },
                    "required": ["server_url", "operation"],
                },
            ),
            Tool(
                name="validate_scenario_config",
                description="Validates scenario configuration before deployment. "
                "Performs comprehensive validation including required fields, endpoint configurations, and test parameters.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scenario_config": {"type": "object"},
                        "strict_validation": {"type": "boolean", "default": True},
                        "check_endpoints": {"type": "boolean", "default": True},
                    },
                    "required": ["scenario_config"],
                },
            ),
            Tool(
                name="deploy_scenario",
                description="Deploys scenario to MockLoop server. "
                "Validates configuration, deploys to server, and activates the scenario.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string"},
                        "scenario_config": {"type": "object"},
                        "validate_before_deploy": {"type": "boolean", "default": True},
                        "force_deploy": {"type": "boolean", "default": False},
                    },
                    "required": ["server_url", "scenario_config"],
                },
            ),
            Tool(
                name="switch_scenario",
                description="Switches active scenario on a server. "
                "Changes the currently active scenario and optionally verifies the switch was successful.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string"},
                        "scenario_name": {"type": "string"},
                        "verify_switch": {"type": "boolean", "default": True},
                    },
                    "required": ["server_url", "scenario_name"],
                },
            ),
            Tool(
                name="list_active_scenarios",
                description="Lists all active scenarios across servers. "
                "Discovers running servers and retrieves their currently active scenarios.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_urls": {"type": "array", "items": {"type": "string"}},
                        "discover_servers": {"type": "boolean", "default": True},
                    },
                },
            ),
            Tool(
                name="execute_test_plan",
                description="Combines scenario generation and deployment in one operation. "
                "Analyzes OpenAPI spec, generates scenarios, deploys them, and optionally executes tests immediately.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "openapi_spec": {"type": "object"},
                        "server_url": {"type": "string"},
                        "test_focus": {"type": "string", "default": "comprehensive"},
                        "auto_generate_scenarios": {"type": "boolean", "default": True},
                        "execute_immediately": {"type": "boolean", "default": True},
                    },
                    "required": ["openapi_spec", "server_url"],
                },
            ),
            Tool(
                name="run_test_iteration",
                description="Executes a single test iteration with monitoring. "
                "Runs a test iteration for a specified duration while collecting performance metrics and logs.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string"},
                        "scenario_name": {"type": "string"},
                        "duration_seconds": {"type": "integer", "default": 300},
                        "monitor_performance": {"type": "boolean", "default": True},
                        "collect_logs": {"type": "boolean", "default": True},
                    },
                    "required": ["server_url", "scenario_name"],
                },
            ),
            Tool(
                name="run_load_test",
                description="Executes load testing with configurable parameters. "
                "Performs comprehensive load testing with ramp-up, steady state, and ramp-down phases.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string"},
                        "target_load": {"type": "integer"},
                        "duration_seconds": {"type": "integer", "default": 300},
                        "ramp_up_time": {"type": "integer", "default": 60},
                        "scenario_name": {"type": "string"},
                    },
                    "required": ["server_url", "target_load"],
                },
            ),
            Tool(
                name="run_security_test",
                description="Executes security testing scenarios for vulnerability assessment. "
                "Performs comprehensive security testing including authentication, authorization, and injection attacks.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server_url": {"type": "string"},
                        "api_spec": {"type": "object"},
                        "security_focus": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "compliance_requirements": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "scenario_name": {"type": "string"},
                    },
                    "required": ["server_url", "api_spec"],
                },
            ),
            Tool(
                name="analyze_test_results",
                description="Analyzes test results and provides comprehensive insights. "
                "Performs statistical analysis, identifies trends, and generates actionable recommendations.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "test_results": {"type": "array", "items": {"type": "object"}},
                        "analysis_type": {"type": "string", "default": "comprehensive"},
                        "include_recommendations": {"type": "boolean", "default": True},
                    },
                    "required": ["test_results"],
                },
            ),
            Tool(
                name="generate_test_report",
                description="Generates formatted test reports in various formats. "
                "Creates comprehensive reports with charts, analysis, and recommendations.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "test_results": {"type": "array", "items": {"type": "object"}},
                        "report_format": {"type": "string", "default": "comprehensive"},
                        "include_charts": {"type": "boolean", "default": True},
                        "output_format": {"type": "string", "default": "json"},
                    },
                    "required": ["test_results"],
                },
            ),
            Tool(
                name="compare_test_runs",
                description="Compares multiple test runs to identify performance changes. "
                "Performs statistical comparison and identifies regressions or improvements.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "baseline_results": {
                            "type": "array",
                            "items": {"type": "object"},
                        },
                        "comparison_results": {
                            "type": "array",
                            "items": {"type": "object"},
                        },
                        "comparison_metrics": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["baseline_results", "comparison_results"],
                },
            ),
            Tool(
                name="get_performance_metrics",
                description="Retrieves and analyzes performance metrics from test results. "
                "Extracts key performance indicators and provides aggregated metrics.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "test_results": {"type": "array", "items": {"type": "object"}},
                        "metric_types": {"type": "array", "items": {"type": "string"}},
                        "aggregation_method": {"type": "string", "default": "average"},
                    },
                    "required": ["test_results"],
                },
            ),
            Tool(
                name="create_test_session",
                description="Creates a new test session for workflow management. "
                "Initializes a test session with configuration and tracking capabilities.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_name": {"type": "string"},
                        "test_plan": {"type": "object"},
                        "session_config": {"type": "object"},
                    },
                    "required": ["session_name", "test_plan"],
                },
            ),
            Tool(
                name="end_test_session",
                description="Ends a test session and generates final reports. "
                "Completes the test session, performs final analysis, and generates comprehensive reports.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "generate_final_report": {"type": "boolean", "default": True},
                    },
                    "required": ["session_id"],
                },
            ),
            Tool(
                name="schedule_test_suite",
                description="Schedules automated test suite execution. "
                "Sets up automated testing schedules with configurable parameters and notifications.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "test_suite": {"type": "object"},
                        "schedule_config": {"type": "object"},
                        "notification_config": {"type": "object"},
                    },
                    "required": ["test_suite", "schedule_config"],
                },
            ),
            Tool(
                name="monitor_test_progress",
                description="Monitors ongoing test execution and provides real-time updates. "
                "Tracks test progress, identifies issues, and provides performance insights during execution.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "include_performance_data": {
                            "type": "boolean",
                            "default": True,
                        },
                        "alert_on_issues": {"type": "boolean", "default": True},
                    },
                    "required": ["session_id"],
                },
            ),
            Tool(
                name="create_test_session_context",
                description="Creates a new test session context for stateful testing workflows. "
                "Enables tracking of test state, variables, and progress across multiple test iterations.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_name": {"type": "string"},
                        "test_plan": {"type": "object"},
                        "session_config": {"type": "object"},
                    },
                    "required": ["session_name", "test_plan"],
                },
            ),
            Tool(
                name="create_workflow_context",
                description="Creates a workflow context for managing complex testing workflows. "
                "Enables coordination between multiple test sessions and cross-session data sharing.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "workflow_name": {"type": "string"},
                        "workflow_config": {"type": "object"},
                        "parent_context_id": {"type": "string"},
                    },
                    "required": ["workflow_name", "workflow_config"],
                },
            ),
            Tool(
                name="create_agent_context",
                description="Creates an agent context for AI agent integration. "
                "Enables AI agents to maintain state and coordinate with other agents in testing workflows.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "agent_name": {"type": "string"},
                        "agent_type": {"type": "string"},
                        "agent_config": {"type": "object"},
                        "parent_context_id": {"type": "string"},
                    },
                    "required": ["agent_name", "agent_type", "agent_config"],
                },
            ),
            Tool(
                name="get_context_data",
                description="Retrieves data from a specific context. "
                "Allows access to stored variables, state, and configuration data from any context.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "context_id": {"type": "string"},
                        "keys": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["context_id"],
                },
            ),
            Tool(
                name="update_context_data",
                description="Updates data in a specific context. "
                "Allows modification of stored variables, state, and configuration data.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "context_id": {"type": "string"},
                        "data": {"type": "object"},
                        "merge": {"type": "boolean", "default": True},
                    },
                    "required": ["context_id", "data"],
                },
            ),
            Tool(
                name="create_context_snapshot",
                description="Creates a snapshot of a context for rollback capabilities. "
                "Enables saving context state at specific points for later restoration.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "context_id": {"type": "string"},
                        "snapshot_name": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["context_id", "snapshot_name"],
                },
            ),
            Tool(
                name="restore_context_snapshot",
                description="Restores a context from a previously created snapshot. "
                "Enables rollback to previous context states for testing and recovery.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "context_id": {"type": "string"},
                        "snapshot_id": {"type": "string"},
                    },
                    "required": ["context_id", "snapshot_id"],
                },
            ),
            Tool(
                name="list_contexts_by_type",
                description="Lists all contexts of a specific type. "
                "Enables discovery and management of contexts across the testing environment.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "context_type": {"type": "string"},
                        "status": {"type": "string"},
                    },
                },
            ),
            Tool(
                name="get_global_context_data",
                description="Retrieves data from the global context. "
                "Enables access to shared data across all testing sessions and workflows.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "keys": {"type": "array", "items": {"type": "string"}},
                    },
                },
            ),
            Tool(
                name="update_global_context_data",
                description="Updates data in the global context. "
                "Enables modification of shared data accessible across all testing sessions and workflows.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "data": {"type": "object"},
                        "merge": {"type": "boolean", "default": True},
                    },
                    "required": ["data"],
                },
            ),
        ]

    @mcp_server.list_prompts()
    async def list_prompts():
        """List all available prompts."""
        return [
            Prompt(
                name="analyze_openapi_for_testing",
                description="Analyze an OpenAPI specification to identify testable scenarios and risk areas. "
                "Generates comprehensive testing recommendations based on API structure and security configuration.",
                arguments=[
                    {
                        "name": "openapi_spec",
                        "description": "The OpenAPI specification to analyze",
                        "required": True,
                    },
                    {
                        "name": "testing_focus",
                        "description": "Focus area for testing",
                        "required": False,
                    },
                    {
                        "name": "risk_assessment",
                        "description": "Whether to include risk assessment",
                        "required": False,
                    },
                ],
            ),
            Prompt(
                name="generate_scenario_config",
                description="Generate a specific scenario configuration for MockLoop testing. "
                "Creates detailed scenario configurations that can be directly used with MockLoop servers.",
                arguments=[
                    {
                        "name": "scenario_type",
                        "description": "Type of scenario",
                        "required": True,
                    },
                    {
                        "name": "endpoints",
                        "description": "List of endpoint configurations",
                        "required": True,
                    },
                    {
                        "name": "test_parameters",
                        "description": "Optional test parameters",
                        "required": False,
                    },
                    {
                        "name": "scenario_name",
                        "description": "Optional custom name",
                        "required": False,
                    },
                ],
            ),
            Prompt(
                name="optimize_scenario_for_load",
                description="Optimize a scenario configuration for load testing performance. "
                "Takes a base scenario and optimizes it for high-load testing by adjusting response times and concurrency settings.",
                arguments=[
                    {
                        "name": "base_scenario",
                        "description": "Base scenario configuration",
                        "required": True,
                    },
                    {
                        "name": "target_load",
                        "description": "Target number of concurrent users",
                        "required": True,
                    },
                    {
                        "name": "performance_requirements",
                        "description": "Optional performance requirements",
                        "required": False,
                    },
                ],
            ),
            Prompt(
                name="generate_error_scenarios",
                description="Generate error simulation scenarios for testing error handling. "
                "Creates scenarios that simulate various error conditions to test API resilience.",
                arguments=[
                    {
                        "name": "api_endpoints",
                        "description": "List of API endpoints to test",
                        "required": True,
                    },
                    {
                        "name": "error_types",
                        "description": "Optional list of specific error types",
                        "required": False,
                    },
                    {
                        "name": "severity_level",
                        "description": "Severity level of errors",
                        "required": False,
                    },
                ],
            ),
            Prompt(
                name="generate_security_test_scenarios",
                description="Generate security testing scenarios for API vulnerability assessment. "
                "Creates scenarios that test for common security vulnerabilities and compliance with security standards.",
                arguments=[
                    {
                        "name": "api_spec",
                        "description": "OpenAPI specification to analyze",
                        "required": True,
                    },
                    {
                        "name": "security_focus",
                        "description": "Optional list of security areas",
                        "required": False,
                    },
                    {
                        "name": "compliance_requirements",
                        "description": "Optional list of compliance standards",
                        "required": False,
                    },
                ],
            ),
        ]

    @mcp_server.list_resources()
    async def list_resources():
        """List all available resources."""
        return [
            Resource(
                uri="scenario-pack://error-simulation/4xx-client-errors",
                name="4xx Client Error Simulation Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://error-simulation/5xx-server-errors",
                name="5xx Server Error Simulation Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://error-simulation/network-timeouts",
                name="Network Timeout Simulation Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://error-simulation/rate-limiting",
                name="Rate Limiting Simulation Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://performance-testing/load-testing",
                name="Load Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://performance-testing/stress-testing",
                name="Stress Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://performance-testing/spike-testing",
                name="Spike Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://performance-testing/endurance-testing",
                name="Endurance Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://security-testing/auth-bypass",
                name="Authentication Bypass Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://security-testing/injection-attacks",
                name="Injection Attack Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://security-testing/xss-attacks",
                name="XSS Attack Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://security-testing/csrf-attacks",
                name="CSRF Attack Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://business-logic/edge-cases",
                name="Edge Case Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://business-logic/data-validation",
                name="Data Validation Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://business-logic/workflow-testing",
                name="Workflow Testing Scenario Pack",
            ),
            Resource(
                uri="scenario-pack://discovery/list-all",
                name="List all available scenario packs",
            ),
            Resource(
                uri="scenario-pack://discovery/community-info",
                name="Community scenarios architecture information",
            ),
        ]

    @mcp_server.call_tool()
    async def call_tool(name: str, arguments: dict):
        """Handle tool calls."""
        tool_map = {
            "generate_mock_api": generate_mock_api_tool,
            "query_mock_logs": query_mock_logs_tool,
            "discover_mock_servers": discover_mock_servers_tool,
            "manage_mock_data": manage_mock_data_tool,
            "validate_scenario_config": validate_scenario_config_tool,
            "deploy_scenario": deploy_scenario_tool,
            "switch_scenario": switch_scenario_tool,
            "list_active_scenarios": list_active_scenarios_tool,
            "execute_test_plan": execute_test_plan_tool,
            "run_test_iteration": run_test_iteration_tool,
            "run_load_test": run_load_test_tool,
            "run_security_test": run_security_test_tool,
            "analyze_test_results": analyze_test_results_tool,
            "generate_test_report": generate_test_report_tool,
            "compare_test_runs": compare_test_runs_tool,
            "get_performance_metrics": get_performance_metrics_tool,
            "create_test_session": create_test_session_tool,
            "end_test_session": end_test_session_tool,
            "schedule_test_suite": schedule_test_suite_tool,
            "monitor_test_progress": monitor_test_progress_tool,
            "create_test_session_context": create_test_session_context_tool,
            "create_workflow_context": create_workflow_context_tool,
            "create_agent_context": create_agent_context_tool,
            "get_context_data": get_context_data_tool,
            "update_context_data": update_context_data_tool,
            "create_context_snapshot": create_context_snapshot_tool,
            "restore_context_snapshot": restore_context_snapshot_tool,
            "list_contexts_by_type": list_contexts_by_type_tool,
            "get_global_context_data": get_global_context_data_tool,
            "update_global_context_data": update_global_context_data_tool,
        }

        if name in tool_map:
            return await tool_map[name](**arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")

    @mcp_server.get_prompt()
    async def get_prompt(name: str, arguments: dict):
        """Handle prompt calls."""
        prompt_map = {
            "analyze_openapi_for_testing": analyze_openapi_for_testing_prompt,
            "generate_scenario_config": generate_scenario_config_prompt,
            "optimize_scenario_for_load": optimize_scenario_for_load_prompt,
            "generate_error_scenarios": generate_error_scenarios_prompt,
            "generate_security_test_scenarios": generate_security_test_scenarios_prompt,
        }

        if name in prompt_map:
            return await prompt_map[name](**arguments)
        else:
            raise ValueError(f"Unknown prompt: {name}")

    @mcp_server.read_resource()
    async def read_resource(uri: str):
        """Handle resource reads."""
        resource_map = {
            "scenario-pack://error-simulation/4xx-client-errors": resource_4xx_client_errors,
            "scenario-pack://error-simulation/5xx-server-errors": resource_5xx_server_errors,
            "scenario-pack://error-simulation/network-timeouts": resource_network_timeouts,
            "scenario-pack://error-simulation/rate-limiting": resource_rate_limiting,
            "scenario-pack://performance-testing/load-testing": resource_load_testing,
            "scenario-pack://performance-testing/stress-testing": resource_stress_testing,
            "scenario-pack://performance-testing/spike-testing": resource_spike_testing,
            "scenario-pack://performance-testing/endurance-testing": resource_endurance_testing,
            "scenario-pack://security-testing/auth-bypass": resource_auth_bypass,
            "scenario-pack://security-testing/injection-attacks": resource_injection_attacks,
            "scenario-pack://security-testing/xss-attacks": resource_xss_attacks,
            "scenario-pack://security-testing/csrf-attacks": resource_csrf_attacks,
            "scenario-pack://business-logic/edge-cases": resource_edge_cases,
            "scenario-pack://business-logic/data-validation": resource_data_validation,
            "scenario-pack://business-logic/workflow-testing": resource_workflow_testing,
            "scenario-pack://discovery/list-all": resource_list_all_packs,
            "scenario-pack://discovery/community-info": resource_community_info,
        }

        if uri in resource_map:
            return await resource_map[uri]()
        else:
            raise ValueError(f"Unknown resource: {uri}")

    return mcp_server


async def run_stdio_server():
    """Run the stdio MCP server."""
    mcp_server = create_stdio_server()

    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(run_stdio_server())
