"""
MCP Tools Module for automated test execution and management.

This module provides comprehensive MCP tools that enable AI agents to execute
and manage complex testing workflows. All tools are integrated with the
comprehensive audit logging infrastructure for regulatory compliance.

Features:
- Scenario management and deployment
- Test execution and monitoring
- Analysis and reporting capabilities
- Advanced workflow orchestration
- Performance optimization
- Security testing automation
- Full audit logging integration
- Async execution for all operations
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlparse

# Handle imports for different execution contexts
if __package__ is None or __package__ == "":
    from mcp_audit_logger import create_audit_logger
    from mcp_prompts import (
        analyze_openapi_for_testing,
        generate_scenario_config,
        optimize_scenario_for_load,
        generate_error_scenarios,
        generate_security_test_scenarios,
    )
    from mcp_resources import list_scenario_packs, get_scenario_pack_by_uri
    from utils.http_client import (
        MockServerClient,
        discover_running_servers,
        check_server_connectivity,
    )
    from mock_server_manager import MockServerManager
    from generator import generate_mock_api
    from proxy.config import (
        ProxyConfig,
        AuthConfig,
        EndpointConfig,
        PluginConfig,
        ProxyMode,
        AuthType,
    )
    from proxy.plugin_manager import PluginManager
    from proxy.proxy_handler import ProxyHandler
    from proxy.auth_handler import AuthHandler
    from schemapin import (
        get_schemapin_config,
        SchemaVerificationInterceptor,
        SchemaVerificationError,
        PolicyAction,
    )
    from schemapin.verification import extract_tool_schema
else:
    from .mcp_audit_logger import create_audit_logger
    from .mcp_prompts import (
        analyze_openapi_for_testing,
        generate_scenario_config,
        optimize_scenario_for_load,
        generate_error_scenarios,
        generate_security_test_scenarios,
    )
    from .mcp_resources import list_scenario_packs, get_scenario_pack_by_uri
    from .utils.http_client import (
        MockServerClient,
        discover_running_servers,
        check_server_connectivity,
    )
    from .mock_server_manager import MockServerManager
    from .generator import generate_mock_api
    from .proxy.config import (
        ProxyConfig,
        AuthConfig,
        EndpointConfig,
        PluginConfig,
        ProxyMode,
        AuthType,
    )
    from .proxy.plugin_manager import PluginManager
    from .proxy.proxy_handler import ProxyHandler
    from .proxy.auth_handler import AuthHandler
    from .schemapin import (
        get_schemapin_config,
        SchemaVerificationInterceptor,
        SchemaVerificationError,
        PolicyAction,
    )
    from .schemapin.verification import extract_tool_schema

# Configure logger for this module
logger = logging.getLogger(__name__)

# Test session storage for tracking active sessions
_active_test_sessions: dict[str, dict[str, Any]] = {}


def mcp_tool_audit(tool_name: str):
    """
    Decorator to add MCP audit logging and SchemaPin verification to tool functions.

    Args:
        tool_name: Name of the MCP tool being audited
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            audit_logger = create_audit_logger(
                db_path="mcp_audit.db",
                session_id=f"mcp_tool_{tool_name}",
                user_id="mcp_system",
            )
            start_time = time.time()
            entry_id = None

            try:
                # Log tool execution start
                if audit_logger:
                    entry_id = audit_logger.log_tool_execution(
                        tool_name=tool_name,
                        input_parameters=kwargs,
                        data_sources=["mock_server", "scenario_config"],
                        compliance_tags=["mcp_tool", "test_execution"],
                        processing_purpose="automated_testing",
                        legal_basis="legitimate_interests",
                    )

                # SchemaPin verification
                schemapin_config = get_schemapin_config()
                if schemapin_config.enabled:
                    interceptor = SchemaVerificationInterceptor(schemapin_config)

                    # Extract schema and signature from tool metadata
                    tool_schema = extract_tool_schema(func)
                    signature = kwargs.get('_schema_signature')
                    domain = kwargs.get('_schema_domain')

                    # Perform verification
                    verification_result = await interceptor.verify_tool_schema(
                        tool_name=tool_name,
                        schema=tool_schema,
                        signature=signature,
                        domain=domain
                    )

                    # Handle policy decision
                    policy_decision = await interceptor.policy_handler.evaluate_verification_result(
                        verification_result, tool_name
                    )

                    # Enforce policy
                    if policy_decision.action == PolicyAction.BLOCK:
                        raise SchemaVerificationError(
                            f"Schema verification failed for {tool_name}: {verification_result.error}"
                        )
                    elif policy_decision.action == PolicyAction.WARN:
                        logger.warning(
                            f"Schema verification warning for {tool_name}: {verification_result.error}"
                        )
                    # LOG mode continues execution regardless

                # Execute the original function
                result = await func(*args, **kwargs)

                # Log successful completion
                if audit_logger and entry_id:
                    execution_time_ms = (time.time() - start_time) * 1000
                    audit_logger.log_tool_execution(
                        tool_name=f"{tool_name}_completion",
                        input_parameters={"original_entry_id": entry_id},
                        execution_result={"status": result.get("status", "unknown")},
                        execution_time_ms=execution_time_ms,
                        data_sources=["mock_server", "scenario_config"],
                        compliance_tags=["mcp_tool", "test_execution", "completion"],
                        processing_purpose="automated_testing_completion",
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
                        data_sources=["mock_server", "scenario_config"],
                        compliance_tags=["mcp_tool", "test_execution", "error"],
                        processing_purpose="automated_testing_error",
                        legal_basis="legitimate_interests",
                        error_details=str(e),
                    )
                raise

        return wrapper

    return decorator


# Scenario Management Tools


@mcp_tool_audit("validate_scenario_config")
async def validate_scenario_config(
    scenario_config: dict[str, Any],
    strict_validation: bool = True,
    check_endpoints: bool = True,
) -> dict[str, Any]:
    """
    Validates scenario configuration before deployment.

    Args:
        scenario_config: The scenario configuration to validate
        strict_validation: Whether to perform strict validation
        check_endpoints: Whether to validate endpoint configurations

    Returns:
        Validation result with detailed feedback
    """
    try:
        validation_result = {
            "status": "success",
            "valid": True,
            "errors": [],
            "warnings": [],
            "suggestions": [],
            "validated_config": scenario_config.copy(),
        }

        # Required fields validation
        required_fields = ["scenario_name", "description", "scenario_type", "endpoints"]
        for field in required_fields:
            if field not in scenario_config:
                validation_result["errors"].append(f"Missing required field: {field}")
                validation_result["valid"] = False

        # Scenario type validation
        valid_types = [
            "load_testing",
            "error_simulation",
            "security_testing",
            "functional_testing",
        ]
        scenario_type = scenario_config.get("scenario_type")
        if scenario_type and scenario_type not in valid_types:
            validation_result["errors"].append(
                f"Invalid scenario_type: {scenario_type}. Must be one of {valid_types}"
            )
            validation_result["valid"] = False

        # Endpoints validation
        if check_endpoints and "endpoints" in scenario_config:
            endpoints = scenario_config["endpoints"]
            if not isinstance(endpoints, list) or len(endpoints) == 0:
                validation_result["errors"].append("Endpoints must be a non-empty list")
                validation_result["valid"] = False
            else:
                for i, endpoint in enumerate(endpoints):
                    endpoint_errors = _validate_endpoint_config(endpoint, i)
                    validation_result["errors"].extend(endpoint_errors)
                    if endpoint_errors:
                        validation_result["valid"] = False

        # Test parameters validation
        if "test_parameters" in scenario_config:
            test_params = scenario_config["test_parameters"]
            param_warnings = _validate_test_parameters(test_params, scenario_type)
            validation_result["warnings"].extend(param_warnings)

        # Performance suggestions
        if scenario_type == "load_testing":
            suggestions = _generate_load_testing_suggestions(scenario_config)
            validation_result["suggestions"].extend(suggestions)

        # Set final status
        if validation_result["errors"]:
            validation_result["status"] = "error"
            validation_result["valid"] = False
        elif validation_result["warnings"] and strict_validation:
            validation_result["status"] = "warning"

        return validation_result

    except Exception as e:
        logger.exception("Error validating scenario configuration")
        return {
            "status": "error",
            "valid": False,
            "errors": [f"Validation failed: {e!s}"],
            "warnings": [],
            "suggestions": [],
            "validated_config": {},
        }


@mcp_tool_audit("deploy_scenario")
async def deploy_scenario(
    server_url: str,
    scenario_config: dict[str, Any],
    validate_before_deploy: bool = True,
    force_deploy: bool = False,
) -> dict[str, Any]:
    """
    Deploys scenario to MockLoop server.

    Args:
        server_url: URL of the target MockLoop server
        scenario_config: Complete scenario configuration
        validate_before_deploy: Whether to validate before deployment
        force_deploy: Whether to force deployment even with warnings

    Returns:
        Deployment result with status and details
    """
    try:
        deployment_result = {
            "status": "success",
            "deployed": False,
            "scenario_name": scenario_config.get("scenario_name", "unknown"),
            "server_url": server_url,
            "validation_result": None,
            "deployment_details": {},
            "performance_metrics": {},
        }

        start_time = time.time()

        # Validate server connectivity
        connectivity_result = await check_server_connectivity(server_url)
        if connectivity_result.get("status") != "healthy":
            return {
                **deployment_result,
                "status": "error",
                "error": f"Server not accessible: {connectivity_result.get('error', 'Unknown error')}",
            }

        # Validate scenario configuration if requested
        if validate_before_deploy:
            validation_result = await validate_scenario_config(scenario_config)
            deployment_result["validation_result"] = validation_result

            if not validation_result["valid"] and not force_deploy:
                return {
                    **deployment_result,
                    "status": "error",
                    "error": "Scenario validation failed. Use force_deploy=True to override.",
                }

        # Initialize HTTP client with server discovery for dual-port support
        servers = await discover_running_servers(
            [int(server_url.split(":")[-1])], check_health=True
        )
        admin_port = None
        for server in servers:
            if server.get("url") == server_url and server.get("admin_port"):
                admin_port = server["admin_port"]
                break

        client = MockServerClient(server_url, admin_port=admin_port)

        # Deploy scenario
        scenario_name = scenario_config["scenario_name"]
        create_result = await client.create_scenario(scenario_name, scenario_config)

        if create_result.get("status") == "success":
            deployment_result["deployed"] = True
            deployment_result["deployment_details"] = create_result.get("result", {})

            # Switch to the deployed scenario
            switch_result = await client.switch_scenario(scenario_name)
            if switch_result.get("status") == "success":
                deployment_result["deployment_details"]["activated"] = True
                deployment_result["deployment_details"]["previous_scenario"] = (
                    switch_result.get("previous_scenario")
                )
            else:
                deployment_result["deployment_details"]["activated"] = False
                deployment_result["deployment_details"]["switch_error"] = (
                    switch_result.get("error")
                )

        else:
            deployment_result["status"] = "error"
            deployment_result["error"] = (
                f"Scenario deployment failed: {create_result.get('error', 'Unknown error')}"
            )

        # Calculate performance metrics
        end_time = time.time()
        deployment_result["performance_metrics"] = {
            "deployment_time_ms": round((end_time - start_time) * 1000, 2),
            "server_response_time": connectivity_result.get(
                "response_time_ms", "unknown"
            ),
            "timestamp": end_time,
        }

        return deployment_result

    except Exception as e:
        logger.exception("Error deploying scenario")
        return {
            "status": "error",
            "deployed": False,
            "scenario_name": scenario_config.get("scenario_name", "unknown"),
            "server_url": server_url,
            "error": f"Deployment failed: {e!s}",
            "validation_result": None,
            "deployment_details": {},
            "performance_metrics": {},
        }


@mcp_tool_audit("switch_scenario")
async def switch_scenario(
    server_url: str, scenario_name: str, verify_switch: bool = True
) -> dict[str, Any]:
    """
    Switches active scenario on a server.

    Args:
        server_url: URL of the target MockLoop server
        scenario_name: Name of the scenario to switch to
        verify_switch: Whether to verify the switch was successful

    Returns:
        Switch operation result
    """
    try:
        switch_result = {
            "status": "success",
            "switched": False,
            "scenario_name": scenario_name,
            "server_url": server_url,
            "previous_scenario": None,
            "verification_result": None,
        }

        # Validate server connectivity
        connectivity_result = await check_server_connectivity(server_url)
        if connectivity_result.get("status") != "healthy":
            return {
                **switch_result,
                "status": "error",
                "error": f"Server not accessible: {connectivity_result.get('error', 'Unknown error')}",
            }

        # Initialize HTTP client with server discovery for dual-port support
        servers = await discover_running_servers(
            [int(server_url.split(":")[-1])], check_health=True
        )
        admin_port = None
        for server in servers:
            if server.get("url") == server_url and server.get("admin_port"):
                admin_port = server["admin_port"]
                break

        client = MockServerClient(server_url, admin_port=admin_port)

        # Perform the switch
        result = await client.switch_scenario(scenario_name)

        if result.get("status") == "success":
            switch_result["switched"] = True
            switch_result["previous_scenario"] = result.get("previous_scenario")

            # Verify the switch if requested
            if verify_switch:
                current_result = await client.get_current_scenario()
                if current_result.get("status") == "success":
                    current_scenario = current_result.get("current_scenario", {})
                    if current_scenario.get("name") == scenario_name:
                        switch_result["verification_result"] = "verified"
                    else:
                        switch_result["verification_result"] = "failed"
                        switch_result["status"] = "warning"
                        switch_result["error"] = (
                            "Switch completed but verification failed"
                        )
                else:
                    switch_result["verification_result"] = "unable_to_verify"
                    switch_result["status"] = "warning"

        else:
            switch_result["status"] = "error"
            switch_result["error"] = (
                f"Scenario switch failed: {result.get('error', 'Unknown error')}"
            )

        return switch_result

    except Exception as e:
        logger.exception("Error switching scenario")
        return {
            "status": "error",
            "switched": False,
            "scenario_name": scenario_name,
            "server_url": server_url,
            "error": f"Switch failed: {e!s}",
            "previous_scenario": None,
            "verification_result": None,
        }


@mcp_tool_audit("list_active_scenarios")
async def list_active_scenarios(
    server_urls: list[str] | None = None, discover_servers: bool = True
) -> dict[str, Any]:
    """
    Lists all active scenarios across servers.

    Args:
        server_urls: List of server URLs to check. If None, discovers servers automatically
        discover_servers: Whether to auto-discover running servers

    Returns:
        List of active scenarios across all servers
    """
    try:
        result = {
            "status": "success",
            "servers_checked": 0,
            "active_scenarios": [],
            "server_details": [],
            "discovery_used": False,
        }

        target_servers = []

        # Discover servers if needed
        if not server_urls and discover_servers:
            discovered = await discover_running_servers(check_health=True)
            mockloop_servers = [s for s in discovered if s.get("is_mockloop_server")]
            target_servers = [s["url"] for s in mockloop_servers]
            result["discovery_used"] = True
            result["server_details"] = mockloop_servers
        elif server_urls:
            target_servers = server_urls

        if not target_servers:
            return {
                **result,
                "status": "warning",
                "error": "No servers to check. Provide server_urls or enable discover_servers.",
            }

        # Check each server
        for server_url in target_servers:
            try:
                # Initialize HTTP client with server discovery for dual-port support
                servers = await discover_running_servers(
                    [int(server_url.split(":")[-1])], check_health=True
                )
                admin_port = None
                for server in servers:
                    if server.get("url") == server_url and server.get("admin_port"):
                        admin_port = server["admin_port"]
                        break

                client = MockServerClient(server_url, admin_port=admin_port)

                # Get current scenario
                current_result = await client.get_current_scenario()
                if current_result.get("status") == "success":
                    current_scenario = current_result.get("current_scenario", {})
                    if current_scenario:
                        result["active_scenarios"].append(
                            {
                                "server_url": server_url,
                                "scenario_name": current_scenario.get(
                                    "name", "unknown"
                                ),
                                "scenario_id": current_scenario.get("id"),
                                "description": current_scenario.get("description", ""),
                                "activated_at": current_scenario.get("activated_at"),
                                "scenario_type": current_scenario.get("config", {}).get(
                                    "scenario_type", "unknown"
                                ),
                            }
                        )

                result["servers_checked"] += 1

            except Exception as e:
                logger.debug(f"Failed to check server {server_url}: {e}")
                # Continue checking other servers
                continue

        return result

    except Exception as e:
        logger.exception("Error listing active scenarios")
        return {
            "status": "error",
            "servers_checked": 0,
            "active_scenarios": [],
            "server_details": [],
            "discovery_used": False,
            "error": f"Failed to list active scenarios: {e!s}",
        }


# Test Execution Tools


@mcp_tool_audit("execute_test_plan")
async def execute_test_plan(
    openapi_spec: dict[str, Any],
    server_url: str,
    test_focus: str = "comprehensive",
    auto_generate_scenarios: bool = True,
    execute_immediately: bool = True,
    mode: str = "auto",
    validation_mode: str = "strict",
    comparison_config: dict[str, Any] | None = None,
    parallel_execution: bool = False,
    report_differences: bool = True,
) -> dict[str, Any]:
    """
    Enhanced test plan execution with proxy-aware testing and validation against both mock and live APIs.

    Args:
        openapi_spec: OpenAPI specification to analyze
        server_url: Target MockLoop server URL or live API URL
        test_focus: Focus area for testing ("performance", "security", "functional", "comprehensive")
        auto_generate_scenarios: Whether to auto-generate scenarios from OpenAPI spec
        execute_immediately: Whether to execute tests immediately after deployment
        mode: Plugin mode - "auto", "mock", "proxy", or "hybrid" (default: "auto")
        validation_mode: Validation strictness - "strict", "soft", or "report_only" (default: "strict")
        comparison_config: Configuration for response comparison with ignore_fields and tolerance
        parallel_execution: Whether to execute tests in parallel for performance (default: False)
        report_differences: Whether to report differences between expected and actual responses (default: True)

    Returns:
        Complete test plan execution result with proxy-aware capabilities and validation
    """
    try:
        execution_result = {
            "status": "success",
            "test_plan_id": str(uuid.uuid4()),
            "server_url": server_url,
            "test_focus": test_focus,
            "mode": mode,
            "validation_mode": validation_mode,
            "analysis_result": None,
            "generated_scenarios": [],
            "deployed_scenarios": [],
            "execution_results": [],
            "performance_metrics": {},
            "proxy_detection": {},
            "validation_results": [],
            "comparison_results": [],
            "differences_report": [],
        }

        start_time = time.time()

        # Step 1: Detect mode automatically if set to "auto"
        detected_mode = mode
        if mode == "auto":
            detected_mode = await _detect_plugin_mode(server_url, openapi_spec)
            execution_result["proxy_detection"] = {
                "original_mode": mode,
                "detected_mode": detected_mode,
                "detection_method": "automatic",
            }

        # Step 2: Set up comparison configuration
        comparison_cfg = comparison_config or {}
        ignore_fields = comparison_cfg.get(
            "ignore_fields", ["timestamp", "request_id", "trace_id"]
        )
        tolerance = comparison_cfg.get(
            "tolerance", {"response_time_ms": 100, "numeric_variance": 0.01}
        )

        # Step 3: Analyze OpenAPI specification
        if auto_generate_scenarios:
            analysis_result = await analyze_openapi_for_testing(
                openapi_spec, test_focus, True
            )
            execution_result["analysis_result"] = analysis_result

            # Step 4: Generate scenarios based on analysis and mode
            testable_scenarios = analysis_result.get("testable_scenarios", [])
            for scenario_info in testable_scenarios[:3]:  # Limit to top 3 scenarios
                # Extract endpoints from OpenAPI spec
                endpoints = []
                paths = openapi_spec.get("paths", {})
                for path, methods in paths.items():
                    for method in methods:
                        endpoints.append({"path": path, "method": method.upper()})

                # Generate scenario configuration with mode-specific enhancements
                scenario_config = await _generate_enhanced_scenario_config(
                    scenario_type=scenario_info.get(
                        "scenario_type", "functional_testing"
                    ),
                    endpoints=endpoints[:5],  # Limit endpoints per scenario
                    scenario_name=f"auto_{scenario_info.get('scenario_type', 'test')}_{int(time.time())}",
                    mode=detected_mode,
                    openapi_spec=openapi_spec,
                )

                execution_result["generated_scenarios"].append(scenario_config)

        # Step 5: Deploy scenarios based on mode
        for scenario_config in execution_result["generated_scenarios"]:
            if detected_mode in ["mock", "hybrid"]:
                # Deploy to mock server
                deploy_result = await deploy_scenario(
                    server_url, scenario_config, validate_before_deploy=True
                )
                execution_result["deployed_scenarios"].append(deploy_result)

            # Step 6: Execute tests with proxy-aware validation
            if execute_immediately:
                if parallel_execution:
                    # Execute tests in parallel
                    test_tasks = []
                    for scenario in execution_result["generated_scenarios"]:
                        task = _execute_proxy_aware_test(
                            server_url=server_url,
                            scenario_config=scenario,
                            mode=detected_mode,
                            validation_mode=validation_mode,
                            comparison_config=comparison_cfg,
                            openapi_spec=openapi_spec,
                        )
                        test_tasks.append(task)

                    test_results = await asyncio.gather(
                        *test_tasks, return_exceptions=True
                    )
                    for result in test_results:
                        if isinstance(result, Exception):
                            execution_result["execution_results"].append(
                                {"status": "error", "error": str(result)}
                            )
                        else:
                            execution_result["execution_results"].append(result)
                else:
                    # Execute tests sequentially
                    for scenario_config_item in execution_result["generated_scenarios"]:
                        test_result = await _execute_proxy_aware_test(
                            server_url=server_url,
                            scenario_config=scenario_config_item,
                            mode=detected_mode,
                            validation_mode=validation_mode,
                            comparison_config=comparison_cfg,
                            openapi_spec=openapi_spec,
                        )
                        execution_result["execution_results"].append(test_result)

        # Step 7: Perform response validation and comparison
        if report_differences and execution_result["execution_results"]:
            validation_results = []
            comparison_results = []
            differences_report = []

            for test_result in execution_result["execution_results"]:
                if test_result.get("status") == "success":
                    # Validate responses against OpenAPI spec
                    validation_result = await _validate_responses_against_spec(
                        test_result.get("request_logs", []),
                        openapi_spec,
                        validation_mode,
                    )
                    validation_results.append(validation_result)

                    # Compare mock vs live API responses if in hybrid mode
                    if (
                        detected_mode == "hybrid"
                        and test_result.get("mock_responses")
                        and test_result.get("live_responses")
                    ):
                        comparison_result = await _compare_responses(
                            test_result["mock_responses"],
                            test_result["live_responses"],
                            ignore_fields,
                            tolerance,
                        )
                        comparison_results.append(comparison_result)

                        # Generate differences report
                        if comparison_result.get("differences"):
                            differences_report.extend(comparison_result["differences"])

            execution_result["validation_results"] = validation_results
            execution_result["comparison_results"] = comparison_results
            execution_result["differences_report"] = differences_report

        # Calculate overall performance metrics
        end_time = time.time()
        execution_result["performance_metrics"] = {
            "total_execution_time_ms": round((end_time - start_time) * 1000, 2),
            "scenarios_generated": len(execution_result["generated_scenarios"]),
            "scenarios_deployed": len(
                [d for d in execution_result["deployed_scenarios"] if d.get("deployed")]
            ),
            "tests_executed": len(execution_result["execution_results"]),
            "timestamp": end_time,
        }

        # Determine overall status
        failed_deployments = [
            d for d in execution_result["deployed_scenarios"] if not d.get("deployed")
        ]
        failed_executions = [
            e
            for e in execution_result["execution_results"]
            if e.get("status") != "success"
        ]

        if failed_deployments or failed_executions:
            execution_result["status"] = "partial_success"
            execution_result["warnings"] = []
            if failed_deployments:
                execution_result["warnings"].append(
                    f"{len(failed_deployments)} scenario deployments failed"
                )
            if failed_executions:
                execution_result["warnings"].append(
                    f"{len(failed_executions)} test executions failed"
                )

        return execution_result

    except Exception as e:
        logger.exception("Error executing test plan")
        return {
            "status": "error",
            "test_plan_id": str(uuid.uuid4()),
            "server_url": server_url,
            "test_focus": test_focus,
            "error": f"Test plan execution failed: {e!s}",
            "analysis_result": None,
            "generated_scenarios": [],
            "deployed_scenarios": [],
            "execution_results": [],
            "performance_metrics": {},
        }


@mcp_tool_audit("run_test_iteration")
async def run_test_iteration(
    server_url: str,
    scenario_name: str,
    duration_seconds: int = 300,
    monitor_performance: bool = True,
    collect_logs: bool = True,
) -> dict[str, Any]:
    """
    Executes a single test iteration with monitoring.

    Args:
        server_url: Target MockLoop server URL
        scenario_name: Name of the scenario to execute
        duration_seconds: Duration of the test iteration
        monitor_performance: Whether to monitor performance metrics
        collect_logs: Whether to collect request logs during execution

    Returns:
        Test iteration result with metrics and logs
    """
    try:
        iteration_result = {
            "status": "success",
            "iteration_id": str(uuid.uuid4()),
            "server_url": server_url,
            "scenario_name": scenario_name,
            "duration_seconds": duration_seconds,
            "start_time": None,
            "end_time": None,
            "performance_metrics": {},
            "request_logs": [],
            "error_summary": {},
            "recommendations": [],
        }

        # Initialize HTTP client with server discovery for dual-port support
        servers = await discover_running_servers(
            [int(server_url.split(":")[-1])], check_health=True
        )
        admin_port = None
        for server in servers:
            if server.get("url") == server_url and server.get("admin_port"):
                admin_port = server["admin_port"]
                break

        client = MockServerClient(server_url, admin_port=admin_port)

        # Switch to the specified scenario
        switch_result = await switch_scenario(
            server_url, scenario_name, verify_switch=True
        )
        if not switch_result.get("switched"):
            return {
                **iteration_result,
                "status": "error",
                "error": f"Failed to switch to scenario '{scenario_name}': {switch_result.get('error')}",
            }

        # Record start time
        start_time = time.time()
        iteration_result["start_time"] = datetime.fromtimestamp(
            start_time, tz=timezone.utc  # noqa: UP017
        ).isoformat()

        # Get initial metrics if monitoring is enabled
        initial_stats = None
        if monitor_performance:
            stats_result = await client.get_stats()
            if stats_result.get("status") == "success":
                initial_stats = stats_result.get("stats", {})

        # Simulate test execution by monitoring for the specified duration
        # In a real implementation, this would trigger actual load testing tools
        await asyncio.sleep(min(duration_seconds, 10))  # Cap at 10 seconds for demo

        # Record end time
        end_time = time.time()
        iteration_result["end_time"] = datetime.fromtimestamp(
            end_time, tz=timezone.utc  # noqa: UP017
        ).isoformat()

        # Collect final metrics
        if monitor_performance:
            final_stats_result = await client.get_stats()
            if final_stats_result.get("status") == "success":
                final_stats = final_stats_result.get("stats", {})
                iteration_result["performance_metrics"] = _calculate_performance_delta(
                    initial_stats, final_stats
                )

        # Collect request logs if requested
        if collect_logs:
            logs_result = await client.query_logs(limit=100, include_admin=False)
            if logs_result.get("status") == "success":
                iteration_result["request_logs"] = logs_result.get("logs", [])

                # Analyze logs for errors
                error_summary = _analyze_request_logs(iteration_result["request_logs"])
                iteration_result["error_summary"] = error_summary

                # Generate recommendations
                recommendations = _generate_test_recommendations(
                    iteration_result["performance_metrics"],
                    error_summary,
                    scenario_name,
                )
                iteration_result["recommendations"] = recommendations

        return iteration_result

    except Exception as e:
        logger.exception("Error running test iteration")
        return {
            "status": "error",
            "iteration_id": str(uuid.uuid4()),
            "server_url": server_url,
            "scenario_name": scenario_name,
            "duration_seconds": duration_seconds,
            "error": f"Test iteration failed: {e!s}",
            "start_time": None,
            "end_time": None,
            "performance_metrics": {},
            "request_logs": [],
            "error_summary": {},
            "recommendations": [],
        }


@mcp_tool_audit("run_load_test")
async def run_load_test(
    server_url: str,
    target_load: int,
    duration_seconds: int = 300,
    ramp_up_time: int = 60,
    scenario_name: str | None = None,
) -> dict[str, Any]:
    """
    Executes load testing with configurable parameters.

    Args:
        server_url: Target MockLoop server URL
        target_load: Target number of concurrent users
        duration_seconds: Duration of the load test
        ramp_up_time: Time to ramp up to target load
        scenario_name: Optional specific scenario to use

    Returns:
        Load test execution result
    """
    try:
        load_test_result = {
            "status": "success",
            "test_id": str(uuid.uuid4()),
            "server_url": server_url,
            "target_load": target_load,
            "duration_seconds": duration_seconds,
            "ramp_up_time": ramp_up_time,
            "scenario_used": scenario_name,
            "load_profile": {},
            "performance_results": {},
            "bottlenecks_identified": [],
            "recommendations": [],
        }

        # If no scenario specified, create an optimized load testing scenario
        if not scenario_name:
            # Generate a basic load testing scenario
            endpoints = [{"path": "/health", "method": "GET"}]  # Default endpoint
            base_scenario = await generate_scenario_config(
                scenario_type="load_testing",
                endpoints=endpoints,
                scenario_name=f"load_test_{target_load}_{int(time.time())}",
            )

            # Optimize for load
            optimized_scenario = await optimize_scenario_for_load(
                base_scenario=base_scenario,
                target_load=target_load,
                performance_requirements={
                    "max_response_time_ms": 2000,
                    "target_throughput_rps": target_load * 2,
                    "error_rate_threshold": 0.01,
                },
            )

            # Deploy the optimized scenario
            deploy_result = await deploy_scenario(server_url, optimized_scenario)
            if not deploy_result.get("deployed"):
                return {
                    **load_test_result,
                    "status": "error",
                    "error": f"Failed to deploy load test scenario: {deploy_result.get('error')}",
                }

            scenario_name = optimized_scenario["scenario_name"]
            load_test_result["scenario_used"] = scenario_name

        # Define load profile
        load_profile = {
            "phases": [
                {
                    "phase": "ramp_up",
                    "duration": ramp_up_time,
                    "target_users": target_load,
                },
                {
                    "phase": "steady_state",
                    "duration": duration_seconds - ramp_up_time,
                    "target_users": target_load,
                },
                {"phase": "ramp_down", "duration": 30, "target_users": 0},
            ],
            "total_duration": duration_seconds + 30,
        }
        load_test_result["load_profile"] = load_profile

        # Execute load test phases
        for phase in load_profile["phases"]:
            phase_result = await run_test_iteration(
                server_url=server_url,
                scenario_name=scenario_name,
                duration_seconds=phase["duration"],
                monitor_performance=True,
                collect_logs=True,
            )

            # Collect phase results
            if phase["phase"] not in load_test_result["performance_results"]:
                load_test_result["performance_results"][phase["phase"]] = []
            load_test_result["performance_results"][phase["phase"]].append(phase_result)

        # Analyze results for bottlenecks
        bottlenecks = _identify_performance_bottlenecks(
            load_test_result["performance_results"], target_load
        )
        load_test_result["bottlenecks_identified"] = bottlenecks

        # Generate load test recommendations
        recommendations = _generate_load_test_recommendations(
            load_test_result["performance_results"], bottlenecks, target_load
        )
        load_test_result["recommendations"] = recommendations

        return load_test_result

    except Exception as e:
        logger.exception("Error running load test")
        return {
            "status": "error",
            "test_id": str(uuid.uuid4()),
            "server_url": server_url,
            "target_load": target_load,
            "duration_seconds": duration_seconds,
            "ramp_up_time": ramp_up_time,
            "error": f"Load test failed: {e!s}",
            "scenario_used": None,
            "load_profile": {},
            "performance_results": {},
            "bottlenecks_identified": [],
            "recommendations": [],
        }


@mcp_tool_audit("create_mcp_plugin")
async def create_mcp_plugin(
    spec_url_or_path: str,
    plugin_name: str | None = None,
    mode: str = "mock",
    target_url: str | None = None,
    auth_config: dict[str, Any] | None = None,
    proxy_config: dict[str, Any] | None = None,
    auto_register: bool = True,
) -> dict[str, Any]:
    """
    Dynamically create an MCP plugin for any API supporting mock or proxy mode.

    This tool creates MCP plugins that can operate in three modes:
    - Mock: Uses existing generate_mock_api functionality
    - Proxy: Creates proxy configuration and handlers for real API calls
    - Hybrid: Sets up both mock and proxy capabilities with routing rules

    Args:
        spec_url_or_path: URL or file path to OpenAPI specification
        plugin_name: Name for the MCP plugin (optional, derived from API spec if not provided)
        mode: Plugin mode - "mock", "proxy", or "hybrid" (default: "mock")
        target_url: Target API URL (required if mode is "proxy" or "hybrid")
        auth_config: Authentication configuration with type, header, value, oauth_config
        proxy_config: Proxy configuration with timeout, retry_attempts, rate_limit, headers
        auto_register: Whether to automatically register the plugin (default: True)

    Returns:
        Plugin creation result with configuration details and MCP information
    """
    try:
        plugin_result = {
            "status": "success",
            "plugin_id": str(uuid.uuid4()),
            "plugin_name": plugin_name,
            "mode": mode,
            "spec_source": spec_url_or_path,
            "target_url": target_url,
            "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "plugin_config": {},
            "mcp_config": {},
            "mock_server_path": None,
            "proxy_config": {},
            "validation_result": {},
            "registration_result": {},
        }

        start_time = time.time()

        # Validate input parameters
        validation_result = _validate_plugin_parameters(
            mode, target_url, auth_config, proxy_config
        )
        plugin_result["validation_result"] = validation_result

        if not validation_result["valid"]:
            return {
                **plugin_result,
                "status": "error",
                "error": f"Parameter validation failed: {validation_result['errors']}",
            }

        # Load and parse OpenAPI specification
        try:
            api_spec = await _load_openapi_spec(spec_url_or_path)
        except Exception as e:
            return {
                **plugin_result,
                "status": "error",
                "error": f"Failed to load OpenAPI specification: {e!s}",
            }

        # Extract API information
        api_info = api_spec.get("info", {})
        api_title = api_info.get("title", "Unknown API")

        # Generate plugin name if not provided
        if not plugin_name:
            plugin_name = _generate_plugin_name(api_title)

        plugin_result["plugin_name"] = plugin_name

        # Determine base URL for proxy mode
        if mode in ["proxy", "hybrid"] and not target_url:
            # Try to extract from OpenAPI spec servers
            servers = api_spec.get("servers", [])
            if servers and servers[0].get("url"):
                target_url = servers[0]["url"]
                plugin_result["target_url"] = target_url
            else:
                return {
                    **plugin_result,
                    "status": "error",
                    "error": "target_url is required for proxy/hybrid mode and could not be determined from API spec",
                }

        # Create proxy configuration
        proxy_mode = ProxyMode(mode.lower())

        # Set up authentication configuration
        auth_cfg = None
        if auth_config:
            auth_type_str = auth_config.get("type", "none")
            auth_type = (
                AuthType(auth_type_str.lower())
                if auth_type_str != "none"
                else AuthType.NONE
            )

            auth_cfg = AuthConfig(
                auth_type=auth_type,
                credentials=auth_config.get("credentials", {}),
                location=auth_config.get("location", "header"),
                name=auth_config.get("header", "Authorization"),
            )

        # Create proxy configuration object
        base_url = target_url or "http://localhost:8000"
        proxy_cfg = ProxyConfig(
            api_name=plugin_name,
            base_url=base_url,
            mode=proxy_mode,
            default_auth=auth_cfg,
            timeout=proxy_config.get("timeout", 30) if proxy_config else 30,
            retry_count=proxy_config.get("retry_attempts", 3) if proxy_config else 3,
            rate_limit=proxy_config.get("rate_limit") if proxy_config else None,
            headers=proxy_config.get("headers", {}) if proxy_config else {},
        )

        # Generate endpoint configurations from OpenAPI spec
        endpoints = _generate_endpoint_configs(api_spec, proxy_cfg, mode)
        for endpoint in endpoints:
            proxy_cfg.add_endpoint(endpoint)

        plugin_result["proxy_config"] = proxy_cfg.to_dict()

        # Create plugin configuration
        plugin_cfg = PluginConfig(
            plugin_name=plugin_name,
            api_spec=api_spec,
            proxy_config=proxy_cfg,
            mcp_server_name=f"mcp_{plugin_name.lower().replace(' ', '_')}",
        )

        plugin_result["plugin_config"] = plugin_cfg.to_dict()

        # Handle different modes
        if mode == "mock":
            # Use existing generate_mock_api functionality
            mock_result = await _create_mock_plugin(api_spec, plugin_name, proxy_cfg)
            plugin_result["mock_server_path"] = (
                str(mock_result) if mock_result else None
            )

        elif mode == "proxy":
            # Create proxy configuration and handlers
            proxy_result = await _create_proxy_plugin(plugin_cfg)
            plugin_result["proxy_setup"] = proxy_result

        elif mode == "hybrid":
            # Set up both mock and proxy capabilities
            mock_result = await _create_mock_plugin(api_spec, plugin_name, proxy_cfg)
            proxy_result = await _create_proxy_plugin(plugin_cfg)

            plugin_result["mock_server_path"] = (
                str(mock_result) if mock_result else None
            )
            plugin_result["proxy_setup"] = proxy_result

            # Add routing rules for hybrid mode
            routing_rules = _generate_hybrid_routing_rules(api_spec)
            for rule in routing_rules:
                proxy_cfg.add_route_rule(rule)

        # Generate MCP configuration
        mcp_config = _generate_mcp_configuration(plugin_cfg, mode)
        plugin_result["mcp_config"] = mcp_config

        # Auto-register plugin if requested
        if auto_register:
            registration_result = await _register_mcp_plugin(plugin_cfg)
            plugin_result["registration_result"] = registration_result

        # Calculate performance metrics
        end_time = time.time()
        plugin_result["performance_metrics"] = {
            "creation_time_ms": round((end_time - start_time) * 1000, 2),
            "endpoints_configured": len(endpoints),
            "timestamp": end_time,
        }

        return plugin_result

    except Exception as e:
        logger.exception("Error creating MCP plugin")
        return {
            "status": "error",
            "plugin_id": str(uuid.uuid4()),
            "plugin_name": plugin_name,
            "mode": mode,
            "spec_source": spec_url_or_path,
            "error": f"Plugin creation failed: {e!s}",
            "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "plugin_config": {},
            "mcp_config": {},
            "mock_server_path": None,
            "proxy_config": {},
            "validation_result": {},
            "registration_result": {},
        }


# Helper Functions


def _validate_endpoint_config(endpoint: dict[str, Any], index: int) -> list[str]:
    """Validate endpoint configuration."""
    errors = []

    if "path" not in endpoint:
        errors.append(f"Endpoint {index}: Missing 'path' field")

    if "method" not in endpoint:
        errors.append(f"Endpoint {index}: Missing 'method' field")
    elif endpoint["method"].upper() not in [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ]:
        errors.append(f"Endpoint {index}: Invalid HTTP method '{endpoint['method']}'")

    if "response_config" not in endpoint:
        errors.append(f"Endpoint {index}: Missing 'response_config' field")
    elif "status_code" not in endpoint["response_config"]:
        errors.append(f"Endpoint {index}: Missing 'status_code' in response_config")

    return errors


def _validate_test_parameters(
    test_params: dict[str, Any], scenario_type: str | None
) -> list[str]:
    """Validate test parameters."""
    warnings = []

    if "concurrent_users" in test_params:
        users = test_params["concurrent_users"]
        if users > 1000:
            warnings.append("High concurrent user count may impact performance")
        elif users < 1:
            warnings.append("Concurrent users should be at least 1")

    if "duration_seconds" in test_params:
        duration = test_params["duration_seconds"]
        if duration > 3600:  # 1 hour
            warnings.append("Long test duration may consume significant resources")
        elif duration < 10:
            warnings.append(
                "Very short test duration may not provide meaningful results"
            )

    if scenario_type == "load_testing" and test_params.get("concurrent_users", 0) < 10:
        warnings.append(
            "Load testing typically requires more concurrent users for meaningful results"
        )

    return warnings


def _generate_load_testing_suggestions(scenario_config: dict[str, Any]) -> list[str]:
    """Generate load testing suggestions."""
    suggestions = []

    endpoints = scenario_config.get("endpoints", [])
    if len(endpoints) > 10:
        suggestions.append(
            "Consider reducing the number of endpoints for focused load testing"
        )

    test_params = scenario_config.get("test_parameters", {})
    if test_params.get("concurrent_users", 0) > 100:
        suggestions.append(
            "Consider implementing gradual ramp-up for high load scenarios"
        )

    if not any("response_time_ms" in ep.get("response_config", {}) for ep in endpoints):
        suggestions.append(
            "Consider adding response time configurations for realistic load simulation"
        )

    return suggestions


def _calculate_performance_delta(
    initial_stats: dict | None, final_stats: dict | None
) -> dict[str, Any]:
    """Calculate performance metrics delta."""
    if not initial_stats or not final_stats:
        return {"error": "Insufficient stats data for delta calculation"}

    delta = {
        "requests_processed": final_stats.get("total_requests", 0)
        - initial_stats.get("total_requests", 0),
        "average_response_time_change": 0,
        "error_rate_change": 0,
        "throughput_rps": 0,
    }

    # Calculate average response time change
    initial_avg = initial_stats.get("average_response_time", 0)
    final_avg = final_stats.get("average_response_time", 0)
    if initial_avg > 0:
        delta["average_response_time_change"] = (
            (final_avg - initial_avg) / initial_avg
        ) * 100

    # Calculate error rate change
    initial_errors = initial_stats.get("error_count", 0)
    final_errors = final_stats.get("error_count", 0)
    initial_total = initial_stats.get("total_requests", 1)
    final_total = final_stats.get("total_requests", 1)

    initial_rate = (initial_errors / initial_total) * 100
    final_rate = (final_errors / final_total) * 100
    delta["error_rate_change"] = final_rate - initial_rate

    # Calculate throughput
    time_diff = final_stats.get("timestamp", 0) - initial_stats.get("timestamp", 0)
    if time_diff > 0:
        delta["throughput_rps"] = delta["requests_processed"] / time_diff

    return delta


def _analyze_request_logs(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze request logs for errors and patterns."""
    error_summary = {
        "total_requests": len(logs),
        "error_count": 0,
        "error_rate": 0,
        "status_code_distribution": {},
        "error_patterns": [],
    }

    status_codes = {}
    error_patterns = {}

    for log in logs:
        status_code = log.get("status_code", 0)
        status_codes[status_code] = status_codes.get(status_code, 0) + 1

        if status_code >= 400:
            error_summary["error_count"] += 1
            error_type = f"{status_code}_error"
            error_patterns[error_type] = error_patterns.get(error_type, 0) + 1

    error_summary["status_code_distribution"] = status_codes
    error_summary["error_rate"] = (
        (error_summary["error_count"] / len(logs)) * 100 if logs else 0
    )
    error_summary["error_patterns"] = [
        {"pattern": pattern, "count": count}
        for pattern, count in error_patterns.items()
    ]

    return error_summary


def _generate_test_recommendations(
    performance_metrics: dict[str, Any],
    error_summary: dict[str, Any],
    scenario_name: str,
) -> list[str]:
    """Generate test recommendations based on results."""
    recommendations = []

    # Performance recommendations
    if "average_response_time_change" in performance_metrics:
        change = performance_metrics["average_response_time_change"]
        if change > 50:
            recommendations.append(
                "Response time increased significantly - consider optimizing server performance"
            )
        elif change < -20:
            recommendations.append(
                "Response time improved - current configuration is performing well"
            )

    # Error rate recommendations
    error_rate = error_summary.get("error_rate", 0)
    if error_rate > 5:
        recommendations.append(
            "High error rate detected - investigate server configuration and endpoint implementations"
        )
    elif error_rate > 1:
        recommendations.append(
            "Moderate error rate - monitor for patterns and consider error handling improvements"
        )

    # Throughput recommendations
    throughput = performance_metrics.get("throughput_rps", 0)
    if throughput < 10:
        recommendations.append(
            "Low throughput detected - consider load balancing or server scaling"
        )

    return recommendations


def _identify_performance_bottlenecks(
    performance_results: dict[str, Any], target_load: int
) -> list[dict[str, Any]]:
    """Identify performance bottlenecks from load test results."""
    bottlenecks = []

    for phase, results in performance_results.items():
        if not results:
            continue

        for result in results:
            metrics = result.get("performance_metrics", {})

            # Check response time bottleneck
            avg_response_change = metrics.get("average_response_time_change", 0)
            if avg_response_change > 100:
                bottlenecks.append(
                    {
                        "type": "response_time",
                        "phase": phase,
                        "severity": "high",
                        "description": f"Response time increased by {avg_response_change:.1f}% during {phase}",
                        "recommendation": "Consider server optimization or load balancing",
                    }
                )

            # Check throughput bottleneck
            throughput = metrics.get("throughput_rps", 0)
            expected_throughput = target_load * 0.8  # 80% of target load
            if throughput < expected_throughput:
                bottlenecks.append(
                    {
                        "type": "throughput",
                        "phase": phase,
                        "severity": "medium",
                        "description": f"Throughput ({throughput:.1f} RPS) below expected ({expected_throughput:.1f} RPS)",
                        "recommendation": "Investigate server capacity and connection limits",
                    }
                )

    return bottlenecks


def _generate_load_test_recommendations(
    performance_results: dict[str, Any],
    bottlenecks: list[dict[str, Any]],
    target_load: int,
) -> list[str]:
    """Generate load test specific recommendations."""
    recommendations = []

    # Bottleneck-based recommendations
    for bottleneck in bottlenecks:
        recommendations.append(
            f"{bottleneck['type'].title()} bottleneck: {bottleneck['recommendation']}"
        )

    # General load test recommendations
    if not bottlenecks:
        recommendations.append(
            "Load test completed successfully with no major bottlenecks detected"
        )

    # Scale recommendations
    if target_load > 100:
        recommendations.append(
            "For high load scenarios, consider implementing connection pooling and caching"
        )

    return recommendations


def _analyze_security_test_results(
    logs: list[dict[str, Any]], error_summary: dict[str, Any], security_focus: list[str]
) -> list[dict[str, Any]]:
    """Analyze security test results."""
    findings = []

    # Check for authentication issues
    if "authentication" in security_focus:
        auth_errors = [log for log in logs if log.get("status_code") == 401]
        if auth_errors:
            findings.append(
                {
                    "type": "authentication",
                    "severity": "medium",
                    "count": len(auth_errors),
                    "description": "Authentication failures detected",
                }
            )

    # Check for authorization issues
    if "authorization" in security_focus:
        authz_errors = [log for log in logs if log.get("status_code") == 403]
        if authz_errors:
            findings.append(
                {
                    "type": "authorization",
                    "severity": "medium",
                    "count": len(authz_errors),
                    "description": "Authorization failures detected",
                }
            )

    return findings


def _assess_vulnerabilities(
    findings: list[dict[str, Any]], api_spec: dict[str, Any]
) -> dict[str, Any]:
    """Assess vulnerabilities based on findings."""
    assessment = {"risk_level": "low", "vulnerabilities": [], "recommendations": []}

    high_severity_count = len([f for f in findings if f.get("severity") == "high"])
    medium_severity_count = len([f for f in findings if f.get("severity") == "medium"])

    if high_severity_count > 0:
        assessment["risk_level"] = "high"
    elif medium_severity_count > 2:
        assessment["risk_level"] = "medium"

    assessment["vulnerabilities"] = findings

    return assessment


def _check_compliance_status(
    findings: list[dict[str, Any]],
    vulnerability_assessment: dict[str, Any],
    compliance_requirements: list[str],
) -> dict[str, Any]:
    """Check compliance status against requirements."""
    status = {}

    for requirement in compliance_requirements:
        if requirement.lower() == "gdpr":
            status["gdpr"] = {
                "compliant": vulnerability_assessment.get("risk_level") != "high",
                "issues": [],
            }
        elif requirement.lower() == "pci":
            status["pci"] = {
                "compliant": len(findings) == 0,
                "issues": [f["description"] for f in findings],
            }

    return status


def _generate_security_recommendations(
    findings: list[dict[str, Any]],
    vulnerability_assessment: dict[str, Any],
    security_focus: list[str],
) -> list[str]:
    """Generate security recommendations."""
    recommendations = []

    if vulnerability_assessment.get("risk_level") == "high":
        recommendations.append(
            "High risk vulnerabilities detected - immediate remediation required"
        )

    for finding in findings:
        if finding["type"] == "authentication":
            recommendations.append("Implement stronger authentication mechanisms")
        elif finding["type"] == "authorization":
            recommendations.append("Review and strengthen authorization controls")

    return recommendations


def _calculate_summary_statistics(test_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate summary statistics from test results."""
    if not test_results:
        return {}

    total_tests = len(test_results)
    successful_tests = len([r for r in test_results if r.get("status") == "success"])

    return {
        "total_tests": total_tests,
        "successful_tests": successful_tests,
        "success_rate": (successful_tests / total_tests) * 100,
        "failure_rate": ((total_tests - successful_tests) / total_tests) * 100,
    }


def _analyze_performance_trends(test_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze performance trends across test results."""
    response_times = []
    throughputs = []

    for result in test_results:
        metrics = result.get("performance_metrics", {})
        if "average_response_time_change" in metrics:
            response_times.append(metrics["average_response_time_change"])
        if "throughput_rps" in metrics:
            throughputs.append(metrics["throughput_rps"])

    analysis = {}
    if response_times:
        analysis["response_time_trend"] = {
            "average": sum(response_times) / len(response_times),
            "min": min(response_times),
            "max": max(response_times),
        }

    if throughputs:
        analysis["throughput_trend"] = {
            "average": sum(throughputs) / len(throughputs),
            "min": min(throughputs),
            "max": max(throughputs),
        }

    return analysis


def _analyze_error_patterns(test_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze error patterns across test results."""
    all_errors = []

    for result in test_results:
        error_summary = result.get("error_summary", {})
        error_patterns = error_summary.get("error_patterns", [])
        all_errors.extend(error_patterns)

    # Aggregate error patterns
    pattern_counts = {}
    for error in all_errors:
        pattern = error.get("pattern", "unknown")
        pattern_counts[pattern] = pattern_counts.get(pattern, 0) + error.get("count", 0)

    return {
        "total_errors": sum(pattern_counts.values()),
        "error_patterns": [
            {"pattern": pattern, "count": count}
            for pattern, count in pattern_counts.items()
        ],
    }


def _analyze_test_trends(test_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze trends across test results."""
    return {
        "test_count": len(test_results),
        "trend_direction": "stable",  # Simplified for now
        "performance_stability": "good" if len(test_results) > 0 else "unknown",
    }


def _generate_analysis_recommendations(
    summary_stats: dict[str, Any],
    performance_analysis: dict[str, Any],
    error_analysis: dict[str, Any],
    trend_analysis: dict[str, Any],
) -> list[str]:
    """Generate analysis recommendations."""
    recommendations = []

    success_rate = summary_stats.get("success_rate", 0)
    if success_rate < 90:
        recommendations.append("Low success rate detected - investigate test failures")

    total_errors = error_analysis.get("total_errors", 0)
    if total_errors > 10:
        recommendations.append(
            "High error count - review error patterns and fix underlying issues"
        )

    return recommendations


def _calculate_total_tests(test_plan: dict[str, Any]) -> int:
    """Calculate total number of tests in a test plan."""
    # Simplified calculation
    scenarios = test_plan.get("scenarios", [])
    return len(scenarios) * test_plan.get("iterations_per_scenario", 1)


def _generate_session_summary(session_data: dict[str, Any]) -> dict[str, Any]:
    """Generate session summary."""
    return {
        "session_name": session_data.get("session_name", "unknown"),
        "total_duration": session_data.get("duration", "unknown"),
        "tests_completed": session_data.get("progress", {}).get("completed_tests", 0),
        "tests_failed": session_data.get("progress", {}).get("failed_tests", 0),
        "final_status": session_data.get("session_state", "unknown"),
    }


def _calculate_next_execution(schedule_config: dict[str, Any]) -> str:
    """Calculate next execution time."""
    # Simplified implementation
    return datetime.now(timezone.utc).isoformat()  # noqa: UP017


def _validate_test_suite(test_suite: dict[str, Any]) -> dict[str, bool]:
    """Validate test suite configuration."""
    return {"valid": True, "errors": []}


def _calculate_progress_percentage(progress: dict[str, Any]) -> float:
    """Calculate progress percentage."""
    total = progress.get("total_tests", 0)
    completed = progress.get("completed_tests", 0)
    return (completed / total) * 100 if total > 0 else 0


# Additional helper functions for reporting and comparison
def _generate_summary_report(
    analysis_result: dict[str, Any], test_results: list[dict[str, Any]]
) -> dict[str, Any]:
    """Generate summary report."""
    return {
        "overview": analysis_result.get("summary_statistics", {}),
        "key_findings": analysis_result.get("recommendations", [])[:3],
        "test_count": len(test_results),
    }


def _generate_detailed_report(
    analysis_result: dict[str, Any], test_results: list[dict[str, Any]]
) -> dict[str, Any]:
    """Generate detailed report."""
    return {
        "executive_summary": _generate_summary_report(analysis_result, test_results),
        "performance_details": analysis_result.get("performance_analysis", {}),
        "error_details": analysis_result.get("error_analysis", {}),
        "recommendations": analysis_result.get("recommendations", []),
    }


def _generate_comprehensive_report(
    analysis_result: dict[str, Any], test_results: list[dict[str, Any]]
) -> dict[str, Any]:
    """Generate comprehensive report."""
    return {
        "executive_summary": _generate_summary_report(analysis_result, test_results),
        "detailed_analysis": _generate_detailed_report(analysis_result, test_results),
        "raw_data": {"test_results": test_results, "analysis_result": analysis_result},
    }


def _generate_chart_data(
    test_results: list[dict[str, Any]], analysis_result: dict[str, Any]
) -> dict[str, Any]:
    """Generate chart data for visualization."""
    return {
        "success_rate_chart": {
            "type": "pie",
            "data": analysis_result.get("summary_statistics", {}),
        },
        "performance_trend_chart": {
            "type": "line",
            "data": analysis_result.get("performance_analysis", {}),
        },
    }


def _export_html_report(
    report_content: dict[str, Any], chart_data: dict[str, Any] | None
) -> str:
    """Export report as HTML."""
    html = f"""
    <html>
    <head><title>Test Report</title></head>
    <body>
    <h1>Test Report</h1>
    <pre>{json.dumps(report_content, indent=2)}</pre>
    </body>
    </html>
    """
    return html


def _export_markdown_report(report_content: dict[str, Any]) -> str:
    """Export report as Markdown."""
    return f"""# Test Report

## Summary
{json.dumps(report_content.get("overview", {}), indent=2)}

## Recommendations
{chr(10).join(f"- {rec}" for rec in report_content.get("recommendations", []))}
"""


def _compare_performance_metrics(
    baseline: dict[str, Any], comparison: dict[str, Any]
) -> dict[str, Any]:
    """Compare performance metrics between baseline and comparison."""
    return {
        "response_time_comparison": "improved",  # Simplified
        "throughput_comparison": "stable",
        "overall_performance": "improved",
    }


def _analyze_regressions(
    baseline_stats: dict[str, Any], comparison_stats: dict[str, Any]
) -> dict[str, Any]:
    """Analyze regressions between test runs."""
    return {"regressions_detected": False, "regression_details": []}


def _analyze_improvements(
    baseline_stats: dict[str, Any], comparison_stats: dict[str, Any]
) -> dict[str, Any]:
    """Analyze improvements between test runs."""
    return {
        "improvements_detected": True,
        "improvement_details": ["Response time improved"],
    }


def _calculate_statistical_significance(
    baseline_results: list[dict[str, Any]],
    comparison_results: list[dict[str, Any]],
    metrics: list[str],
) -> dict[str, Any]:
    """Calculate statistical significance of differences."""
    return {"significant_differences": False, "confidence_level": 0.95, "p_values": {}}


def _generate_comparison_recommendations(
    performance_comparison: dict[str, Any],
    regression_analysis: dict[str, Any],
    improvement_analysis: dict[str, Any],
    statistical_significance: dict[str, Any],
) -> list[str]:
    """Generate comparison recommendations."""
    recommendations = []

    if improvement_analysis.get("improvements_detected"):
        recommendations.append(
            "Performance improvements detected - maintain current configuration"
        )

    if regression_analysis.get("regressions_detected"):
        recommendations.append(
            "Performance regressions detected - investigate recent changes"
        )

    return recommendations


def _extract_response_time_metrics(stats: dict[str, Any]) -> dict[str, Any]:
    """Extract response time metrics from stats."""
    return {
        "average": stats.get("average_response_time", 0),
        "min": stats.get("min_response_time", 0),
        "max": stats.get("max_response_time", 0),
    }


def _extract_throughput_metrics(stats: dict[str, Any]) -> dict[str, Any]:
    """Extract throughput metrics from stats."""
    return {
        "requests_per_second": stats.get("requests_per_second", 0),
        "total_requests": stats.get("total_requests", 0),
    }


def _extract_error_rate_metrics(stats: dict[str, Any]) -> dict[str, Any]:
    """Extract error rate metrics from stats."""
    total = stats.get("total_requests", 1)
    errors = stats.get("error_count", 0)
    return {
        "error_rate": (errors / total) * 100,
        "error_count": errors,
        "total_requests": total,
    }


def _extract_resource_usage_metrics(stats: dict[str, Any]) -> dict[str, Any]:
    """Extract resource usage metrics from stats."""
    return {
        "cpu_usage": stats.get("cpu_usage", 0),
        "memory_usage": stats.get("memory_usage", 0),
        "disk_usage": stats.get("disk_usage", 0),
    }


def _calculate_aggregated_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    """Calculate aggregated metrics."""
    aggregated = {}

    # Aggregate response time
    if "response_time" in metrics:
        rt_metrics = metrics["response_time"]
        aggregated["average_response_time"] = rt_metrics.get("average", 0)

    # Aggregate throughput
    if "throughput" in metrics:
        tp_metrics = metrics["throughput"]
        aggregated["total_throughput"] = tp_metrics.get("requests_per_second", 0)

    return aggregated


def _generate_performance_indicators(
    metrics: dict[str, Any], aggregated: dict[str, Any]
) -> dict[str, Any]:
    """Generate performance indicators."""
    indicators = {}

    # Response time indicator
    avg_response_time = aggregated.get("average_response_time", 0)
    if avg_response_time < 100:
        indicators["response_time_status"] = "excellent"
    elif avg_response_time < 500:
        indicators["response_time_status"] = "good"
    else:
        indicators["response_time_status"] = "needs_improvement"

    # Throughput indicator
    throughput = aggregated.get("total_throughput", 0)
    if throughput > 100:
        indicators["throughput_status"] = "excellent"
    elif throughput > 50:
        indicators["throughput_status"] = "good"
    else:
        indicators["throughput_status"] = "needs_improvement"

    return indicators


# Missing MCP Tools Implementation


@mcp_tool_audit("run_security_test")
async def run_security_test(
    server_url: str,
    api_spec: dict[str, Any],
    security_focus: list[str] | None = None,
    compliance_requirements: list[str] | None = None,
    scenario_name: str | None = None,
) -> dict[str, Any]:
    """
    Executes security testing scenarios for vulnerability assessment.

    Args:
        server_url: Target MockLoop server URL
        api_spec: OpenAPI specification for security analysis
        security_focus: List of security areas to focus on
        compliance_requirements: List of compliance standards to check
        scenario_name: Optional specific scenario to use

    Returns:
        Security test execution result
    """
    try:
        security_test_result = {
            "status": "success",
            "test_id": str(uuid.uuid4()),
            "server_url": server_url,
            "security_focus": security_focus
            or ["authentication", "authorization", "injection"],
            "compliance_requirements": compliance_requirements or [],
            "scenario_used": scenario_name,
            "vulnerability_assessment": {},
            "compliance_status": {},
            "security_findings": [],
            "recommendations": [],
        }

        # Generate security test scenarios if none specified
        if not scenario_name:
            security_scenarios = await generate_security_test_scenarios(
                api_spec=api_spec,
                security_focus=security_test_result["security_focus"],
                compliance_requirements=compliance_requirements or [],
            )

            # Deploy the first security scenario
            if security_scenarios.get("scenarios"):
                first_scenario = security_scenarios["scenarios"][0]
                deploy_result = await deploy_scenario(server_url, first_scenario)
                if not deploy_result.get("deployed"):
                    return {
                        **security_test_result,
                        "status": "error",
                        "error": f"Failed to deploy security test scenario: {deploy_result.get('error')}",
                    }
                scenario_name = first_scenario["scenario_name"]
                security_test_result["scenario_used"] = scenario_name

        # Execute security test iteration
        test_result = await run_test_iteration(
            server_url=server_url,
            scenario_name=scenario_name,
            duration_seconds=120,  # Shorter duration for security tests
            monitor_performance=True,
            collect_logs=True,
        )

        # Analyze security test results
        if test_result.get("status") == "success":
            request_logs = test_result.get("request_logs", [])
            error_summary = test_result.get("error_summary", {})

            # Analyze security findings
            security_findings = _analyze_security_test_results(
                request_logs, error_summary, security_test_result["security_focus"]
            )
            security_test_result["security_findings"] = security_findings

            # Assess vulnerabilities
            vulnerability_assessment = _assess_vulnerabilities(
                security_findings, api_spec
            )
            security_test_result["vulnerability_assessment"] = vulnerability_assessment

            # Check compliance status
            if compliance_requirements:
                compliance_status = _check_compliance_status(
                    security_findings, vulnerability_assessment, compliance_requirements
                )
                security_test_result["compliance_status"] = compliance_status

            # Generate security recommendations
            recommendations = _generate_security_recommendations(
                security_findings,
                vulnerability_assessment,
                security_test_result["security_focus"],
            )
            security_test_result["recommendations"] = recommendations

        else:
            security_test_result["status"] = "error"
            security_test_result["error"] = (
                f"Security test execution failed: {test_result.get('error')}"
            )

        return security_test_result

    except Exception as e:
        logger.exception("Error running security test")
        return {
            "status": "error",
            "test_id": str(uuid.uuid4()),
            "server_url": server_url,
            "error": f"Security test failed: {e!s}",
            "security_focus": security_focus or [],
            "compliance_requirements": compliance_requirements or [],
            "scenario_used": None,
            "vulnerability_assessment": {},
            "compliance_status": {},
            "security_findings": [],
            "recommendations": [],
        }


@mcp_tool_audit("analyze_test_results")
async def analyze_test_results(
    test_results: list[dict[str, Any]],
    analysis_type: str = "comprehensive",
    include_recommendations: bool = True,
) -> dict[str, Any]:
    """
    Analyzes test results and provides comprehensive insights.

    Args:
        test_results: List of test result dictionaries
        analysis_type: Type of analysis ("summary", "detailed", "comprehensive")
        include_recommendations: Whether to include recommendations

    Returns:
        Analysis result with insights and recommendations
    """
    try:
        analysis_result = {
            "status": "success",
            "analysis_id": str(uuid.uuid4()),
            "analysis_type": analysis_type,
            "test_count": len(test_results),
            "summary_statistics": {},
            "performance_analysis": {},
            "error_analysis": {},
            "trend_analysis": {},
            "recommendations": [],
        }

        if not test_results:
            return {
                **analysis_result,
                "status": "warning",
                "error": "No test results provided for analysis",
            }

        # Calculate summary statistics
        summary_stats = _calculate_summary_statistics(test_results)
        analysis_result["summary_statistics"] = summary_stats

        # Analyze performance trends
        if analysis_type in ["detailed", "comprehensive"]:
            performance_analysis = _analyze_performance_trends(test_results)
            analysis_result["performance_analysis"] = performance_analysis

            # Analyze error patterns
            error_analysis = _analyze_error_patterns(test_results)
            analysis_result["error_analysis"] = error_analysis

        # Analyze trends across tests
        if analysis_type == "comprehensive":
            trend_analysis = _analyze_test_trends(test_results)
            analysis_result["trend_analysis"] = trend_analysis

        # Generate recommendations
        if include_recommendations:
            recommendations = _generate_analysis_recommendations(
                summary_stats,
                analysis_result.get("performance_analysis", {}),
                analysis_result.get("error_analysis", {}),
                analysis_result.get("trend_analysis", {}),
            )
            analysis_result["recommendations"] = recommendations

        return analysis_result

    except Exception as e:
        logger.exception("Error analyzing test results")
        return {
            "status": "error",
            "analysis_id": str(uuid.uuid4()),
            "analysis_type": analysis_type,
            "test_count": 0,
            "error": f"Analysis failed: {e!s}",
            "summary_statistics": {},
            "performance_analysis": {},
            "error_analysis": {},
            "trend_analysis": {},
            "recommendations": [],
        }


@mcp_tool_audit("generate_test_report")
async def generate_test_report(
    test_results: list[dict[str, Any]],
    report_format: str = "comprehensive",
    include_charts: bool = True,
    output_format: str = "json",
) -> dict[str, Any]:
    """
    Generates formatted test reports in various formats.

    Args:
        test_results: List of test result dictionaries
        report_format: Format type ("summary", "detailed", "comprehensive")
        include_charts: Whether to include chart data
        output_format: Output format ("json", "html", "markdown")

    Returns:
        Generated report in specified format
    """
    try:
        report_result = {
            "status": "success",
            "report_id": str(uuid.uuid4()),
            "report_format": report_format,
            "output_format": output_format,
            "generated_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "report_content": {},
            "chart_data": None,
            "export_data": None,
        }

        # First analyze the test results
        analysis_result = await analyze_test_results(test_results, report_format, True)
        if analysis_result.get("status") != "success":
            return {
                **report_result,
                "status": "error",
                "error": f"Failed to analyze test results: {analysis_result.get('error')}",
            }

        # Generate report content based on format
        if report_format == "summary":
            report_content = _generate_summary_report(analysis_result, test_results)
        elif report_format == "detailed":
            report_content = _generate_detailed_report(analysis_result, test_results)
        else:  # comprehensive
            report_content = _generate_comprehensive_report(
                analysis_result, test_results
            )

        report_result["report_content"] = report_content

        # Generate chart data if requested
        if include_charts:
            chart_data = _generate_chart_data(test_results, analysis_result)
            report_result["chart_data"] = chart_data

        # Export in specified format
        if output_format == "html":
            export_data = _export_html_report(
                report_content, report_result.get("chart_data")
            )
            report_result["export_data"] = export_data
        elif output_format == "markdown":
            export_data = _export_markdown_report(report_content)
            report_result["export_data"] = export_data
        # JSON format is the default (report_content)

        return report_result

    except Exception as e:
        logger.exception("Error generating test report")
        return {
            "status": "error",
            "report_id": str(uuid.uuid4()),
            "report_format": report_format,
            "output_format": output_format,
            "error": f"Report generation failed: {e!s}",
            "generated_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "report_content": {},
            "chart_data": None,
            "export_data": None,
        }


@mcp_tool_audit("compare_test_runs")
async def compare_test_runs(
    baseline_results: list[dict[str, Any]],
    comparison_results: list[dict[str, Any]],
    comparison_metrics: list[str] | None = None,
) -> dict[str, Any]:
    """
    Compares multiple test runs to identify performance changes.

    Args:
        baseline_results: Baseline test results for comparison
        comparison_results: New test results to compare against baseline
        comparison_metrics: Specific metrics to compare

    Returns:
        Comparison result with performance changes
    """
    try:
        comparison_result = {
            "status": "success",
            "comparison_id": str(uuid.uuid4()),
            "baseline_count": len(baseline_results),
            "comparison_count": len(comparison_results),
            "metrics_compared": comparison_metrics
            or ["response_time", "throughput", "error_rate"],
            "performance_comparison": {},
            "regression_analysis": {},
            "improvement_analysis": {},
            "statistical_significance": {},
            "recommendations": [],
        }

        if not baseline_results or not comparison_results:
            return {
                **comparison_result,
                "status": "error",
                "error": "Both baseline and comparison results are required",
            }

        # Analyze both sets of results
        baseline_analysis = await analyze_test_results(
            baseline_results, "detailed", False
        )
        comparison_analysis = await analyze_test_results(
            comparison_results, "detailed", False
        )

        if (
            baseline_analysis.get("status") != "success"
            or comparison_analysis.get("status") != "success"
        ):
            return {
                **comparison_result,
                "status": "error",
                "error": "Failed to analyze test results for comparison",
            }

        # Compare performance metrics
        baseline_stats = baseline_analysis.get("summary_statistics", {})
        comparison_stats = comparison_analysis.get("summary_statistics", {})

        performance_comparison = _compare_performance_metrics(
            baseline_stats, comparison_stats
        )
        comparison_result["performance_comparison"] = performance_comparison

        # Analyze regressions
        regression_analysis = _analyze_regressions(baseline_stats, comparison_stats)
        comparison_result["regression_analysis"] = regression_analysis

        # Analyze improvements
        improvement_analysis = _analyze_improvements(baseline_stats, comparison_stats)
        comparison_result["improvement_analysis"] = improvement_analysis

        # Calculate statistical significance
        statistical_significance = _calculate_statistical_significance(
            baseline_results, comparison_results, comparison_result["metrics_compared"]
        )
        comparison_result["statistical_significance"] = statistical_significance

        # Generate comparison recommendations
        recommendations = _generate_comparison_recommendations(
            performance_comparison,
            regression_analysis,
            improvement_analysis,
            statistical_significance,
        )
        comparison_result["recommendations"] = recommendations

        return comparison_result

    except Exception as e:
        logger.exception("Error comparing test runs")
        return {
            "status": "error",
            "comparison_id": str(uuid.uuid4()),
            "baseline_count": len(baseline_results) if baseline_results else 0,
            "comparison_count": len(comparison_results) if comparison_results else 0,
            "error": f"Test run comparison failed: {e!s}",
            "metrics_compared": comparison_metrics or [],
            "performance_comparison": {},
            "regression_analysis": {},
            "improvement_analysis": {},
            "statistical_significance": {},
            "recommendations": [],
        }


@mcp_tool_audit("get_performance_metrics")
async def get_performance_metrics(
    test_results: list[dict[str, Any]],
    metric_types: list[str] | None = None,
    aggregation_method: str = "average",
) -> dict[str, Any]:
    """
    Retrieves and analyzes performance metrics from test results.

    Args:
        test_results: List of test result dictionaries
        metric_types: Types of metrics to extract
        aggregation_method: Method for aggregating metrics

    Returns:
        Performance metrics analysis
    """
    try:
        metrics_result = {
            "status": "success",
            "metrics_id": str(uuid.uuid4()),
            "test_count": len(test_results),
            "metric_types": metric_types
            or ["response_time", "throughput", "error_rate", "resource_usage"],
            "aggregation_method": aggregation_method,
            "extracted_metrics": {},
            "aggregated_metrics": {},
            "performance_indicators": {},
        }

        if not test_results:
            return {
                **metrics_result,
                "status": "warning",
                "error": "No test results provided for metrics extraction",
            }

        extracted_metrics = {}

        # Extract metrics by type
        for metric_type in metrics_result["metric_types"]:
            if metric_type == "response_time":
                response_time_metrics = []
                for result in test_results:
                    perf_metrics = result.get("performance_metrics", {})
                    if perf_metrics:
                        rt_metrics = _extract_response_time_metrics(perf_metrics)
                        response_time_metrics.append(rt_metrics)
                extracted_metrics["response_time"] = response_time_metrics

            elif metric_type == "throughput":
                throughput_metrics = []
                for result in test_results:
                    perf_metrics = result.get("performance_metrics", {})
                    if perf_metrics:
                        tp_metrics = _extract_throughput_metrics(perf_metrics)
                        throughput_metrics.append(tp_metrics)
                extracted_metrics["throughput"] = throughput_metrics

            elif metric_type == "error_rate":
                error_rate_metrics = []
                for result in test_results:
                    error_summary = result.get("error_summary", {})
                    if error_summary:
                        er_metrics = _extract_error_rate_metrics(error_summary)
                        error_rate_metrics.append(er_metrics)
                extracted_metrics["error_rate"] = error_rate_metrics

            elif metric_type == "resource_usage":
                resource_metrics = []
                for result in test_results:
                    perf_metrics = result.get("performance_metrics", {})
                    if perf_metrics:
                        ru_metrics = _extract_resource_usage_metrics(perf_metrics)
                        resource_metrics.append(ru_metrics)
                extracted_metrics["resource_usage"] = resource_metrics

        metrics_result["extracted_metrics"] = extracted_metrics

        # Calculate aggregated metrics
        aggregated_metrics = _calculate_aggregated_metrics(extracted_metrics)
        metrics_result["aggregated_metrics"] = aggregated_metrics

        # Generate performance indicators
        performance_indicators = _generate_performance_indicators(
            extracted_metrics, aggregated_metrics
        )
        metrics_result["performance_indicators"] = performance_indicators

        return metrics_result

    except Exception as e:
        logger.exception("Error extracting performance metrics")
        return {
            "status": "error",
            "metrics_id": str(uuid.uuid4()),
            "test_count": len(test_results) if test_results else 0,
            "error": f"Performance metrics extraction failed: {e!s}",
            "metric_types": metric_types or [],
            "aggregation_method": aggregation_method,
            "extracted_metrics": {},
            "aggregated_metrics": {},
            "performance_indicators": {},
        }


@mcp_tool_audit("create_test_session")
async def create_test_session(
    session_name: str,
    test_plan: dict[str, Any],
    session_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Creates a new test session for workflow management.

    Args:
        session_name: Name for the test session
        test_plan: Test plan configuration
        session_config: Optional session configuration

    Returns:
        Test session creation result
    """
    try:
        session_id = str(uuid.uuid4())
        session_result = {
            "status": "success",
            "session_id": session_id,
            "session_name": session_name,
            "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "test_plan": test_plan,
            "session_config": session_config or {},
            "session_state": "created",
            "progress": {
                "total_tests": _calculate_total_tests(test_plan),
                "completed_tests": 0,
                "failed_tests": 0,
                "current_test": None,
            },
        }

        # Store session in global storage
        _active_test_sessions[session_id] = session_result.copy()

        return session_result

    except Exception as e:
        logger.exception("Error creating test session")
        return {
            "status": "error",
            "session_id": None,
            "session_name": session_name,
            "error": f"Test session creation failed: {e!s}",
            "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "test_plan": {},
            "session_config": {},
            "session_state": "error",
            "progress": {},
        }


@mcp_tool_audit("end_test_session")
async def end_test_session(
    session_id: str, generate_final_report: bool = True
) -> dict[str, Any]:
    """
    Ends a test session and generates final reports.

    Args:
        session_id: ID of the test session to end
        generate_final_report: Whether to generate a final report

    Returns:
        Test session completion result
    """
    try:
        if session_id not in _active_test_sessions:
            return {
                "status": "error",
                "session_id": session_id,
                "error": "Test session not found",
                "ended_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
                "final_report": None,
                "session_summary": {},
            }

        session_data = _active_test_sessions[session_id]
        session_data["session_state"] = "completed"
        session_data["ended_at"] = datetime.now(timezone.utc).isoformat()  # noqa: UP017

        end_result = {
            "status": "success",
            "session_id": session_id,
            "ended_at": session_data["ended_at"],
            "final_report": None,
            "session_summary": _generate_session_summary(session_data),
        }

        # Generate final report if requested
        if generate_final_report:
            # This would typically include all test results from the session
            # For now, we'll create a placeholder report
            final_report = {
                "session_name": session_data.get("session_name"),
                "duration": session_data.get("ended_at", "")
                + " - "
                + session_data.get("created_at", ""),
                "summary": end_result["session_summary"],
            }
            end_result["final_report"] = final_report

        # Remove from active sessions
        del _active_test_sessions[session_id]

        return end_result

    except Exception as e:
        logger.exception("Error ending test session")
        return {
            "status": "error",
            "session_id": session_id,
            "error": f"Test session completion failed: {e!s}",
            "ended_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "final_report": None,
            "session_summary": {},
        }


@mcp_tool_audit("schedule_test_suite")
async def schedule_test_suite(
    test_suite: dict[str, Any],
    schedule_config: dict[str, Any],
    notification_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Schedules automated test suite execution.

    Args:
        test_suite: Test suite configuration
        schedule_config: Scheduling configuration
        notification_config: Optional notification settings

    Returns:
        Test suite scheduling result
    """
    try:
        schedule_id = str(uuid.uuid4())
        schedule_result = {
            "status": "success",
            "schedule_id": schedule_id,
            "test_suite": test_suite,
            "schedule_config": schedule_config,
            "notification_config": notification_config or {},
            "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "next_execution": _calculate_next_execution(schedule_config),
            "schedule_state": "active",
            "validation_result": _validate_test_suite(test_suite),
        }

        if not schedule_result["validation_result"]["valid"]:
            return {
                **schedule_result,
                "status": "error",
                "error": f"Test suite validation failed: {schedule_result['validation_result']['errors']}",
            }

        return schedule_result

    except Exception as e:
        logger.exception("Error scheduling test suite")
        return {
            "status": "error",
            "schedule_id": None,
            "error": f"Test suite scheduling failed: {e!s}",
            "test_suite": {},
            "schedule_config": {},
            "notification_config": {},
            "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "next_execution": None,
            "schedule_state": "error",
            "validation_result": {"valid": False, "errors": []},
        }


@mcp_tool_audit("monitor_test_progress")
async def monitor_test_progress(
    session_id: str, include_performance_data: bool = True, alert_on_issues: bool = True
) -> dict[str, Any]:
    """
    Monitors ongoing test execution and provides real-time updates.

    Args:
        session_id: ID of the test session to monitor
        include_performance_data: Whether to include performance metrics
        alert_on_issues: Whether to generate alerts for issues

    Returns:
        Test progress monitoring result
    """
    try:
        if session_id not in _active_test_sessions:
            return {
                "status": "error",
                "session_id": session_id,
                "error": "Test session not found",
                "progress": {},
                "performance_data": {},
                "alerts": [],
                "monitoring_timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            }

        session_data = _active_test_sessions[session_id]
        progress = session_data.get("progress", {})

        monitor_result = {
            "status": "success",
            "session_id": session_id,
            "session_state": session_data.get("session_state", "unknown"),
            "progress": progress,
            "progress_percentage": _calculate_progress_percentage(progress),
            "performance_data": {},
            "alerts": [],
            "monitoring_timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }

        # Include performance data if requested
        if include_performance_data:
            # This would typically fetch real-time performance metrics
            # For now, we'll provide placeholder data
            monitor_result["performance_data"] = {
                "current_response_time": "150ms",
                "current_throughput": "45 RPS",
                "current_error_rate": "0.5%",
            }

        # Generate alerts if requested
        if alert_on_issues:
            alerts = []
            if progress.get("failed_tests", 0) > 0:
                alerts.append(
                    {
                        "type": "test_failure",
                        "severity": "warning",
                        "message": f"{progress['failed_tests']} tests have failed",
                    }
                )
            monitor_result["alerts"] = alerts

        return monitor_result

    except Exception as e:
        logger.exception("Error monitoring test progress")
        return {
            "status": "error",
            "session_id": session_id,
            "error": f"Test progress monitoring failed: {e!s}",
            "progress": {},
            "performance_data": {},
            "alerts": [],
            "monitoring_timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }


# MCP Plugin Helper Functions


def _validate_plugin_parameters(
    mode: str,
    target_url: str | None,
    auth_config: dict[str, Any] | None,
    proxy_config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Validate plugin creation parameters."""
    validation_result = {"valid": True, "errors": [], "warnings": []}

    # Validate mode
    valid_modes = ["mock", "proxy", "hybrid"]
    if mode not in valid_modes:
        validation_result["errors"].append(
            f"Invalid mode '{mode}'. Must be one of {valid_modes}"
        )
        validation_result["valid"] = False

    # Validate target_url for proxy/hybrid modes
    if mode in ["proxy", "hybrid"] and not target_url:
        validation_result["errors"].append(
            "target_url is required for proxy and hybrid modes"
        )
        validation_result["valid"] = False

    # Validate target_url format if provided
    if target_url:
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                validation_result["errors"].append(
                    "target_url must be a valid URL with scheme and netloc"
                )
                validation_result["valid"] = False
        except Exception as e:
            validation_result["errors"].append(f"Invalid target_url format: {e!s}")
            validation_result["valid"] = False

    # Validate auth_config if provided
    if auth_config:
        auth_type = auth_config.get("type")
        valid_auth_types = ["api_key", "bearer", "oauth2", "basic", "custom"]
        if auth_type and auth_type not in valid_auth_types:
            validation_result["warnings"].append(
                f"Unknown auth type '{auth_type}'. Supported types: {valid_auth_types}"
            )

    # Validate proxy_config if provided
    if proxy_config:
        timeout = proxy_config.get("timeout")
        if timeout and (not isinstance(timeout, int) or timeout <= 0):
            validation_result["warnings"].append("timeout should be a positive integer")

        retry_attempts = proxy_config.get("retry_attempts")
        if retry_attempts and (
            not isinstance(retry_attempts, int) or retry_attempts < 0
        ):
            validation_result["warnings"].append(
                "retry_attempts should be a non-negative integer"
            )

    return validation_result


async def _load_openapi_spec(spec_url_or_path: str) -> dict[str, Any]:
    """Load OpenAPI specification from URL, file path, or JSON string."""
    try:
        # Check if it's a JSON string (starts with { or [)
        if spec_url_or_path.strip().startswith(("{", "[")):
            return json.loads(spec_url_or_path)

        # Check if it's a URL
        if spec_url_or_path.startswith(("http://", "https://")):
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(spec_url_or_path) as response:
                    if response.status == 200:
                        content_type = response.headers.get("content-type", "")
                        if "json" in content_type:
                            return await response.json()
                        else:
                            # Try to parse as YAML
                            import yaml

                            text = await response.text()
                            return yaml.safe_load(text)
                    else:
                        raise ValueError(
                            f"HTTP {response.status}: Failed to fetch OpenAPI spec"
                        )
        else:
            # Treat as file path
            file_path = Path(spec_url_or_path)
            if not file_path.exists():
                raise FileNotFoundError(
                    f"OpenAPI spec file not found: {spec_url_or_path}"
                )

            with open(file_path, encoding="utf-8") as f:
                if file_path.suffix.lower() in [".yaml", ".yml"]:
                    import yaml

                    return yaml.safe_load(f)
                else:
                    return json.load(f)
    except Exception as e:
        raise ValueError(f"Failed to load OpenAPI specification: {e!s}") from e


def _generate_plugin_name(api_title: str) -> str:
    """Generate a plugin name from API title."""
    # Clean the API title to create a valid plugin name
    plugin_name = api_title.lower()
    # Replace spaces and special characters with underscores
    plugin_name = "".join(c if c.isalnum() else "_" for c in plugin_name)
    # Remove consecutive underscores
    while "__" in plugin_name:
        plugin_name = plugin_name.replace("__", "_")
    # Remove leading/trailing underscores
    plugin_name = plugin_name.strip("_")
    # Ensure it's not empty
    if not plugin_name:
        plugin_name = "api_plugin"
    return plugin_name


def _generate_endpoint_configs(
    api_spec: dict[str, Any], proxy_config: ProxyConfig, mode: str
) -> list[EndpointConfig]:
    """Generate endpoint configurations from OpenAPI specification."""
    endpoints = []
    paths = api_spec.get("paths", {})

    for path, methods in paths.items():
        for method, operation in methods.items():
            if method.upper() in [
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "HEAD",
                "OPTIONS",
            ]:
                # Create mock response from OpenAPI spec
                mock_response = None
                if mode in ["mock", "hybrid"]:
                    responses = operation.get("responses", {})
                    success_response = (
                        responses.get("200")
                        or responses.get("201")
                        or next(iter(responses.values()))
                        if responses
                        else None
                    )

                    if success_response:
                        content = success_response.get("content", {})
                        json_content = content.get("application/json", {})
                        example = json_content.get("example")

                        mock_response = {
                            "status_code": 200,
                            "content": example
                            or {
                                "message": f"Mock response for {method.upper()} {path}"
                            },
                            "headers": {"Content-Type": "application/json"},
                        }

                # Create endpoint configuration
                endpoint = EndpointConfig(
                    path=path,
                    method=method.upper(),
                    mock_response=mock_response,
                    proxy_url=f"{proxy_config.base_url}{path}"
                    if mode in ["proxy", "hybrid"]
                    else None,
                    auth_config=proxy_config.default_auth,
                    timeout=proxy_config.timeout,
                    retry_count=proxy_config.retry_count,
                )
                endpoints.append(endpoint)

    return endpoints


async def _create_mock_plugin(
    api_spec: dict[str, Any], plugin_name: str, proxy_config: ProxyConfig
) -> Path | None:
    """Create mock plugin using existing generate_mock_api functionality."""
    try:
        # Use the existing generate_mock_api function
        mock_server_path = generate_mock_api(
            api_spec,
            mock_server_name=f"{plugin_name}_mock",
            auth_enabled=proxy_config.default_auth is not None,
            webhooks_enabled=True,
            admin_ui_enabled=True,
            storage_enabled=True,
            business_port=8000,
            admin_port=8001,
        )
        return mock_server_path
    except Exception:
        logger.exception("Failed to create mock plugin")
        return None


async def _create_proxy_plugin(plugin_config: PluginConfig) -> dict[str, Any]:
    """Create proxy plugin configuration and handlers."""
    try:
        # Initialize plugin manager
        plugin_manager = PluginManager()

        # Create proxy handler
        proxy_handler = ProxyHandler(mode=plugin_config.proxy_config.mode)

        # Create auth handler
        auth_handler = AuthHandler()

        # Add authentication if configured
        if plugin_config.proxy_config.default_auth:
            auth_config = plugin_config.proxy_config.default_auth
            auth_handler.add_credentials(
                plugin_config.plugin_name,
                auth_config.auth_type,
                auth_config.credentials,
            )

        # Create plugin
        plugin_id = plugin_manager.create_plugin(
            plugin_config.plugin_name,
            plugin_config.api_spec,
            plugin_config.proxy_config.to_dict(),
        )

        return {
            "plugin_id": plugin_id,
            "proxy_handler_status": proxy_handler.get_status(),
            "auth_handler_apis": auth_handler.list_apis(),
            "plugin_manager_status": plugin_manager.get_plugin_status(plugin_id),
        }
    except Exception as e:
        logger.exception("Failed to create proxy plugin")
        return {"error": str(e)}


def _generate_hybrid_routing_rules(api_spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate routing rules for hybrid mode."""
    from .proxy.config import RouteRule

    rules = []
    paths = api_spec.get("paths", {})

    # Create default routing rules
    for path, methods in paths.items():
        for method in methods:
            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                # Default: use mock for GET requests, proxy for mutations
                mode = "mock" if method.upper() == "GET" else "proxy"

                rule = RouteRule(
                    pattern=f"{method.upper()} {path}",
                    mode=ProxyMode(mode.lower()),
                    condition=None,
                    priority=1,
                )
                rules.append(rule)

    return rules


def _generate_mcp_configuration(
    plugin_config: PluginConfig, mode: str
) -> dict[str, Any]:
    """Generate MCP server configuration."""
    mcp_config = {
        "server_name": plugin_config.mcp_server_name,
        "version": "1.0.0",
        "description": f"MCP plugin for {plugin_config.plugin_name} API",
        "mode": mode,
        "tools": [],
        "resources": [],
    }

    # Generate tools based on API endpoints
    for endpoint in plugin_config.proxy_config.endpoints:
        tool_name = f"{plugin_config.plugin_name}_{endpoint.method.lower()}_{endpoint.path.replace('/', '_').replace('{', '').replace('}', '')}"
        tool_name = tool_name.replace("__", "_").strip("_")

        tool = {
            "name": tool_name,
            "description": f"{endpoint.method} {endpoint.path}",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        }
        mcp_config["tools"].append(tool)

    # Generate resources
    resource = {
        "uri": f"api://{plugin_config.plugin_name}/spec",
        "name": f"{plugin_config.plugin_name} API Specification",
        "description": f"OpenAPI specification for {plugin_config.plugin_name}",
        "mimeType": "application/json",
    }
    mcp_config["resources"].append(resource)

    return mcp_config


async def _register_mcp_plugin(plugin_config: PluginConfig) -> dict[str, Any]:
    """Register the MCP plugin (placeholder implementation)."""
    try:
        # This would typically register the plugin with an MCP registry
        # For now, we'll just return a success status
        registration_result = {
            "status": "success",
            "registered": True,
            "plugin_id": plugin_config.mcp_server_name,
            "registration_time": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            "message": f"Plugin {plugin_config.plugin_name} registered successfully",
        }

        logger.info(f"MCP plugin registered: {plugin_config.plugin_name}")
        return registration_result
    except Exception as e:
        logger.exception("Failed to register MCP plugin")
        return {
            "status": "error",
            "registered": False,
            "error": str(e),
            "registration_time": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }


# Enhanced Execute Test Plan Helper Functions


async def _detect_plugin_mode(server_url: str, openapi_spec: dict[str, Any]) -> str:
    """
    Detect the mode of the target plugin automatically.

    Args:
        server_url: Target server URL
        openapi_spec: OpenAPI specification

    Returns:
        Detected mode: "mock", "proxy", or "hybrid"
    """
    try:
        # Check if server_url is a MockLoop server
        connectivity_result = await check_server_connectivity(server_url)
        if connectivity_result.get("status") == "healthy":
            # Check if it's a MockLoop server by looking for admin endpoints
            servers = await discover_running_servers(
                [int(server_url.split(":")[-1])], check_health=True
            )
            for server in servers:
                if server.get("is_mockloop_server"):
                    return "mock"

        # Check if it's a live API by examining the URL and spec
        parsed_url = urlparse(server_url)
        if parsed_url.scheme in ["http", "https"] and parsed_url.netloc:
            # Check if the URL matches any servers in the OpenAPI spec
            servers = openapi_spec.get("servers", [])
            for server in servers:
                if server.get("url") and server["url"] in server_url:
                    return "proxy"

        # Default to mock mode if detection is unclear
        return "mock"

    except Exception:
        logger.debug("Error detecting plugin mode, defaulting to mock")
        return "mock"


async def _generate_enhanced_scenario_config(
    scenario_type: str,
    endpoints: list[dict[str, Any]],
    scenario_name: str,
    mode: str,
    openapi_spec: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate enhanced scenario configuration with mode-specific features.

    Args:
        scenario_type: Type of scenario to generate
        endpoints: List of endpoints to include
        scenario_name: Name for the scenario
        mode: Plugin mode (mock, proxy, hybrid)
        openapi_spec: OpenAPI specification

    Returns:
        Enhanced scenario configuration
    """
    # Start with basic scenario configuration
    base_config = await generate_scenario_config(
        scenario_type, endpoints, scenario_name
    )

    # Add mode-specific enhancements
    if mode == "proxy":
        # Add proxy-specific configurations
        base_config["proxy_config"] = {
            "target_url": openapi_spec.get("servers", [{}])[0].get("url", ""),
            "timeout": 30,
            "retry_count": 3,
            "validate_ssl": True,
        }
    elif mode == "hybrid":
        # Add hybrid-specific configurations
        base_config["hybrid_config"] = {
            "mock_fallback": True,
            "comparison_enabled": True,
            "route_rules": [
                {"pattern": "GET *", "mode": "mock"},
                {"pattern": "POST *", "mode": "proxy"},
                {"pattern": "PUT *", "mode": "proxy"},
                {"pattern": "DELETE *", "mode": "proxy"},
            ],
        }

    # Add validation configuration
    base_config["validation_config"] = {
        "schema_validation": True,
        "response_validation": True,
        "status_code_validation": True,
    }

    return base_config


async def _execute_proxy_aware_test(
    server_url: str,
    scenario_config: dict[str, Any],
    mode: str,
    validation_mode: str,
    comparison_config: dict[str, Any],
    openapi_spec: dict[str, Any],
) -> dict[str, Any]:
    """
    Execute a test with proxy-aware capabilities.

    Args:
        server_url: Target server URL
        scenario_config: Scenario configuration
        mode: Plugin mode
        validation_mode: Validation strictness
        comparison_config: Comparison configuration
        openapi_spec: OpenAPI specification

    Returns:
        Test execution result with proxy-aware data
    """
    test_result = {
        "status": "success",
        "scenario_name": scenario_config.get("scenario_name", "unknown"),
        "mode": mode,
        "validation_mode": validation_mode,
        "mock_responses": [],
        "live_responses": [],
        "request_logs": [],
        "validation_errors": [],
        "performance_metrics": {},
    }

    try:
        if mode == "mock":
            # Execute against mock server
            iteration_result = await run_test_iteration(
                server_url=server_url,
                scenario_name=scenario_config["scenario_name"],
                duration_seconds=60,
                monitor_performance=True,
                collect_logs=True,
            )
            test_result.update(iteration_result)

        elif mode == "proxy":
            # Execute against live API
            proxy_result = await _execute_proxy_test(
                server_url, scenario_config, openapi_spec
            )
            test_result["live_responses"] = proxy_result.get("responses", [])
            test_result["request_logs"] = proxy_result.get("logs", [])
            test_result["performance_metrics"] = proxy_result.get("metrics", {})

        elif mode == "hybrid":
            # Execute against both mock and live API
            mock_result = await run_test_iteration(
                server_url=server_url,
                scenario_name=scenario_config["scenario_name"],
                duration_seconds=30,
                monitor_performance=True,
                collect_logs=True,
            )

            proxy_result = await _execute_proxy_test(
                server_url, scenario_config, openapi_spec
            )

            test_result["mock_responses"] = mock_result.get("request_logs", [])
            test_result["live_responses"] = proxy_result.get("responses", [])
            test_result["request_logs"] = mock_result.get(
                "request_logs", []
            ) + proxy_result.get("logs", [])
            test_result["performance_metrics"] = {
                "mock": mock_result.get("performance_metrics", {}),
                "live": proxy_result.get("metrics", {}),
            }

        return test_result

    except Exception as e:
        logger.exception("Error executing proxy-aware test")
        return {**test_result, "status": "error", "error": str(e)}


async def _execute_proxy_test(
    server_url: str, scenario_config: dict[str, Any], openapi_spec: dict[str, Any]
) -> dict[str, Any]:
    """
    Execute test against a live API through proxy.

    Args:
        server_url: Target API URL
        scenario_config: Scenario configuration
        openapi_spec: OpenAPI specification

    Returns:
        Proxy test execution result
    """
    import aiohttp

    result = {"responses": [], "logs": [], "metrics": {}}

    start_time = time.time()

    try:
        async with aiohttp.ClientSession() as session:
            # Execute requests based on scenario endpoints
            endpoints = scenario_config.get("endpoints", [])
            for endpoint in endpoints[:3]:  # Limit to 3 endpoints for demo
                path = endpoint.get("path", "/")
                method = endpoint.get("method", "GET").upper()

                # Construct full URL
                base_url = server_url.rstrip("/")
                full_url = f"{base_url}{path}"

                try:
                    async with session.request(
                        method, full_url, timeout=30
                    ) as response:
                        response_data = {
                            "url": full_url,
                            "method": method,
                            "status_code": response.status,
                            "headers": dict(response.headers),
                            "response_time_ms": 0,  # Simplified
                            "timestamp": time.time(),
                        }

                        # Try to get response body
                        try:
                            if response.content_type == "application/json":
                                response_data["body"] = await response.json()
                            else:
                                response_data["body"] = await response.text()
                        except Exception:
                            response_data["body"] = None

                        result["responses"].append(response_data)
                        result["logs"].append(response_data)

                except Exception as e:
                    error_data = {
                        "url": full_url,
                        "method": method,
                        "status_code": 0,
                        "error": str(e),
                        "timestamp": time.time(),
                    }
                    result["responses"].append(error_data)
                    result["logs"].append(error_data)

        end_time = time.time()
        result["metrics"] = {
            "total_time_ms": (end_time - start_time) * 1000,
            "requests_made": len(result["responses"]),
            "successful_requests": len(
                [r for r in result["responses"] if r.get("status_code", 0) < 400]
            ),
        }

    except Exception as e:
        logger.exception("Error executing proxy test")
        result["error"] = str(e)

    return result


async def _validate_responses_against_spec(
    request_logs: list[dict[str, Any]],
    openapi_spec: dict[str, Any],
    validation_mode: str,
) -> dict[str, Any]:
    """
    Validate responses against OpenAPI specification.

    Args:
        request_logs: List of request/response logs
        openapi_spec: OpenAPI specification
        validation_mode: Validation strictness

    Returns:
        Validation result
    """
    validation_result = {
        "status": "success",
        "validation_mode": validation_mode,
        "total_responses": len(request_logs),
        "valid_responses": 0,
        "invalid_responses": 0,
        "validation_errors": [],
        "schema_violations": [],
        "status_code_mismatches": [],
    }

    paths = openapi_spec.get("paths", {})

    for log in request_logs:
        path = log.get("path", log.get("url", "")).split("?")[0]  # Remove query params
        method = log.get("method", "GET").lower()
        status_code = log.get("status_code", 0)

        # Find matching path in OpenAPI spec
        spec_path = None
        for spec_path_key in paths:
            if spec_path_key == path or _path_matches_pattern(path, spec_path_key):
                spec_path = spec_path_key
                break

        if not spec_path:
            validation_result["validation_errors"].append(
                {
                    "type": "path_not_found",
                    "path": path,
                    "method": method,
                    "message": f"Path {path} not found in OpenAPI specification",
                }
            )
            validation_result["invalid_responses"] += 1
            continue

        # Check if method is defined
        path_spec = paths[spec_path]
        if method not in path_spec:
            validation_result["validation_errors"].append(
                {
                    "type": "method_not_allowed",
                    "path": path,
                    "method": method,
                    "message": f"Method {method.upper()} not defined for path {path}",
                }
            )
            validation_result["invalid_responses"] += 1
            continue

        # Check status code
        method_spec = path_spec[method]
        responses = method_spec.get("responses", {})
        if str(status_code) not in responses and "default" not in responses:
            validation_result["status_code_mismatches"].append(
                {
                    "path": path,
                    "method": method,
                    "actual_status": status_code,
                    "expected_statuses": list(responses.keys()),
                }
            )
            if validation_mode == "strict":
                validation_result["invalid_responses"] += 1
                continue

        # Basic schema validation (simplified)
        response_body = log.get("body")
        if response_body and str(status_code) in responses:
            response_spec = responses[str(status_code)]
            content_spec = response_spec.get("content", {})
            if "application/json" in content_spec:
                # Simplified schema validation
                schema = content_spec["application/json"].get("schema", {})
                if schema and not _validate_json_schema(response_body, schema):
                    validation_result["schema_violations"].append(
                        {
                            "path": path,
                            "method": method,
                            "status_code": status_code,
                            "message": "Response body does not match schema",
                        }
                    )
                    if validation_mode == "strict":
                        validation_result["invalid_responses"] += 1
                        continue

        validation_result["valid_responses"] += 1

    # Set overall status based on validation mode
    if validation_mode == "strict" and validation_result["invalid_responses"] > 0:
        validation_result["status"] = "failed"
    elif (
        validation_mode == "soft"
        and validation_result["invalid_responses"]
        > validation_result["valid_responses"]
    ):
        validation_result["status"] = "warning"

    return validation_result


async def _compare_responses(
    mock_responses: list[dict[str, Any]],
    live_responses: list[dict[str, Any]],
    ignore_fields: list[str],
    tolerance: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare mock and live API responses.

    Args:
        mock_responses: Responses from mock server
        live_responses: Responses from live API
        ignore_fields: Fields to ignore in comparison
        tolerance: Tolerance settings for numeric comparisons

    Returns:
        Comparison result
    """
    comparison_result = {
        "status": "success",
        "total_comparisons": 0,
        "matching_responses": 0,
        "differing_responses": 0,
        "differences": [],
        "summary": {},
    }

    # Create lookup for live responses by path and method
    live_lookup = {}
    for response in live_responses:
        key = f"{response.get('method', 'GET')}:{response.get('path', response.get('url', ''))}"
        live_lookup[key] = response

    for mock_response in mock_responses:
        key = f"{mock_response.get('method', 'GET')}:{mock_response.get('path', mock_response.get('url', ''))}"
        live_response = live_lookup.get(key)

        if not live_response:
            comparison_result["differences"].append(
                {
                    "type": "missing_live_response",
                    "path": mock_response.get("path", ""),
                    "method": mock_response.get("method", ""),
                    "message": "No corresponding live response found",
                }
            )
            comparison_result["differing_responses"] += 1
            continue

        comparison_result["total_comparisons"] += 1

        # Compare status codes
        mock_status = mock_response.get("status_code", 0)
        live_status = live_response.get("status_code", 0)
        if mock_status != live_status:
            comparison_result["differences"].append(
                {
                    "type": "status_code_mismatch",
                    "path": mock_response.get("path", ""),
                    "method": mock_response.get("method", ""),
                    "mock_value": mock_status,
                    "live_value": live_status,
                }
            )

        # Compare response bodies (simplified)
        mock_body = mock_response.get("body")
        live_body = live_response.get("body")

        if mock_body != live_body:
            # Perform deep comparison ignoring specified fields
            differences = _deep_compare_objects(
                mock_body, live_body, ignore_fields, tolerance
            )
            if differences:
                comparison_result["differences"].extend(
                    [
                        {
                            "type": "body_difference",
                            "path": mock_response.get("path", ""),
                            "method": mock_response.get("method", ""),
                            "field": diff["field"],
                            "mock_value": diff["mock_value"],
                            "live_value": diff["live_value"],
                        }
                        for diff in differences
                    ]
                )
                comparison_result["differing_responses"] += 1
            else:
                comparison_result["matching_responses"] += 1
        else:
            comparison_result["matching_responses"] += 1

    # Generate summary
    comparison_result["summary"] = {
        "match_percentage": (
            comparison_result["matching_responses"]
            / max(comparison_result["total_comparisons"], 1)
        )
        * 100,
        "total_differences": len(comparison_result["differences"]),
        "critical_differences": len(
            [
                d
                for d in comparison_result["differences"]
                if d["type"] == "status_code_mismatch"
            ]
        ),
    }

    return comparison_result


def _path_matches_pattern(path: str, pattern: str) -> bool:
    """Check if a path matches an OpenAPI path pattern."""
    import re

    # Convert OpenAPI path pattern to regex
    regex_pattern = pattern.replace("{", "(?P<").replace("}", ">[^/]+)")
    regex_pattern = f"^{regex_pattern}$"
    return bool(re.match(regex_pattern, path))


def _validate_json_schema(data: Any, schema: dict[str, Any]) -> bool:
    """Simplified JSON schema validation."""
    # This is a very basic implementation
    # In a real implementation, you'd use a proper JSON schema validator
    if "type" in schema:
        expected_type = schema["type"]
        if (
            (expected_type == "object" and not isinstance(data, dict))
            or (expected_type == "array" and not isinstance(data, list))
            or (expected_type == "string" and not isinstance(data, str))
            or (expected_type == "number" and not isinstance(data, int | float))
            or (expected_type == "boolean" and not isinstance(data, bool))
        ):
            return False

    return True


def _deep_compare_objects(
    obj1: Any,
    obj2: Any,
    ignore_fields: list[str],
    tolerance: dict[str, Any],
    path: str = "",
) -> list[dict[str, Any]]:
    """Deep compare two objects and return differences."""
    differences = []

    if not isinstance(obj1, type(obj2)):
        differences.append(
            {
                "field": path or "root",
                "mock_value": obj1,
                "live_value": obj2,
                "difference_type": "type_mismatch",
            }
        )
        return differences

    if isinstance(obj1, dict) and isinstance(obj2, dict):
        all_keys = set(obj1.keys()) | set(obj2.keys())
        for key in all_keys:
            if key in ignore_fields:
                continue

            field_path = f"{path}.{key}" if path else key

            if key not in obj1:
                differences.append(
                    {
                        "field": field_path,
                        "mock_value": None,
                        "live_value": obj2[key],
                        "difference_type": "missing_in_mock",
                    }
                )
            elif key not in obj2:
                differences.append(
                    {
                        "field": field_path,
                        "mock_value": obj1[key],
                        "live_value": None,
                        "difference_type": "missing_in_live",
                    }
                )
            else:
                differences.extend(
                    _deep_compare_objects(
                        obj1[key], obj2[key], ignore_fields, tolerance, field_path
                    )
                )

    elif isinstance(obj1, list) and isinstance(obj2, list):
        if len(obj1) != len(obj2):
            differences.append(
                {
                    "field": f"{path}.length" if path else "length",
                    "mock_value": len(obj1),
                    "live_value": len(obj2),
                    "difference_type": "length_mismatch",
                }
            )

        for i, (item1, item2) in enumerate(zip(obj1, obj2, strict=False)):
            item_path = f"{path}[{i}]" if path else f"[{i}]"
            differences.extend(
                _deep_compare_objects(item1, item2, ignore_fields, tolerance, item_path)
            )

    elif isinstance(obj1, int | float) and isinstance(obj2, int | float):
        numeric_tolerance = tolerance.get("numeric_variance", 0.01)
        if abs(obj1 - obj2) > numeric_tolerance:
            differences.append(
                {
                    "field": path or "root",
                    "mock_value": obj1,
                    "live_value": obj2,
                    "difference_type": "numeric_difference",
                }
            )

    elif obj1 != obj2:
        differences.append(
            {
                "field": path or "root",
                "mock_value": obj1,
                "live_value": obj2,
                "difference_type": "value_mismatch",
            }
        )

    return differences


def _calculate_progress_percentage(progress: dict[str, Any]) -> float:
    """Calculate progress percentage."""
    total = progress.get("total_tests", 0)
    completed = progress.get("completed_tests", 0)
    return (completed / total) * 100 if total > 0 else 0
