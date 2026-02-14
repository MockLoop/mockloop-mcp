# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
MCP Prompts Module for AI-driven scenario generation.

This module provides MCP prompts that enable AI agents to generate test scenarios
dynamically based on OpenAPI specifications. All prompts are integrated with the
comprehensive audit logging infrastructure for regulatory compliance.

Features:
- OpenAPI analysis for testable scenario identification
- Dynamic scenario configuration generation
- Performance optimization for load testing
- Error simulation scenario creation
- Security testing scenario generation
- Full audit logging integration
- JSON schema validation for outputs
"""

import logging
import time
from functools import wraps
from typing import Any
from datetime import datetime

# Handle imports for different execution contexts
if __package__ is None or __package__ == "":
    from mcp_audit_logger import create_audit_logger
else:
    from .mcp_audit_logger import create_audit_logger

# Import FastMCP for prompt decorators

# Configure logger for this module
logger = logging.getLogger(__name__)

# JSON Schema definitions for prompt outputs
SCENARIO_CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "scenario_name": {"type": "string"},
        "description": {"type": "string"},
        "scenario_type": {
            "type": "string",
            "enum": [
                "load_testing",
                "error_simulation",
                "security_testing",
                "functional_testing",
            ],
        },
        "endpoints": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "method": {"type": "string"},
                    "response_config": {
                        "type": "object",
                        "properties": {
                            "status_code": {"type": "integer"},
                            "response_time_ms": {"type": "integer"},
                            "response_data": {"type": "object"},
                            "headers": {"type": "object"},
                        },
                        "required": ["status_code"],
                    },
                },
                "required": ["path", "method", "response_config"],
            },
        },
        "test_parameters": {
            "type": "object",
            "properties": {
                "concurrent_users": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "ramp_up_time": {"type": "integer"},
                "error_rate_threshold": {"type": "number"},
            },
        },
        "validation_rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_type": {"type": "string"},
                    "condition": {"type": "string"},
                    "expected_value": {"type": ["string", "number", "boolean"]},
                },
            },
        },
    },
    "required": ["scenario_name", "description", "scenario_type", "endpoints"],
}

OPENAPI_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "api_summary": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "version": {"type": "string"},
                "total_endpoints": {"type": "integer"},
                "authentication_methods": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "data_models": {"type": "array", "items": {"type": "string"}},
            },
        },
        "testable_scenarios": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "scenario_type": {"type": "string"},
                    "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                    "description": {"type": "string"},
                    "endpoints_involved": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "test_complexity": {
                        "type": "string",
                        "enum": ["simple", "moderate", "complex"],
                    },
                    "estimated_duration": {"type": "string"},
                },
            },
        },
        "risk_areas": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "area": {"type": "string"},
                    "risk_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                    },
                    "description": {"type": "string"},
                    "mitigation_suggestions": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
    },
    "required": ["api_summary", "testable_scenarios", "risk_areas"],
}


def mcp_prompt_audit(prompt_name: str):
    """
    Decorator to add MCP audit logging to prompt functions.

    Args:
        prompt_name: Name of the MCP prompt being audited
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            audit_logger = create_audit_logger(
                db_path="mcp_audit.db",
                session_id=f"mcp_prompt_{prompt_name}",
                user_id="mcp_system",
            )
            start_time = time.time()
            entry_id = None

            try:
                # Log prompt invocation start
                if audit_logger:
                    entry_id = audit_logger.log_prompt_invocation(
                        prompt_name=prompt_name,
                        input_parameters=kwargs,
                        data_sources=["openapi_specification"],
                        compliance_tags=["mcp_prompt", "ai_generation"],
                        processing_purpose="ai_scenario_generation",
                        legal_basis="legitimate_interests",
                    )

                # Execute the original function
                result = await func(*args, **kwargs)

                # Log successful completion
                if audit_logger and entry_id:
                    execution_time_ms = (time.time() - start_time) * 1000
                    audit_logger.log_prompt_invocation(
                        prompt_name=f"{prompt_name}_completion",
                        input_parameters={"original_entry_id": entry_id},
                        generated_output=result,
                        execution_time_ms=execution_time_ms,
                        data_sources=["openapi_specification"],
                        compliance_tags=["mcp_prompt", "ai_generation", "completion"],
                        processing_purpose="ai_scenario_generation_completion",
                        legal_basis="legitimate_interests",
                    )

                return result

            except Exception as e:
                # Log error
                if audit_logger and entry_id:
                    execution_time_ms = (time.time() - start_time) * 1000
                    audit_logger.log_prompt_invocation(
                        prompt_name=f"{prompt_name}_error",
                        input_parameters={"original_entry_id": entry_id},
                        generated_output={"error": str(e)},
                        execution_time_ms=execution_time_ms,
                        data_sources=["openapi_specification"],
                        compliance_tags=["mcp_prompt", "ai_generation", "error"],
                        processing_purpose="ai_scenario_generation_error",
                        legal_basis="legitimate_interests",
                    )
                raise

        return wrapper

    return decorator


def validate_json_schema(
    data: dict[str, Any], schema: dict[str, Any]
) -> tuple[bool, str | None]:
    """
    Validate JSON data against a schema.

    Args:
        data: JSON data to validate
        schema: JSON schema to validate against

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        import jsonschema

        jsonschema.validate(data, schema)
        return True, None
    except ImportError:
        # Fallback validation without jsonschema
        logger.warning("jsonschema not available, performing basic validation")
        return _basic_schema_validation(data, schema)
    except Exception as e:
        return False, str(e)


def _basic_schema_validation(
    data: dict[str, Any], schema: dict[str, Any]
) -> tuple[bool, str | None]:
    """
    Basic schema validation fallback when jsonschema is not available.

    Args:
        data: JSON data to validate
        schema: JSON schema to validate against

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Check required fields
        if "required" in schema:
            for field in schema["required"]:
                if field not in data:
                    return False, f"Missing required field: {field}"

        # Check field types
        if "properties" in schema:
            for field, field_schema in schema["properties"].items():
                if field in data:
                    expected_type = field_schema.get("type")
                    if expected_type == "string" and not isinstance(data[field], str):
                        return False, f"Field {field} must be a string"
                    elif expected_type == "integer" and not isinstance(
                        data[field], int
                    ):
                        return False, f"Field {field} must be an integer"
                    elif expected_type == "array" and not isinstance(data[field], list):
                        return False, f"Field {field} must be an array"
                    elif expected_type == "object" and not isinstance(
                        data[field], dict
                    ):
                        return False, f"Field {field} must be an object"

        return True, None
    except Exception as e:
        return False, str(e)


# MCP Prompt Functions


@mcp_prompt_audit("analyze_openapi_for_testing")
async def analyze_openapi_for_testing(
    openapi_spec: dict[str, Any],
    testing_focus: str = "comprehensive",
    risk_assessment: bool = True,
) -> dict[str, Any]:
    """
    Analyze an OpenAPI specification to identify testable scenarios and risk areas.

    This prompt analyzes the provided OpenAPI specification and generates a comprehensive
    report of testable scenarios, risk areas, and testing recommendations.

    Args:
        openapi_spec: The OpenAPI specification to analyze
        testing_focus: Focus area for testing ("performance", "security", "functional", "comprehensive")
        risk_assessment: Whether to include risk assessment in the analysis

    Returns:
        Structured analysis with testable scenarios and risk areas
    """
    try:
        # Extract basic API information
        info = openapi_spec.get("info", {})
        paths = openapi_spec.get("paths", {})
        components = openapi_spec.get("components", {})
        security = openapi_spec.get("security", [])

        # Analyze API structure
        api_summary = {
            "title": info.get("title", "Unknown API"),
            "version": info.get("version", "1.0.0"),
            "total_endpoints": len(paths),
            "authentication_methods": _extract_auth_methods(security, components),
            "data_models": list(components.get("schemas", {}).keys()),
        }

        # Generate testable scenarios based on endpoints
        testable_scenarios = []

        # Functional testing scenarios
        if testing_focus in ["functional", "comprehensive"]:
            testable_scenarios.extend(_generate_functional_scenarios(paths))

        # Performance testing scenarios
        if testing_focus in ["performance", "comprehensive"]:
            testable_scenarios.extend(_generate_performance_scenarios(paths))

        # Security testing scenarios
        if testing_focus in ["security", "comprehensive"]:
            testable_scenarios.extend(_generate_security_scenarios(paths, security))

        # Risk assessment
        risk_areas = []
        if risk_assessment:
            risk_areas = _assess_api_risks(openapi_spec)

        result = {
            "api_summary": api_summary,
            "testable_scenarios": testable_scenarios,
            "risk_areas": risk_areas,
        }

        # Validate result against schema
        is_valid, error = validate_json_schema(result, OPENAPI_ANALYSIS_SCHEMA)
        if not is_valid:
            logger.warning(f"Generated analysis failed schema validation: {error}")
            # Return a minimal valid structure
            result = {
                "api_summary": api_summary,
                "testable_scenarios": [
                    {
                        "scenario_type": "basic_functional",
                        "priority": "high",
                        "description": "Basic endpoint functionality testing",
                        "endpoints_involved": list(paths.keys())[:5],
                        "test_complexity": "simple",
                        "estimated_duration": "30 minutes",
                    }
                ],
                "risk_areas": [
                    {
                        "area": "general_testing",
                        "risk_level": "medium",
                        "description": "General API testing required",
                        "mitigation_suggestions": [
                            "Implement comprehensive test suite"
                        ],
                    }
                ],
            }

        return result

    except Exception as e:
        logger.exception("Error analyzing OpenAPI specification")
        # Return minimal valid structure on error
        return {
            "api_summary": {
                "title": "Error in Analysis",
                "version": "1.0.0",
                "total_endpoints": 0,
                "authentication_methods": [],
                "data_models": [],
            },
            "testable_scenarios": [
                {
                    "scenario_type": "error_recovery",
                    "priority": "high",
                    "description": "Analysis failed, manual testing required",
                    "endpoints_involved": [],
                    "test_complexity": "complex",
                    "estimated_duration": "Manual assessment needed",
                }
            ],
            "risk_areas": [
                {
                    "area": "analysis_failure",
                    "risk_level": "high",
                    "description": f"Automated analysis failed: {e!s}",
                    "mitigation_suggestions": ["Manual specification review required"],
                }
            ],
        }


@mcp_prompt_audit("generate_scenario_config")
async def generate_scenario_config(
    scenario_type: str,
    endpoints: list[dict[str, Any]],
    test_parameters: dict[str, Any] | None = None,
    scenario_name: str | None = None,
) -> dict[str, Any]:
    """
    Generate a specific scenario configuration for MockLoop testing.

    This prompt creates detailed scenario configurations that can be directly
    used with MockLoop servers for dynamic testing scenarios.

    Args:
        scenario_type: Type of scenario ("load_testing", "error_simulation", "security_testing", "functional_testing")
        endpoints: List of endpoint configurations
        test_parameters: Optional test parameters for the scenario
        scenario_name: Optional custom name for the scenario

    Returns:
        Complete scenario configuration ready for MockLoop
    """
    try:
        # Generate scenario name if not provided
        if not scenario_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scenario_name = f"{scenario_type}_{timestamp}"

        # Set default test parameters based on scenario type
        if not test_parameters:
            test_parameters = _get_default_test_parameters(scenario_type)

        # Process endpoints and generate response configurations
        processed_endpoints = []
        for endpoint in endpoints:
            processed_endpoint = _process_endpoint_for_scenario(endpoint, scenario_type)
            processed_endpoints.append(processed_endpoint)

        # Generate validation rules
        validation_rules = _generate_validation_rules(
            scenario_type, processed_endpoints
        )

        # Create scenario configuration
        scenario_config = {
            "scenario_name": scenario_name,
            "description": _generate_scenario_description(
                scenario_type, len(processed_endpoints)
            ),
            "scenario_type": scenario_type,
            "endpoints": processed_endpoints,
            "test_parameters": test_parameters,
            "validation_rules": validation_rules,
        }

        # Validate result against schema
        is_valid, error = validate_json_schema(scenario_config, SCENARIO_CONFIG_SCHEMA)
        if not is_valid:
            logger.warning(
                f"Generated scenario config failed schema validation: {error}"
            )
            # Fix common validation issues
            scenario_config = _fix_scenario_config(scenario_config)

        return scenario_config

    except Exception as e:
        logger.exception("Error generating scenario configuration")
        # Return minimal valid configuration on error
        return {
            "scenario_name": scenario_name or "error_scenario",
            "description": f"Error generating scenario: {e!s}",
            "scenario_type": scenario_type,
            "endpoints": [
                {
                    "path": "/health",
                    "method": "GET",
                    "response_config": {
                        "status_code": 200,
                        "response_time_ms": 100,
                        "response_data": {"status": "ok"},
                        "headers": {"Content-Type": "application/json"},
                    },
                }
            ],
            "test_parameters": {
                "concurrent_users": 1,
                "duration_seconds": 60,
                "ramp_up_time": 10,
                "error_rate_threshold": 0.05,
            },
            "validation_rules": [],
        }


@mcp_prompt_audit("optimize_scenario_for_load")
async def optimize_scenario_for_load(
    base_scenario: dict[str, Any],
    target_load: int,
    performance_requirements: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Optimize a scenario configuration for load testing performance.

    This prompt takes a base scenario and optimizes it for high-load testing
    by adjusting response times, concurrency settings, and resource usage.

    Args:
        base_scenario: Base scenario configuration to optimize
        target_load: Target number of concurrent users
        performance_requirements: Optional performance requirements

    Returns:
        Optimized scenario configuration for load testing
    """
    try:
        # Copy base scenario
        optimized_scenario = base_scenario.copy()

        # Set default performance requirements
        if not performance_requirements:
            performance_requirements = {
                "max_response_time_ms": 2000,
                "target_throughput_rps": target_load * 2,
                "error_rate_threshold": 0.01,
                "memory_usage_limit_mb": 1024,
            }

        # Optimize test parameters for load
        optimized_scenario["test_parameters"] = {
            "concurrent_users": target_load,
            "duration_seconds": max(300, target_load * 2),  # Scale duration with load
            "ramp_up_time": max(60, target_load // 10),  # Gradual ramp-up
            "error_rate_threshold": performance_requirements.get(
                "error_rate_threshold", 0.01
            ),
        }

        # Optimize endpoint configurations
        optimized_endpoints = []
        for endpoint in optimized_scenario.get("endpoints", []):
            optimized_endpoint = _optimize_endpoint_for_load(
                endpoint, target_load, performance_requirements
            )
            optimized_endpoints.append(optimized_endpoint)

        optimized_scenario["endpoints"] = optimized_endpoints

        # Update scenario metadata
        optimized_scenario["scenario_name"] = (
            f"load_optimized_{optimized_scenario.get('scenario_name', 'scenario')}"
        )
        optimized_scenario["description"] = (
            f"Load-optimized scenario for {target_load} concurrent users"
        )
        optimized_scenario["scenario_type"] = "load_testing"

        # Add load-specific validation rules
        load_validation_rules = [
            {
                "rule_type": "response_time",
                "condition": "max_response_time_ms",
                "expected_value": performance_requirements.get(
                    "max_response_time_ms", 2000
                ),
            },
            {
                "rule_type": "throughput",
                "condition": "min_requests_per_second",
                "expected_value": performance_requirements.get(
                    "target_throughput_rps", target_load
                ),
            },
            {
                "rule_type": "error_rate",
                "condition": "max_error_rate",
                "expected_value": performance_requirements.get(
                    "error_rate_threshold", 0.01
                ),
            },
        ]

        optimized_scenario["validation_rules"] = load_validation_rules

        # Validate result
        is_valid, error = validate_json_schema(
            optimized_scenario, SCENARIO_CONFIG_SCHEMA
        )
        if not is_valid:
            logger.warning(f"Optimized scenario failed schema validation: {error}")
            optimized_scenario = _fix_scenario_config(optimized_scenario)

        return optimized_scenario

    except Exception:
        logger.exception("Error optimizing scenario for load")
        # Return the base scenario with minimal load optimizations
        fallback_scenario = base_scenario.copy()
        fallback_scenario["test_parameters"] = {
            "concurrent_users": target_load,
            "duration_seconds": 300,
            "ramp_up_time": 60,
            "error_rate_threshold": 0.05,
        }
        return fallback_scenario


@mcp_prompt_audit("generate_error_scenarios")
async def generate_error_scenarios(
    api_endpoints: list[dict[str, Any]],
    error_types: list[str] | None = None,
    severity_level: str = "medium",
) -> dict[str, Any]:
    """
    Generate error simulation scenarios for testing error handling.

    This prompt creates scenarios that simulate various error conditions
    to test API resilience and error handling capabilities.

    Args:
        api_endpoints: List of API endpoints to test
        error_types: Optional list of specific error types to simulate
        severity_level: Severity level of errors ("low", "medium", "high")

    Returns:
        Error simulation scenario configuration
    """
    try:
        # Default error types if not specified
        if not error_types:
            error_types = _get_default_error_types(severity_level)

        # Generate error endpoints
        error_endpoints = []
        for endpoint in api_endpoints:
            for error_type in error_types:
                error_endpoint = _create_error_endpoint(
                    endpoint, error_type, severity_level
                )
                error_endpoints.append(error_endpoint)

        # Create error scenario configuration
        scenario_name = f"error_simulation_{severity_level}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        error_scenario = {
            "scenario_name": scenario_name,
            "description": f"Error simulation scenario with {severity_level} severity errors",
            "scenario_type": "error_simulation",
            "endpoints": error_endpoints,
            "test_parameters": {
                "concurrent_users": 10,
                "duration_seconds": 180,
                "ramp_up_time": 30,
                "error_rate_threshold": 1.0,  # Expect errors in this scenario
            },
            "validation_rules": [
                {
                    "rule_type": "error_handling",
                    "condition": "proper_error_responses",
                    "expected_value": True,
                },
                {
                    "rule_type": "response_format",
                    "condition": "valid_error_format",
                    "expected_value": True,
                },
            ],
        }

        # Validate result
        is_valid, error = validate_json_schema(error_scenario, SCENARIO_CONFIG_SCHEMA)
        if not is_valid:
            logger.warning(f"Error scenario failed schema validation: {error}")
            error_scenario = _fix_scenario_config(error_scenario)

        return error_scenario

    except Exception:
        logger.exception("Error generating error scenarios")
        # Return minimal error scenario
        return {
            "scenario_name": "basic_error_simulation",
            "description": "Basic error simulation scenario",
            "scenario_type": "error_simulation",
            "endpoints": [
                {
                    "path": "/error-test",
                    "method": "GET",
                    "response_config": {
                        "status_code": 500,
                        "response_time_ms": 100,
                        "response_data": {"error": "Internal server error"},
                        "headers": {"Content-Type": "application/json"},
                    },
                }
            ],
            "test_parameters": {
                "concurrent_users": 5,
                "duration_seconds": 60,
                "ramp_up_time": 10,
                "error_rate_threshold": 1.0,
            },
            "validation_rules": [],
        }


@mcp_prompt_audit("generate_security_test_scenarios")
async def generate_security_test_scenarios(
    api_spec: dict[str, Any],
    security_focus: list[str] | None = None,
    compliance_requirements: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generate security testing scenarios for API vulnerability assessment.

    This prompt creates scenarios that test for common security vulnerabilities
    and compliance with security standards.

    Args:
        api_spec: OpenAPI specification to analyze for security testing
        security_focus: Optional list of security areas to focus on
        compliance_requirements: Optional list of compliance standards to test

    Returns:
        Security testing scenario configuration
    """
    try:
        # Default security focus areas
        if not security_focus:
            security_focus = [
                "authentication",
                "authorization",
                "input_validation",
                "rate_limiting",
                "data_exposure",
            ]

        # Extract security-relevant information from API spec
        paths = api_spec.get("paths", {})
        security_schemes = api_spec.get("components", {}).get("securitySchemes", {})
        global_security = api_spec.get("security", [])

        # Generate security test endpoints
        security_endpoints = []

        for focus_area in security_focus:
            endpoints = _generate_security_endpoints_for_area(
                focus_area, paths, security_schemes, global_security
            )
            security_endpoints.extend(endpoints)

        # Create security scenario configuration
        scenario_name = f"security_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        security_scenario = {
            "scenario_name": scenario_name,
            "description": f"Security testing scenario covering: {', '.join(security_focus)}",
            "scenario_type": "security_testing",
            "endpoints": security_endpoints,
            "test_parameters": {
                "concurrent_users": 5,
                "duration_seconds": 300,
                "ramp_up_time": 60,
                "error_rate_threshold": 0.8,  # Expect many security-related errors
            },
            "validation_rules": _generate_security_validation_rules(
                security_focus, compliance_requirements
            ),
        }

        # Validate result
        is_valid, error = validate_json_schema(
            security_scenario, SCENARIO_CONFIG_SCHEMA
        )
        if not is_valid:
            logger.warning(f"Security scenario failed schema validation: {error}")
            security_scenario = _fix_scenario_config(security_scenario)

        return security_scenario

    except Exception:
        logger.exception("Error generating security test scenarios")
        # Return minimal security scenario
        return {
            "scenario_name": "basic_security_test",
            "description": "Basic security testing scenario",
            "scenario_type": "security_testing",
            "endpoints": [
                {
                    "path": "/unauthorized-test",
                    "method": "GET",
                    "response_config": {
                        "status_code": 401,
                        "response_time_ms": 100,
                        "response_data": {"error": "Unauthorized"},
                        "headers": {"Content-Type": "application/json"},
                    },
                }
            ],
            "test_parameters": {
                "concurrent_users": 3,
                "duration_seconds": 120,
                "ramp_up_time": 30,
                "error_rate_threshold": 0.9,
            },
            "validation_rules": [],
        }


# Helper functions for prompt implementations


def _extract_auth_methods(security: list[dict], components: dict) -> list[str]:
    """Extract authentication methods from OpenAPI security configuration."""
    auth_methods = []
    security_schemes = components.get("securitySchemes", {})

    for scheme_name, scheme_config in security_schemes.items():
        scheme_type = scheme_config.get("type", "unknown")
        auth_methods.append(f"{scheme_name} ({scheme_type})")

    return auth_methods


def _generate_functional_scenarios(paths: dict) -> list[dict]:
    """Generate functional testing scenarios from API paths."""
    scenarios = []

    # Basic CRUD operations scenario
    crud_endpoints = []
    for path, methods in paths.items():
        for method in methods:
            if method.upper() in ["GET", "POST", "PUT", "DELETE"]:
                crud_endpoints.append(f"{method.upper()} {path}")

    if crud_endpoints:
        scenarios.append(
            {
                "scenario_type": "crud_operations",
                "priority": "high",
                "description": "Test basic CRUD operations across all endpoints",
                "endpoints_involved": crud_endpoints[:10],  # Limit to first 10
                "test_complexity": "moderate",
                "estimated_duration": "45 minutes",
            }
        )

    # Data validation scenario
    post_put_endpoints = []
    for path, methods in paths.items():
        for method in methods:
            if method.upper() in ["POST", "PUT", "PATCH"]:
                post_put_endpoints.append(f"{method.upper()} {path}")

    if post_put_endpoints:
        scenarios.append(
            {
                "scenario_type": "data_validation",
                "priority": "medium",
                "description": "Test input validation and data integrity",
                "endpoints_involved": post_put_endpoints[:5],
                "test_complexity": "moderate",
                "estimated_duration": "30 minutes",
            }
        )

    return scenarios


def _generate_performance_scenarios(paths: dict) -> list[dict]:
    """Generate performance testing scenarios from API paths."""
    scenarios = []

    # High-frequency endpoints
    get_endpoints = []
    for path, methods in paths.items():
        if "get" in methods:
            get_endpoints.append(f"GET {path}")

    if get_endpoints:
        scenarios.append(
            {
                "scenario_type": "load_testing",
                "priority": "high",
                "description": "Load testing for high-frequency read operations",
                "endpoints_involved": get_endpoints[:5],
                "test_complexity": "complex",
                "estimated_duration": "60 minutes",
            }
        )

    # Stress testing scenario
    scenarios.append(
        {
            "scenario_type": "stress_testing",
            "priority": "medium",
            "description": "Stress testing to find breaking points",
            "endpoints_involved": list(paths.keys())[:3],
            "test_complexity": "complex",
            "estimated_duration": "90 minutes",
        }
    )

    return scenarios


def _generate_security_scenarios(paths: dict, security: list) -> list[dict]:
    """Generate security testing scenarios from API paths and security config."""
    scenarios = []

    # Authentication testing
    if security:
        scenarios.append(
            {
                "scenario_type": "authentication_testing",
                "priority": "high",
                "description": "Test authentication mechanisms and unauthorized access",
                "endpoints_involved": list(paths.keys())[:5],
                "test_complexity": "moderate",
                "estimated_duration": "45 minutes",
            }
        )

    # Input validation security
    post_endpoints = [
        path
        for path in paths
        if any(method in ["post", "put", "patch"] for method in paths[path])
    ]
    if post_endpoints:
        scenarios.append(
            {
                "scenario_type": "input_security_testing",
                "priority": "high",
                "description": "Test for injection attacks and malicious input handling",
                "endpoints_involved": post_endpoints[:5],
                "test_complexity": "moderate",
                "estimated_duration": "30 minutes",
            }
        )

    return scenarios


def _assess_api_risks(openapi_spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Assess API risks based on OpenAPI specification."""
    risks = []

    paths = openapi_spec.get("paths", {})
    security = openapi_spec.get("security", [])
    components = openapi_spec.get("components", {})

    # Check for missing authentication
    if not security and not components.get("securitySchemes"):
        risks.append(
            {
                "area": "authentication",
                "risk_level": "high",
                "description": "No authentication mechanisms defined",
                "mitigation_suggestions": [
                    "Implement authentication",
                    "Add security schemes",
                ],
            }
        )

    # Check for sensitive data exposure
    for path in paths:
        if any(
            sensitive in path.lower()
            for sensitive in ["password", "token", "secret", "key"]
        ):
            risks.append(
                {
                    "area": "data_exposure",
                    "risk_level": "critical",
                    "description": f"Potentially sensitive data in path: {path}",
                    "mitigation_suggestions": [
                        "Review path naming",
                        "Implement proper data protection",
                    ],
                }
            )

    # Check for missing input validation
    post_methods = sum(
        1
        for methods in paths.values()
        for method in methods
        if method.lower() in ["post", "put", "patch"]
    )
    if post_methods > 0:
        risks.append(
            {
                "area": "input_validation",
                "risk_level": "medium",
                "description": "Input validation testing required for data modification endpoints",
                "mitigation_suggestions": [
                    "Implement input validation",
                    "Add request body schemas",
                ],
            }
        )

    return risks


def _get_default_test_parameters(scenario_type: str) -> dict[str, Any]:
    """Get default test parameters based on scenario type."""
    defaults = {
        "load_testing": {
            "concurrent_users": 50,
            "duration_seconds": 300,
            "ramp_up_time": 60,
            "error_rate_threshold": 0.05,
        },
        "error_simulation": {
            "concurrent_users": 10,
            "duration_seconds": 180,
            "ramp_up_time": 30,
            "error_rate_threshold": 1.0,
        },
        "security_testing": {
            "concurrent_users": 5,
            "duration_seconds": 240,
            "ramp_up_time": 60,
            "error_rate_threshold": 0.8,
        },
        "functional_testing": {
            "concurrent_users": 10,
            "duration_seconds": 120,
            "ramp_up_time": 20,
            "error_rate_threshold": 0.1,
        },
    }

    return defaults.get(scenario_type, defaults["functional_testing"])


def _process_endpoint_for_scenario(
    endpoint: dict[str, Any], scenario_type: str
) -> dict[str, Any]:
    """Process an endpoint configuration for a specific scenario type."""
    processed = {
        "path": endpoint.get("path", "/"),
        "method": endpoint.get("method", "GET").upper(),
        "response_config": {
            "status_code": 200,
            "response_time_ms": 100,
            "response_data": {"message": "success"},
            "headers": {"Content-Type": "application/json"},
        },
    }

    # Adjust based on scenario type
    if scenario_type == "load_testing":
        processed["response_config"]["response_time_ms"] = 50  # Faster for load testing
    elif scenario_type == "error_simulation":
        processed["response_config"]["status_code"] = 500
        processed["response_config"]["response_data"] = {"error": "Simulated error"}
    elif scenario_type == "security_testing":
        processed["response_config"]["status_code"] = 401
        processed["response_config"]["response_data"] = {"error": "Unauthorized"}

    return processed


def _generate_validation_rules(
    scenario_type: str, endpoints: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Generate validation rules based on scenario type and endpoints."""
    rules = []

    if scenario_type == "load_testing":
        rules.extend(
            [
                {
                    "rule_type": "response_time",
                    "condition": "max_response_time_ms",
                    "expected_value": 2000,
                },
                {
                    "rule_type": "throughput",
                    "condition": "min_requests_per_second",
                    "expected_value": 100,
                },
            ]
        )
    elif scenario_type == "error_simulation":
        rules.extend(
            [
                {
                    "rule_type": "error_handling",
                    "condition": "proper_error_responses",
                    "expected_value": True,
                }
            ]
        )
    elif scenario_type == "security_testing":
        rules.extend(
            [
                {
                    "rule_type": "security",
                    "condition": "unauthorized_access_blocked",
                    "expected_value": True,
                }
            ]
        )

    return rules


def _generate_scenario_description(scenario_type: str, endpoint_count: int) -> str:
    """Generate a description for a scenario based on type and endpoint count."""
    descriptions = {
        "load_testing": f"Load testing scenario with {endpoint_count} endpoints to assess performance under high traffic",
        "error_simulation": f"Error simulation scenario with {endpoint_count} endpoints to test error handling capabilities",
        "security_testing": f"Security testing scenario with {endpoint_count} endpoints to identify vulnerabilities",
        "functional_testing": f"Functional testing scenario with {endpoint_count} endpoints to verify basic functionality",
    }

    return descriptions.get(
        scenario_type, f"Testing scenario with {endpoint_count} endpoints"
    )


def _fix_scenario_config(scenario_config: dict[str, Any]) -> dict[str, Any]:
    """Fix common validation issues in scenario configuration."""
    # Ensure required fields exist
    if "scenario_name" not in scenario_config:
        scenario_config["scenario_name"] = (
            f"fixed_scenario_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

    if "description" not in scenario_config:
        scenario_config["description"] = "Auto-generated scenario configuration"

    if "scenario_type" not in scenario_config:
        scenario_config["scenario_type"] = "functional_testing"

    if "endpoints" not in scenario_config or not scenario_config["endpoints"]:
        scenario_config["endpoints"] = [
            {
                "path": "/health",
                "method": "GET",
                "response_config": {
                    "status_code": 200,
                    "response_time_ms": 100,
                    "response_data": {"status": "ok"},
                    "headers": {"Content-Type": "application/json"},
                },
            }
        ]

    # Fix endpoint configurations
    for endpoint in scenario_config["endpoints"]:
        if "response_config" not in endpoint:
            endpoint["response_config"] = {"status_code": 200}
        elif "status_code" not in endpoint["response_config"]:
            endpoint["response_config"]["status_code"] = 200

    return scenario_config


def _optimize_endpoint_for_load(
    endpoint: dict[str, Any], target_load: int, performance_requirements: dict[str, Any]
) -> dict[str, Any]:
    """Optimize an endpoint configuration for load testing."""
    optimized = endpoint.copy()

    # Reduce response time for high load
    max_response_time = performance_requirements.get("max_response_time_ms", 2000)
    optimized_response_time = min(
        max_response_time // 2, 500
    )  # Cap at 500ms for load testing

    if "response_config" in optimized:
        optimized["response_config"]["response_time_ms"] = optimized_response_time

        # Simplify response data for better performance
        optimized["response_config"]["response_data"] = {
            "status": "ok",
            "load_optimized": True,
        }

    return optimized


def _get_default_error_types(severity_level: str) -> list[str]:
    """Get default error types based on severity level."""
    error_types = {
        "low": ["timeout", "rate_limit"],
        "medium": ["timeout", "rate_limit", "server_error", "bad_request"],
        "high": [
            "timeout",
            "rate_limit",
            "server_error",
            "bad_request",
            "database_error",
            "service_unavailable",
        ],
    }

    return error_types.get(severity_level, error_types["medium"])


def _create_error_endpoint(
    endpoint: dict[str, Any], error_type: str, severity_level: str
) -> dict[str, Any]:
    """Create an error endpoint configuration."""
    error_configs = {
        "timeout": {
            "status_code": 408,
            "response_time_ms": 30000,
            "response_data": {"error": "Request timeout"},
        },
        "rate_limit": {
            "status_code": 429,
            "response_time_ms": 100,
            "response_data": {"error": "Rate limit exceeded"},
        },
        "server_error": {
            "status_code": 500,
            "response_time_ms": 200,
            "response_data": {"error": "Internal server error"},
        },
        "bad_request": {
            "status_code": 400,
            "response_time_ms": 100,
            "response_data": {"error": "Bad request"},
        },
        "database_error": {
            "status_code": 503,
            "response_time_ms": 5000,
            "response_data": {"error": "Database unavailable"},
        },
        "service_unavailable": {
            "status_code": 503,
            "response_time_ms": 100,
            "response_data": {"error": "Service unavailable"},
        },
    }

    error_config = error_configs.get(error_type, error_configs["server_error"])

    return {
        "path": endpoint.get("path", "/") + f"-{error_type}",
        "method": endpoint.get("method", "GET").upper(),
        "response_config": {
            **error_config,
            "headers": {"Content-Type": "application/json"},
        },
    }


def _generate_security_endpoints_for_area(
    focus_area: str, paths: dict, security_schemes: dict, global_security: list
) -> list[dict[str, Any]]:
    """Generate security test endpoints for a specific focus area."""
    endpoints = []

    if focus_area == "authentication":
        endpoints.append(
            {
                "path": "/auth-test-unauthorized",
                "method": "GET",
                "response_config": {
                    "status_code": 401,
                    "response_time_ms": 100,
                    "response_data": {"error": "Unauthorized"},
                    "headers": {"Content-Type": "application/json"},
                },
            }
        )

    elif focus_area == "authorization":
        endpoints.append(
            {
                "path": "/auth-test-forbidden",
                "method": "GET",
                "response_config": {
                    "status_code": 403,
                    "response_time_ms": 100,
                    "response_data": {"error": "Forbidden"},
                    "headers": {"Content-Type": "application/json"},
                },
            }
        )

    elif focus_area == "input_validation":
        endpoints.append(
            {
                "path": "/input-validation-test",
                "method": "POST",
                "response_config": {
                    "status_code": 422,
                    "response_time_ms": 150,
                    "response_data": {"error": "Validation failed"},
                    "headers": {"Content-Type": "application/json"},
                },
            }
        )

    elif focus_area == "rate_limiting":
        endpoints.append(
            {
                "path": "/rate-limit-test",
                "method": "GET",
                "response_config": {
                    "status_code": 429,
                    "response_time_ms": 100,
                    "response_data": {"error": "Rate limit exceeded"},
                    "headers": {"Content-Type": "application/json"},
                },
            }
        )

    elif focus_area == "data_exposure":
        endpoints.append(
            {
                "path": "/data-exposure-test",
                "method": "GET",
                "response_config": {
                    "status_code": 200,
                    "response_time_ms": 100,
                    "response_data": {"message": "No sensitive data exposed"},
                    "headers": {"Content-Type": "application/json"},
                },
            }
        )

    return endpoints


def _generate_security_validation_rules(
    security_focus: list[str], compliance_requirements: list[str] | None
) -> list[dict[str, Any]]:
    """Generate security validation rules based on focus areas and compliance requirements."""
    rules = []

    for focus_area in security_focus:
        if focus_area == "authentication":
            rules.append(
                {
                    "rule_type": "security",
                    "condition": "authentication_required",
                    "expected_value": True,
                }
            )
        elif focus_area == "authorization":
            rules.append(
                {
                    "rule_type": "security",
                    "condition": "proper_authorization",
                    "expected_value": True,
                }
            )
        elif focus_area == "input_validation":
            rules.append(
                {
                    "rule_type": "security",
                    "condition": "input_sanitization",
                    "expected_value": True,
                }
            )
        elif focus_area == "rate_limiting":
            rules.append(
                {
                    "rule_type": "security",
                    "condition": "rate_limiting_active",
                    "expected_value": True,
                }
            )
        elif focus_area == "data_exposure":
            rules.append(
                {
                    "rule_type": "security",
                    "condition": "no_sensitive_data_exposure",
                    "expected_value": True,
                }
            )

    # Add compliance-specific rules
    if compliance_requirements:
        for requirement in compliance_requirements:
            rules.append(
                {
                    "rule_type": "compliance",
                    "condition": f"{requirement}_compliance",
                    "expected_value": True,
                }
            )

    return rules
