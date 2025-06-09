# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
MCP Resources Module for scenario pack management.

This module provides MCP resources that expose built-in scenario packs organized by testing patterns.
All resources are integrated with the comprehensive audit logging infrastructure for regulatory compliance.

Features:
- Built-in scenario packs by testing patterns (errors, performance, security, business logic)
- Resource discovery and filtering capabilities
- Full audit logging integration for resource access
- Content integrity verification with hashing
- Version management for scenario packs
- Placeholder architecture for future community repository integration

Resource URI Format:
- scenario-pack://errors/4xx-client-errors
- scenario-pack://performance/load-testing
- scenario-pack://security/auth-bypass
- scenario-pack://business/edge-cases
"""

import json
import logging
import time
import uuid
import hashlib
from functools import wraps
from typing import Any, Optional
from datetime import datetime, timezone

# Handle imports for different execution contexts
if __package__ is None or __package__ == "":
    from mcp_audit_logger import create_audit_logger
else:
    from .mcp_audit_logger import create_audit_logger

# Import FastMCP for resource decorators
from mcp.server.fastmcp import FastMCP

# Configure logger for this module
logger = logging.getLogger(__name__)

# Resource metadata and versioning
RESOURCE_VERSION = "1.0.0"
RESOURCE_SCHEMA_VERSION = "1.0"
LAST_UPDATED = datetime.now(timezone.utc).isoformat()  # noqa: UP017

# Resource categories and their scenario packs
SCENARIO_PACK_CATEGORIES = {
    "errors": {
        "4xx-client-errors": "HTTP 4xx client error scenarios",
        "5xx-server-errors": "HTTP 5xx server error scenarios",
        "network-timeouts": "Network timeout scenarios",
        "rate-limiting": "Rate limiting scenarios",
    },
    "performance": {
        "load-testing": "Load testing scenarios",
        "stress-testing": "Stress testing scenarios",
        "spike-testing": "Spike testing scenarios",
        "endurance-testing": "Endurance testing scenarios",
    },
    "security": {
        "auth-bypass": "Authentication bypass scenarios",
        "injection-attacks": "SQL/NoSQL injection scenarios",
        "xss-attacks": "Cross-site scripting scenarios",
        "csrf-attacks": "CSRF attack scenarios",
    },
    "business": {
        "edge-cases": "Edge case scenarios",
        "data-validation": "Data validation scenarios",
        "workflow-testing": "Business workflow scenarios",
    },
}


def mcp_resource_audit(resource_uri: str):
    """
    Decorator to add MCP audit logging to resource access functions.

    Args:
        resource_uri: URI of the MCP resource being audited
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            audit_logger = create_audit_logger(
                db_path="mcp_audit.db",
                session_id=f"mcp_resource_{resource_uri.replace('://', '_').replace('/', '_')}",
                user_id="mcp_system",
            )
            start_time = time.time()
            entry_id = None

            try:
                # Log resource access start
                if audit_logger:
                    entry_id = audit_logger.log_resource_access(
                        resource_uri=resource_uri,
                        access_type="read",
                        metadata=kwargs,
                        data_sources=["built_in_scenarios"],
                        compliance_tags=["mcp_resource", "scenario_pack"],
                        processing_purpose="scenario_pack_access",
                        legal_basis="legitimate_interests",
                    )

                # Execute the original function
                result = await func(*args, **kwargs)

                # Log successful completion with content hash
                if audit_logger and entry_id:
                    execution_time_ms = (time.time() - start_time) * 1000
                    content_hash = _calculate_content_hash(result)

                    audit_logger.log_resource_access(
                        resource_uri=f"{resource_uri}_completion",
                        access_type="read_completion",
                        metadata={"original_entry_id": entry_id},
                        content_preview=f"content_hash: {content_hash}, size: {len(json.dumps(result))}",
                        execution_time_ms=execution_time_ms,
                        data_sources=["built_in_scenarios"],
                        compliance_tags=["mcp_resource", "scenario_pack", "completion"],
                        processing_purpose="scenario_pack_access_completion",
                        legal_basis="legitimate_interests",
                    )

                return result

            except Exception as e:
                # Log error
                if audit_logger and entry_id:
                    execution_time_ms = (time.time() - start_time) * 1000
                    audit_logger.log_resource_access(
                        resource_uri=f"{resource_uri}_error",
                        access_type="read_error",
                        metadata={"original_entry_id": entry_id},
                        content_preview=f"error: {e!s}",
                        execution_time_ms=execution_time_ms,
                        data_sources=["built_in_scenarios"],
                        compliance_tags=["mcp_resource", "scenario_pack", "error"],
                        processing_purpose="scenario_pack_access_error",
                        legal_basis="legitimate_interests",
                        error_details=str(e),
                    )
                raise

        return wrapper

    return decorator


def _calculate_content_hash(content: Any) -> str:
    """Calculate SHA-256 hash of content for integrity verification."""
    try:
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()
    except Exception:
        return "hash_calculation_failed"


def _validate_resource_uri(uri: str) -> tuple[bool, str, str, str]:
    """
    Validate and parse resource URI.

    Returns:
        Tuple of (is_valid, category, pack_name, error_message)
    """
    if not uri.startswith("scenario-pack://"):
        return False, "", "", "Invalid URI scheme. Must start with 'scenario-pack://'"

    try:
        path = uri.replace("scenario-pack://", "")
        parts = path.split("/")

        if len(parts) != 2:
            return (
                False,
                "",
                "",
                "Invalid URI format. Expected: scenario-pack://category/pack-name",
            )

        category, pack_name = parts

        if category not in SCENARIO_PACK_CATEGORIES:
            return (
                False,
                "",
                "",
                f"Unknown category: {category}. Available: {list(SCENARIO_PACK_CATEGORIES.keys())}",
            )

        if pack_name not in SCENARIO_PACK_CATEGORIES[category]:
            return (
                False,
                "",
                "",
                f"Unknown pack: {pack_name} in category {category}. Available: {list(SCENARIO_PACK_CATEGORIES[category].keys())}",
            )

        return True, category, pack_name, ""

    except Exception as e:
        return False, "", "", f"URI parsing error: {e}"


# Error Simulation Scenario Packs


@mcp_resource_audit("scenario-pack://errors/4xx-client-errors")
async def get_4xx_client_errors_pack() -> dict[str, Any]:
    """HTTP 4xx client error scenarios for testing error handling."""
    return {
        "metadata": {
            "name": "4xx Client Errors",
            "description": "Comprehensive HTTP 4xx client error scenarios for testing error handling and user experience",
            "category": "errors",
            "pack_id": "4xx-client-errors",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "30-45 minutes",
            "tags": ["errors", "4xx", "client-errors", "http", "validation"],
            "use_cases": [
                "API error handling validation",
                "Client-side error recovery testing",
                "User experience error scenarios",
                "Input validation testing",
            ],
            "prerequisites": ["Basic HTTP knowledge", "Error handling implementation"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "bad_request_validation",
                "description": "Test 400 Bad Request responses for invalid input data",
                "scenario_type": "error_simulation",
                "endpoints": [
                    {
                        "path": "/api/users",
                        "method": "POST",
                        "response_config": {
                            "status_code": 400,
                            "response_time_ms": 150,
                            "response_data": {
                                "error": "Bad Request",
                                "message": "Invalid input data",
                                "details": {
                                    "field_errors": {
                                        "email": "Invalid email format",
                                        "age": "Must be between 18 and 120",
                                    }
                                },
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 5,
                    "duration_seconds": 120,
                    "ramp_up_time": 20,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "status_code",
                        "condition": "equals",
                        "expected_value": 400,
                    },
                    {
                        "rule_type": "response_format",
                        "condition": "contains_field",
                        "expected_value": "error",
                    },
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Use for testing client-side error handling",
                "Validate error message formats and consistency",
                "Test user experience during error conditions",
            ],
            "integration_notes": [
                "Combine with logging scenarios to test error tracking",
                "Use with authentication scenarios for comprehensive testing",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://errors/5xx-server-errors")
async def get_5xx_server_errors_pack() -> dict[str, Any]:
    """HTTP 5xx server error scenarios for testing system resilience."""
    return {
        "metadata": {
            "name": "5xx Server Errors",
            "description": "Comprehensive HTTP 5xx server error scenarios for testing system resilience and recovery",
            "category": "errors",
            "pack_id": "5xx-server-errors",
            "version": RESOURCE_VERSION,
            "complexity": "high",
            "estimated_duration": "45-60 minutes",
            "tags": ["errors", "5xx", "server-errors", "resilience", "recovery"],
            "use_cases": [
                "System resilience testing",
                "Error recovery validation",
                "Monitoring and alerting testing",
                "Failover scenario testing",
            ],
            "prerequisites": ["Error handling implementation", "Monitoring setup"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "internal_server_error",
                "description": "Test 500 Internal Server Error responses for unexpected failures",
                "scenario_type": "error_simulation",
                "endpoints": [
                    {
                        "path": "/api/process-data",
                        "method": "POST",
                        "response_config": {
                            "status_code": 500,
                            "response_time_ms": 5000,
                            "response_data": {
                                "error": "Internal Server Error",
                                "message": "An unexpected error occurred",
                                "error_id": "ERR-500-001",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 3,
                    "duration_seconds": 180,
                    "ramp_up_time": 30,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "status_code",
                        "condition": "equals",
                        "expected_value": 500,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Test system resilience under server failures",
                "Validate error recovery mechanisms",
            ],
            "integration_notes": [
                "Combine with load testing for realistic failure scenarios",
                "Use with monitoring scenarios to test alerting",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://errors/network-timeouts")
async def get_network_timeouts_pack() -> dict[str, Any]:
    """Network timeout scenarios for testing timeout handling and resilience."""
    return {
        "metadata": {
            "name": "Network Timeouts",
            "description": "Network timeout scenarios for testing timeout handling, retries, and system resilience",
            "category": "errors",
            "pack_id": "network-timeouts",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "30-45 minutes",
            "tags": ["errors", "timeouts", "network", "resilience", "retries"],
            "use_cases": [
                "Timeout handling validation",
                "Retry mechanism testing",
                "Network resilience testing",
            ],
            "prerequisites": ["Timeout configuration", "Retry logic implementation"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "connection_timeout",
                "description": "Test connection timeout scenarios",
                "scenario_type": "error_simulation",
                "endpoints": [
                    {
                        "path": "/api/slow-connect",
                        "method": "GET",
                        "response_config": {
                            "status_code": 408,
                            "response_time_ms": 60000,
                            "response_data": {
                                "error": "Request Timeout",
                                "message": "Connection timeout",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 3,
                    "duration_seconds": 300,
                    "ramp_up_time": 60,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "status_code",
                        "condition": "equals",
                        "expected_value": 408,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Test client timeout configurations",
                "Validate retry mechanisms",
            ],
            "integration_notes": [
                "Combine with load testing for realistic scenarios",
                "Use with monitoring to test timeout alerting",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://errors/rate-limiting")
async def get_rate_limiting_pack() -> dict[str, Any]:
    """Rate limiting scenarios for testing API rate limits and throttling."""
    return {
        "metadata": {
            "name": "Rate Limiting",
            "description": "Rate limiting scenarios for testing API rate limits, throttling, and quota management",
            "category": "errors",
            "pack_id": "rate-limiting",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "30-40 minutes",
            "tags": ["errors", "rate-limiting", "throttling", "quotas", "429"],
            "use_cases": [
                "Rate limit testing",
                "Throttling mechanism validation",
                "Quota management testing",
            ],
            "prerequisites": ["Rate limiting implementation", "Quota tracking"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "rate_limit_exceeded",
                "description": "Test 429 Too Many Requests responses for rate limit violations",
                "scenario_type": "error_simulation",
                "endpoints": [
                    {
                        "path": "/api/data",
                        "method": "GET",
                        "response_config": {
                            "status_code": 429,
                            "response_time_ms": 100,
                            "response_data": {
                                "error": "Too Many Requests",
                                "message": "Rate limit exceeded",
                            },
                            "headers": {
                                "Content-Type": "application/json",
                                "X-RateLimit-Limit": "100",
                                "X-RateLimit-Remaining": "0",
                                "Retry-After": "60",
                            },
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 10,
                    "duration_seconds": 180,
                    "ramp_up_time": 30,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "status_code",
                        "condition": "equals",
                        "expected_value": 429,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Test rate limiting mechanisms",
                "Validate throttling responses",
            ],
            "integration_notes": [
                "Combine with load testing for realistic rate limit testing",
                "Use with authentication scenarios for user-specific limits",
            ],
        },
    }


# Performance Testing Scenario Packs


@mcp_resource_audit("scenario-pack://performance/load-testing")
async def get_load_testing_pack() -> dict[str, Any]:
    """Load testing scenarios for performance validation under normal traffic."""
    return {
        "metadata": {
            "name": "Load Testing",
            "description": "Load testing scenarios for validating system performance under expected traffic loads",
            "category": "performance",
            "pack_id": "load-testing",
            "version": RESOURCE_VERSION,
            "complexity": "high",
            "estimated_duration": "60-90 minutes",
            "tags": ["performance", "load-testing", "throughput", "response-time"],
            "use_cases": [
                "Performance baseline establishment",
                "Capacity planning validation",
                "SLA compliance testing",
            ],
            "prerequisites": ["Performance monitoring", "Load testing tools"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "steady_state_load",
                "description": "Sustained load testing at expected traffic levels",
                "scenario_type": "load_testing",
                "endpoints": [
                    {
                        "path": "/api/users",
                        "method": "GET",
                        "response_config": {
                            "status_code": 200,
                            "response_time_ms": 150,
                            "response_data": {
                                "users": [
                                    {
                                        "id": 1,
                                        "name": "User 1",
                                        "email": "user1@example.com",
                                    }
                                ],
                                "total": 1,
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 100,
                    "duration_seconds": 600,
                    "ramp_up_time": 120,
                    "error_rate_threshold": 0.01,
                },
                "validation_rules": [
                    {
                        "rule_type": "response_time",
                        "condition": "p95_response_time_ms",
                        "expected_value": 500,
                    },
                    {
                        "rule_type": "throughput",
                        "condition": "min_requests_per_second",
                        "expected_value": 200,
                    },
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Establish performance baselines",
                "Validate system capacity",
            ],
            "integration_notes": [
                "Combine with monitoring scenarios",
                "Use with database performance testing",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://performance/stress-testing")
async def get_stress_testing_pack() -> dict[str, Any]:
    """Stress testing scenarios for finding system breaking points."""
    return {
        "metadata": {
            "name": "Stress Testing",
            "description": "Stress testing scenarios for finding system breaking points and failure modes",
            "category": "performance",
            "pack_id": "stress-testing",
            "version": RESOURCE_VERSION,
            "complexity": "high",
            "estimated_duration": "90-120 minutes",
            "tags": [
                "performance",
                "stress-testing",
                "breaking-point",
                "failure-modes",
            ],
            "use_cases": [
                "Breaking point identification",
                "Failure mode analysis",
                "System limits testing",
            ],
            "prerequisites": ["Monitoring setup", "Recovery procedures"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "progressive_load_increase",
                "description": "Gradually increase load until system failure",
                "scenario_type": "stress_testing",
                "endpoints": [
                    {
                        "path": "/api/compute-intensive",
                        "method": "POST",
                        "response_config": {
                            "status_code": 200,
                            "response_time_ms": 1000,
                            "response_data": {
                                "result": "computation_complete",
                                "processing_time": "1000ms",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 500,
                    "duration_seconds": 1800,
                    "ramp_up_time": 600,
                    "error_rate_threshold": 0.5,
                },
                "validation_rules": [
                    {
                        "rule_type": "breaking_point",
                        "condition": "identify_failure_threshold",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Find system breaking points",
                "Test failure recovery mechanisms",
            ],
            "integration_notes": [
                "Requires comprehensive monitoring",
                "Use with recovery testing scenarios",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://performance/spike-testing")
async def get_spike_testing_pack() -> dict[str, Any]:
    """Spike testing scenarios for sudden traffic increases."""
    return {
        "metadata": {
            "name": "Spike Testing",
            "description": "Spike testing scenarios for validating system behavior under sudden traffic increases",
            "category": "performance",
            "pack_id": "spike-testing",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "45-60 minutes",
            "tags": ["performance", "spike-testing", "traffic-spikes", "auto-scaling"],
            "use_cases": [
                "Auto-scaling validation",
                "Traffic spike handling",
                "Cache warming testing",
            ],
            "prerequisites": ["Auto-scaling setup", "Performance monitoring"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "sudden_traffic_spike",
                "description": "Simulate sudden traffic spike to test auto-scaling",
                "scenario_type": "spike_testing",
                "endpoints": [
                    {
                        "path": "/api/popular-content",
                        "method": "GET",
                        "response_config": {
                            "status_code": 200,
                            "response_time_ms": 300,
                            "response_data": {
                                "content": "Popular content data",
                                "cache_status": "miss",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 1000,
                    "duration_seconds": 300,
                    "ramp_up_time": 30,
                    "error_rate_threshold": 0.1,
                },
                "validation_rules": [
                    {
                        "rule_type": "auto_scaling",
                        "condition": "scaling_response_time",
                        "expected_value": 120,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Test auto-scaling mechanisms",
                "Validate traffic spike handling",
            ],
            "integration_notes": [
                "Combine with monitoring scenarios",
                "Use with auto-scaling testing",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://performance/endurance-testing")
async def get_endurance_testing_pack() -> dict[str, Any]:
    """Endurance testing scenarios for long-term stability validation."""
    return {
        "metadata": {
            "name": "Endurance Testing",
            "description": "Endurance testing scenarios for validating long-term system stability and resource management",
            "category": "performance",
            "pack_id": "endurance-testing",
            "version": RESOURCE_VERSION,
            "complexity": "high",
            "estimated_duration": "4-8 hours",
            "tags": ["performance", "endurance-testing", "stability", "memory-leaks"],
            "use_cases": [
                "Memory leak detection",
                "Long-term stability testing",
                "Resource management validation",
            ],
            "prerequisites": ["Long-term monitoring", "Resource tracking"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "extended_operation",
                "description": "Extended operation testing for memory leaks and stability",
                "scenario_type": "endurance_testing",
                "endpoints": [
                    {
                        "path": "/api/continuous-operation",
                        "method": "GET",
                        "response_config": {
                            "status_code": 200,
                            "response_time_ms": 200,
                            "response_data": {
                                "operation_id": "continuous_op",
                                "memory_usage": "stable",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 50,
                    "duration_seconds": 14400,
                    "ramp_up_time": 300,
                    "error_rate_threshold": 0.01,
                },
                "validation_rules": [
                    {
                        "rule_type": "memory_stability",
                        "condition": "memory_growth_rate",
                        "expected_value": 0.1,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": ["Detect memory leaks", "Test long-term stability"],
            "integration_notes": [
                "Requires extended monitoring",
                "Use with memory profiling",
            ],
        },
    }


# Security Testing Scenario Packs


@mcp_resource_audit("scenario-pack://security/auth-bypass")
async def get_auth_bypass_pack() -> dict[str, Any]:
    """Authentication bypass scenarios for security testing."""
    return {
        "metadata": {
            "name": "Authentication Bypass",
            "description": "Authentication bypass scenarios for testing security vulnerabilities and access controls",
            "category": "security",
            "pack_id": "auth-bypass",
            "version": RESOURCE_VERSION,
            "complexity": "high",
            "estimated_duration": "60-90 minutes",
            "tags": ["security", "authentication", "bypass", "access-control"],
            "use_cases": [
                "Authentication security testing",
                "Access control validation",
                "Security vulnerability assessment",
            ],
            "prerequisites": [
                "Security testing authorization",
                "Authentication system",
            ],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "token_manipulation",
                "description": "Test authentication bypass through token manipulation",
                "scenario_type": "security_testing",
                "endpoints": [
                    {
                        "path": "/api/secure-endpoint",
                        "method": "GET",
                        "response_config": {
                            "status_code": 401,
                            "response_time_ms": 100,
                            "response_data": {
                                "error": "Unauthorized",
                                "message": "Invalid or manipulated token",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 5,
                    "duration_seconds": 300,
                    "ramp_up_time": 60,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "security",
                        "condition": "bypass_attempt_blocked",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Test authentication security",
                "Validate access controls",
            ],
            "integration_notes": [
                "Requires security testing authorization",
                "Use with logging scenarios",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://security/injection-attacks")
async def get_injection_attacks_pack() -> dict[str, Any]:
    """SQL/NoSQL injection attack scenarios for security testing."""
    return {
        "metadata": {
            "name": "Injection Attacks",
            "description": "SQL/NoSQL injection attack scenarios for testing input validation and data security",
            "category": "security",
            "pack_id": "injection-attacks",
            "version": RESOURCE_VERSION,
            "complexity": "high",
            "estimated_duration": "60-90 minutes",
            "tags": ["security", "injection", "sql", "nosql", "input-validation"],
            "use_cases": [
                "Input validation testing",
                "Database security testing",
                "Injection vulnerability assessment",
            ],
            "prerequisites": ["Security testing authorization", "Database access"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "sql_injection_attempt",
                "description": "Test SQL injection protection mechanisms",
                "scenario_type": "security_testing",
                "endpoints": [
                    {
                        "path": "/api/search",
                        "method": "POST",
                        "response_config": {
                            "status_code": 400,
                            "response_time_ms": 150,
                            "response_data": {
                                "error": "Bad Request",
                                "message": "Invalid input detected",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 3,
                    "duration_seconds": 240,
                    "ramp_up_time": 60,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "security",
                        "condition": "injection_blocked",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Test input validation",
                "Validate injection protection",
            ],
            "integration_notes": [
                "Requires security testing authorization",
                "Use with input validation scenarios",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://security/xss-attacks")
async def get_xss_attacks_pack() -> dict[str, Any]:
    """Cross-site scripting attack scenarios for security testing."""
    return {
        "metadata": {
            "name": "XSS Attacks",
            "description": "Cross-site scripting attack scenarios for testing input sanitization and output encoding",
            "category": "security",
            "pack_id": "xss-attacks",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "45-60 minutes",
            "tags": ["security", "xss", "cross-site-scripting", "input-sanitization"],
            "use_cases": [
                "Input sanitization testing",
                "Output encoding validation",
                "XSS vulnerability assessment",
            ],
            "prerequisites": ["Security testing authorization", "Web application"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "script_injection_attempt",
                "description": "Test XSS protection through script injection attempts",
                "scenario_type": "security_testing",
                "endpoints": [
                    {
                        "path": "/api/user-content",
                        "method": "POST",
                        "response_config": {
                            "status_code": 400,
                            "response_time_ms": 120,
                            "response_data": {
                                "error": "Bad Request",
                                "message": "Malicious content detected",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 5,
                    "duration_seconds": 180,
                    "ramp_up_time": 30,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "security",
                        "condition": "xss_blocked",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": ["Test input sanitization", "Validate XSS protection"],
            "integration_notes": [
                "Requires security testing authorization",
                "Use with content validation scenarios",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://security/csrf-attacks")
async def get_csrf_attacks_pack() -> dict[str, Any]:
    """CSRF attack scenarios for security testing."""
    return {
        "metadata": {
            "name": "CSRF Attacks",
            "description": "Cross-Site Request Forgery attack scenarios for testing CSRF protection mechanisms",
            "category": "security",
            "pack_id": "csrf-attacks",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "45-60 minutes",
            "tags": [
                "security",
                "csrf",
                "cross-site-request-forgery",
                "token-validation",
            ],
            "use_cases": [
                "CSRF protection testing",
                "Token validation testing",
                "Session security testing",
            ],
            "prerequisites": [
                "Security testing authorization",
                "CSRF protection implementation",
            ],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "csrf_token_bypass",
                "description": "Test CSRF protection through token bypass attempts",
                "scenario_type": "security_testing",
                "endpoints": [
                    {
                        "path": "/api/sensitive-action",
                        "method": "POST",
                        "response_config": {
                            "status_code": 403,
                            "response_time_ms": 100,
                            "response_data": {
                                "error": "Forbidden",
                                "message": "CSRF token validation failed",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 3,
                    "duration_seconds": 180,
                    "ramp_up_time": 30,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "security",
                        "condition": "csrf_blocked",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": ["Test CSRF protection", "Validate token mechanisms"],
            "integration_notes": [
                "Requires security testing authorization",
                "Use with session management scenarios",
            ],
        },
    }


# Business Logic Scenario Packs


@mcp_resource_audit("scenario-pack://business/edge-cases")
async def get_edge_cases_pack() -> dict[str, Any]:
    """Edge case scenarios for business logic testing."""
    return {
        "metadata": {
            "name": "Edge Cases",
            "description": "Edge case scenarios for testing business logic boundaries and exceptional conditions",
            "category": "business",
            "pack_id": "edge-cases",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "45-60 minutes",
            "tags": ["business-logic", "edge-cases", "boundaries", "exceptions"],
            "use_cases": [
                "Business logic validation",
                "Boundary condition testing",
                "Exception handling testing",
            ],
            "prerequisites": ["Business logic implementation", "Error handling"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "boundary_value_testing",
                "description": "Test business logic with boundary values",
                "scenario_type": "functional_testing",
                "endpoints": [
                    {
                        "path": "/api/calculate",
                        "method": "POST",
                        "response_config": {
                            "status_code": 400,
                            "response_time_ms": 150,
                            "response_data": {
                                "error": "Bad Request",
                                "message": "Value exceeds maximum allowed limit",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 5,
                    "duration_seconds": 240,
                    "ramp_up_time": 40,
                    "error_rate_threshold": 0.8,
                },
                "validation_rules": [
                    {
                        "rule_type": "business_logic",
                        "condition": "boundary_validation",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": [
                "Test business logic boundaries",
                "Validate edge case handling",
            ],
            "integration_notes": [
                "Combine with validation scenarios",
                "Use with error handling testing",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://business/data-validation")
async def get_data_validation_pack() -> dict[str, Any]:
    """Data validation scenarios for business logic testing."""
    return {
        "metadata": {
            "name": "Data Validation",
            "description": "Data validation scenarios for testing input validation and business rule enforcement",
            "category": "business",
            "pack_id": "data-validation",
            "version": RESOURCE_VERSION,
            "complexity": "medium",
            "estimated_duration": "30-45 minutes",
            "tags": [
                "business-logic",
                "data-validation",
                "input-validation",
                "business-rules",
            ],
            "use_cases": [
                "Input validation testing",
                "Business rule enforcement",
                "Data integrity testing",
            ],
            "prerequisites": ["Validation rules implementation", "Business logic"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "invalid_data_rejection",
                "description": "Test rejection of invalid data according to business rules",
                "scenario_type": "functional_testing",
                "endpoints": [
                    {
                        "path": "/api/validate-data",
                        "method": "POST",
                        "response_config": {
                            "status_code": 422,
                            "response_time_ms": 120,
                            "response_data": {
                                "error": "Validation Failed",
                                "message": "Data does not meet business requirements",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 8,
                    "duration_seconds": 180,
                    "ramp_up_time": 30,
                    "error_rate_threshold": 1.0,
                },
                "validation_rules": [
                    {
                        "rule_type": "validation",
                        "condition": "invalid_data_rejected",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": ["Test input validation", "Validate business rules"],
            "integration_notes": [
                "Combine with edge case scenarios",
                "Use with business logic testing",
            ],
        },
    }


@mcp_resource_audit("scenario-pack://business/workflow-testing")
async def get_workflow_testing_pack() -> dict[str, Any]:
    """Business workflow testing scenarios."""
    return {
        "metadata": {
            "name": "Workflow Testing",
            "description": "Business workflow testing scenarios for validating complex business processes and state transitions",
            "category": "business",
            "pack_id": "workflow-testing",
            "version": RESOURCE_VERSION,
            "complexity": "high",
            "estimated_duration": "60-90 minutes",
            "tags": ["business-logic", "workflows", "state-transitions", "processes"],
            "use_cases": [
                "Business process validation",
                "State transition testing",
                "Workflow integrity testing",
            ],
            "prerequisites": ["Workflow implementation", "State management"],
            "last_updated": LAST_UPDATED,
        },
        "scenarios": [
            {
                "scenario_name": "multi_step_workflow",
                "description": "Test complex multi-step business workflow",
                "scenario_type": "functional_testing",
                "endpoints": [
                    {
                        "path": "/api/workflow/step1",
                        "method": "POST",
                        "response_config": {
                            "status_code": 200,
                            "response_time_ms": 200,
                            "response_data": {
                                "workflow_id": "wf_12345",
                                "current_step": "step1",
                                "status": "in_progress",
                            },
                            "headers": {"Content-Type": "application/json"},
                        },
                    }
                ],
                "test_parameters": {
                    "concurrent_users": 10,
                    "duration_seconds": 360,
                    "ramp_up_time": 60,
                    "error_rate_threshold": 0.05,
                },
                "validation_rules": [
                    {
                        "rule_type": "workflow",
                        "condition": "state_transitions_valid",
                        "expected_value": True,
                    }
                ],
            }
        ],
        "documentation": {
            "usage_examples": ["Test business workflows", "Validate state transitions"],
            "integration_notes": [
                "Combine with data validation scenarios",
                "Use with state management testing",
            ],
        },
    }


# Resource Discovery and Management Functions


async def list_scenario_packs(
    category: str | None = None,
    tags: list[str] | None = None,
    complexity: str | None = None,
) -> dict[str, Any]:
    """
    List available scenario packs with optional filtering.

    Args:
        category: Filter by category (errors, performance, security, business)
        tags: Filter by tags
        complexity: Filter by complexity level (low, medium, high)

    Returns:
        Filtered list of scenario packs with metadata
    """
    all_packs = []

    # Get all scenario pack functions
    pack_functions = {
        "scenario-pack://errors/4xx-client-errors": get_4xx_client_errors_pack,
        "scenario-pack://errors/5xx-server-errors": get_5xx_server_errors_pack,
        "scenario-pack://errors/network-timeouts": get_network_timeouts_pack,
        "scenario-pack://errors/rate-limiting": get_rate_limiting_pack,
        "scenario-pack://performance/load-testing": get_load_testing_pack,
        "scenario-pack://performance/stress-testing": get_stress_testing_pack,
        "scenario-pack://performance/spike-testing": get_spike_testing_pack,
        "scenario-pack://performance/endurance-testing": get_endurance_testing_pack,
        "scenario-pack://security/auth-bypass": get_auth_bypass_pack,
        "scenario-pack://security/injection-attacks": get_injection_attacks_pack,
        "scenario-pack://security/xss-attacks": get_xss_attacks_pack,
        "scenario-pack://security/csrf-attacks": get_csrf_attacks_pack,
        "scenario-pack://business/edge-cases": get_edge_cases_pack,
        "scenario-pack://business/data-validation": get_data_validation_pack,
        "scenario-pack://business/workflow-testing": get_workflow_testing_pack,
    }

    # Get metadata for each pack
    for uri, func in pack_functions.items():
        try:
            pack_data = await func()
            metadata = pack_data["metadata"]

            # Apply filters
            if category and metadata["category"] != category:
                continue
            if complexity and metadata["complexity"] != complexity:
                continue
            if tags and not any(tag in metadata["tags"] for tag in tags):
                continue

            all_packs.append(
                {
                    "uri": uri,
                    "name": metadata["name"],
                    "description": metadata["description"],
                    "category": metadata["category"],
                    "complexity": metadata["complexity"],
                    "estimated_duration": metadata["estimated_duration"],
                    "tags": metadata["tags"],
                    "use_cases": metadata["use_cases"],
                    "last_updated": metadata["last_updated"],
                }
            )
        except Exception as e:
            logger.warning(f"Failed to load metadata for {uri}: {e}")

    return {
        "total_packs": len(all_packs),
        "packs": all_packs,
        "categories": list(SCENARIO_PACK_CATEGORIES.keys()),
        "available_filters": {
            "categories": list(SCENARIO_PACK_CATEGORIES.keys()),
            "complexity_levels": ["low", "medium", "high"],
            "common_tags": ["errors", "performance", "security", "business-logic"],
        },
    }


async def get_scenario_pack_by_uri(uri: str) -> dict[str, Any]:
    """
    Get a specific scenario pack by URI.

    Args:
        uri: Scenario pack URI (e.g., "scenario-pack://errors/4xx-client-errors")

    Returns:
        Complete scenario pack data or error information
    """
    # Validate URI
    is_valid, category, pack_name, error_msg = _validate_resource_uri(uri)
    if not is_valid:
        return {"error": "Invalid URI", "message": error_msg, "uri": uri}

    # Map URIs to functions
    pack_functions = {
        "scenario-pack://errors/4xx-client-errors": get_4xx_client_errors_pack,
        "scenario-pack://errors/5xx-server-errors": get_5xx_server_errors_pack,
        "scenario-pack://errors/network-timeouts": get_network_timeouts_pack,
        "scenario-pack://errors/rate-limiting": get_rate_limiting_pack,
        "scenario-pack://performance/load-testing": get_load_testing_pack,
        "scenario-pack://performance/stress-testing": get_stress_testing_pack,
        "scenario-pack://performance/spike-testing": get_spike_testing_pack,
        "scenario-pack://performance/endurance-testing": get_endurance_testing_pack,
        "scenario-pack://security/auth-bypass": get_auth_bypass_pack,
        "scenario-pack://security/injection-attacks": get_injection_attacks_pack,
        "scenario-pack://security/xss-attacks": get_xss_attacks_pack,
        "scenario-pack://security/csrf-attacks": get_csrf_attacks_pack,
        "scenario-pack://business/edge-cases": get_edge_cases_pack,
        "scenario-pack://business/data-validation": get_data_validation_pack,
        "scenario-pack://business/workflow-testing": get_workflow_testing_pack,
    }

    func = pack_functions.get(uri)
    if not func:
        return {
            "error": "Pack not found",
            "message": f"No scenario pack found for URI: {uri}",
            "uri": uri,
        }

    try:
        return await func()
    except Exception as e:
        logger.exception(f"Error loading scenario pack {uri}")
        return {
            "error": "Load error",
            "message": f"Failed to load scenario pack: {e}",
            "uri": uri,
        }


# Resource validation functions


def validate_scenario_pack_content(pack_data: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate scenario pack content against MockLoop schema.

    Args:
        pack_data: Scenario pack data to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Check required top-level fields
    required_fields = ["metadata", "scenarios", "documentation"]
    for field in required_fields:
        if field not in pack_data:
            errors.append(f"Missing required field: {field}")

    # Validate metadata
    if "metadata" in pack_data:
        metadata = pack_data["metadata"]
        required_metadata = ["name", "description", "category", "pack_id", "version"]
        for field in required_metadata:
            if field not in metadata:
                errors.append(f"Missing required metadata field: {field}")

    # Validate scenarios
    if "scenarios" in pack_data:
        scenarios = pack_data["scenarios"]
        if not isinstance(scenarios, list):
            errors.append("Scenarios must be a list")
        else:
            for i, scenario in enumerate(scenarios):
                if not isinstance(scenario, dict):
                    errors.append(f"Scenario {i} must be a dictionary")
                    continue

                required_scenario_fields = [
                    "scenario_name",
                    "description",
                    "scenario_type",
                    "endpoints",
                ]
                for field in required_scenario_fields:
                    if field not in scenario:
                        errors.append(f"Scenario {i} missing required field: {field}")

    return len(errors) == 0, errors


def get_resource_integrity_info(pack_data: dict[str, Any]) -> dict[str, Any]:
    """
    Get integrity information for a resource.

    Args:
        pack_data: Scenario pack data

    Returns:
        Integrity information including hash and validation status
    """
    content_hash = _calculate_content_hash(pack_data)
    is_valid, errors = validate_scenario_pack_content(pack_data)

    return {
        "content_hash": content_hash,
        "is_valid": is_valid,
        "validation_errors": errors,
        "content_size": len(json.dumps(pack_data)),
        "last_validated": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
    }
