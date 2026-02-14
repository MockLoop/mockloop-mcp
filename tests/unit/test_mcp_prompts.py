# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Unit tests for MCP Prompts module.

Tests all prompt functions with various OpenAPI specifications,
validates JSON schema compliance, tests audit logging integration,
and tests error handling and edge cases.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from typing import Any

# Import the module under test
from src.mockloop_mcp.mcp_prompts import (
    analyze_openapi_for_testing,
    generate_scenario_config,
    optimize_scenario_for_load,
    generate_error_scenarios,
    generate_security_test_scenarios,
    validate_json_schema,
    SCENARIO_CONFIG_SCHEMA,
    OPENAPI_ANALYSIS_SCHEMA,
)


class TestMCPPrompts:
    """Test class for MCP Prompts functionality."""

    @pytest.fixture
    def sample_openapi_spec(self) -> dict[str, Any]:
        """Sample OpenAPI specification for testing."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0",
                "description": "A test API for unit testing",
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "responses": {"200": {"description": "Success"}},
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}},
                    },
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                            }
                        ],
                        "responses": {"200": {"description": "Success"}},
                    },
                    "put": {
                        "summary": "Update user",
                        "responses": {"200": {"description": "Updated"}},
                    },
                    "delete": {
                        "summary": "Delete user",
                        "responses": {"204": {"description": "Deleted"}},
                    },
                },
                "/auth/login": {
                    "post": {
                        "summary": "User login",
                        "responses": {"200": {"description": "Login successful"}},
                    }
                },
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "email": {"type": "string"},
                        },
                    }
                },
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                    }
                },
            },
            "security": [{"bearerAuth": []}],
        }

    @pytest.fixture
    def sample_endpoints(self) -> list[dict[str, Any]]:
        """Sample endpoints for testing scenario generation."""
        return [
            {"path": "/users", "method": "GET"},
            {"path": "/users", "method": "POST"},
            {"path": "/users/{id}", "method": "GET"},
        ]

    @pytest.fixture
    def sample_scenario_config(self) -> dict[str, Any]:
        """Sample scenario configuration for testing."""
        return {
            "scenario_name": "test_scenario",
            "description": "Test scenario for unit testing",
            "scenario_type": "functional_testing",
            "endpoints": [
                {
                    "path": "/users",
                    "method": "GET",
                    "response_config": {
                        "status_code": 200,
                        "response_time_ms": 100,
                        "response_data": {"users": []},
                        "headers": {"Content-Type": "application/json"},
                    },
                }
            ],
            "test_parameters": {
                "concurrent_users": 10,
                "duration_seconds": 120,
                "ramp_up_time": 20,
                "error_rate_threshold": 0.1,
            },
            "validation_rules": [],
        }

    @pytest.mark.asyncio
    async def test_analyze_openapi_for_testing_comprehensive(self, sample_openapi_spec):
        """Test comprehensive OpenAPI analysis."""
        result = await analyze_openapi_for_testing(
            openapi_spec=sample_openapi_spec,
            testing_focus="comprehensive",
            risk_assessment=True,
        )

        # Validate structure
        assert isinstance(result, dict)
        assert "api_summary" in result
        assert "testable_scenarios" in result
        assert "risk_areas" in result

        # Validate API summary
        api_summary = result["api_summary"]
        assert api_summary["title"] == "Test API"
        assert api_summary["version"] == "1.0.0"
        assert api_summary["total_endpoints"] == 3
        assert len(api_summary["authentication_methods"]) > 0
        assert "User" in api_summary["data_models"]

        # Validate testable scenarios
        scenarios = result["testable_scenarios"]
        assert isinstance(scenarios, list)
        assert len(scenarios) > 0

        # Check for different scenario types
        scenario_types = [s["scenario_type"] for s in scenarios]
        assert any("crud" in st for st in scenario_types)

        # Validate risk areas
        risk_areas = result["risk_areas"]
        assert isinstance(risk_areas, list)

        # Validate schema compliance
        is_valid, error = validate_json_schema(result, OPENAPI_ANALYSIS_SCHEMA)
        assert is_valid, f"Schema validation failed: {error}"

    @pytest.mark.asyncio
    async def test_analyze_openapi_for_testing_security_focus(
        self, sample_openapi_spec
    ):
        """Test OpenAPI analysis with security focus."""
        result = await analyze_openapi_for_testing(
            openapi_spec=sample_openapi_spec,
            testing_focus="security",
            risk_assessment=True,
        )

        # Should contain security-focused scenarios
        scenarios = result["testable_scenarios"]
        scenario_types = [s["scenario_type"] for s in scenarios]
        assert any("security" in st or "authentication" in st for st in scenario_types)

    @pytest.mark.asyncio
    async def test_analyze_openapi_for_testing_error_handling(self):
        """Test OpenAPI analysis error handling."""
        # Test with invalid spec
        invalid_spec = {"invalid": "spec"}

        result = await analyze_openapi_for_testing(
            openapi_spec=invalid_spec,
            testing_focus="comprehensive",
            risk_assessment=True,
        )

        # Should return valid structure even on error
        assert isinstance(result, dict)
        assert "api_summary" in result
        assert "testable_scenarios" in result
        assert "risk_areas" in result

        # Should indicate error in the response
        assert result["api_summary"]["title"] == "Unknown API"

    @pytest.mark.asyncio
    async def test_generate_scenario_config_functional(self, sample_endpoints):
        """Test functional scenario configuration generation."""
        result = await generate_scenario_config(
            scenario_type="functional_testing",
            endpoints=sample_endpoints,
            test_parameters=None,
            scenario_name="test_functional_scenario",
        )

        # Validate structure
        assert isinstance(result, dict)
        assert result["scenario_name"] == "test_functional_scenario"
        assert result["scenario_type"] == "functional_testing"
        assert "description" in result
        assert "endpoints" in result
        assert "test_parameters" in result
        assert "validation_rules" in result

        # Validate endpoints
        endpoints = result["endpoints"]
        assert len(endpoints) == len(sample_endpoints)
        for endpoint in endpoints:
            assert "path" in endpoint
            assert "method" in endpoint
            assert "response_config" in endpoint
            assert "status_code" in endpoint["response_config"]

        # Validate schema compliance
        is_valid, error = validate_json_schema(result, SCENARIO_CONFIG_SCHEMA)
        assert is_valid, f"Schema validation failed: {error}"

    @pytest.mark.asyncio
    async def test_generate_scenario_config_load_testing(self, sample_endpoints):
        """Test load testing scenario configuration generation."""
        custom_params = {
            "concurrent_users": 100,
            "duration_seconds": 300,
            "ramp_up_time": 60,
            "error_rate_threshold": 0.05,
        }

        result = await generate_scenario_config(
            scenario_type="load_testing",
            endpoints=sample_endpoints,
            test_parameters=custom_params,
            scenario_name=None,  # Should auto-generate
        )

        # Should auto-generate name
        assert "load_testing" in result["scenario_name"]
        assert result["scenario_type"] == "load_testing"
        assert result["test_parameters"] == custom_params

        # Load testing should have optimized response times
        for endpoint in result["endpoints"]:
            response_time = endpoint["response_config"]["response_time_ms"]
            assert response_time <= 100  # Should be optimized for load testing

    @pytest.mark.asyncio
    async def test_generate_scenario_config_error_handling(self):
        """Test scenario config generation error handling."""
        # Test with empty endpoints
        result = await generate_scenario_config(
            scenario_type="functional_testing",
            endpoints=[],
            test_parameters=None,
            scenario_name="error_test",
        )

        # Should return valid minimal configuration
        assert result["scenario_name"] == "error_test"
        assert len(result["endpoints"]) == 0  # Should have empty endpoints on error

    @pytest.mark.asyncio
    async def test_optimize_scenario_for_load(self, sample_scenario_config):
        """Test scenario optimization for load testing."""
        target_load = 500
        performance_requirements = {
            "max_response_time_ms": 1000,
            "target_throughput_rps": 1000,
            "error_rate_threshold": 0.01,
        }

        result = await optimize_scenario_for_load(
            base_scenario=sample_scenario_config,
            target_load=target_load,
            performance_requirements=performance_requirements,
        )

        # Validate optimization
        assert result["scenario_type"] == "load_testing"
        assert "load_optimized" in result["scenario_name"]
        assert result["test_parameters"]["concurrent_users"] == target_load
        assert (
            result["test_parameters"]["duration_seconds"] >= 300
        )  # Should scale with load
        assert result["test_parameters"]["error_rate_threshold"] == 0.01

        # Validate load-specific validation rules
        validation_rules = result["validation_rules"]
        rule_types = [rule["rule_type"] for rule in validation_rules]
        assert "response_time" in rule_types
        assert "throughput" in rule_types
        assert "error_rate" in rule_types

        # Validate schema compliance
        is_valid, error = validate_json_schema(result, SCENARIO_CONFIG_SCHEMA)
        assert is_valid, f"Schema validation failed: {error}"

    @pytest.mark.asyncio
    async def test_optimize_scenario_for_load_error_handling(self):
        """Test load optimization error handling."""
        # Test with invalid base scenario
        invalid_scenario = {"invalid": "scenario"}

        result = await optimize_scenario_for_load(
            base_scenario=invalid_scenario,
            target_load=100,
            performance_requirements=None,
        )

        # Should return the base scenario with minimal optimizations
        assert result["test_parameters"]["concurrent_users"] == 100

    @pytest.mark.asyncio
    async def test_generate_error_scenarios(self, sample_endpoints):
        """Test error scenario generation."""
        result = await generate_error_scenarios(
            api_endpoints=sample_endpoints,
            error_types=["timeout", "server_error", "rate_limit"],
            severity_level="medium",
        )

        # Validate structure
        assert isinstance(result, dict)
        assert result["scenario_type"] == "error_simulation"
        assert "error_simulation" in result["scenario_name"]
        assert "medium" in result["description"]

        # Should have error endpoints for each combination
        endpoints = result["endpoints"]
        assert len(endpoints) == len(sample_endpoints) * 3  # 3 error types

        # Validate error configurations
        for endpoint in endpoints:
            status_code = endpoint["response_config"]["status_code"]
            assert status_code >= 400  # Should be error status codes
            assert "error" in endpoint["response_config"]["response_data"]

        # Error scenarios should expect high error rates
        assert result["test_parameters"]["error_rate_threshold"] == 1.0

        # Validate schema compliance
        is_valid, error = validate_json_schema(result, SCENARIO_CONFIG_SCHEMA)
        assert is_valid, f"Schema validation failed: {error}"

    @pytest.mark.asyncio
    async def test_generate_error_scenarios_high_severity(self, sample_endpoints):
        """Test high severity error scenario generation."""
        result = await generate_error_scenarios(
            api_endpoints=sample_endpoints,
            error_types=None,  # Should use defaults
            severity_level="high",
        )

        # High severity should have more error types
        endpoints = result["endpoints"]
        assert len(endpoints) > len(sample_endpoints) * 3  # More than 3 error types

        # Should include severe errors like database_error
        error_paths = [ep["path"] for ep in endpoints]
        assert any("database" in path.lower() for path in error_paths)

    @pytest.mark.asyncio
    async def test_generate_security_test_scenarios(self, sample_openapi_spec):
        """Test security scenario generation."""
        security_focus = ["authentication", "authorization", "input_validation"]
        compliance_requirements = ["OWASP", "GDPR"]

        result = await generate_security_test_scenarios(
            api_spec=sample_openapi_spec,
            security_focus=security_focus,
            compliance_requirements=compliance_requirements,
        )

        # Validate structure
        assert isinstance(result, dict)
        assert result["scenario_type"] == "security_testing"
        assert "security_test" in result["scenario_name"]

        # Should have security test endpoints
        endpoints = result["endpoints"]
        assert len(endpoints) >= len(security_focus)

        # Validate security-specific configurations
        for endpoint in endpoints:
            status_code = endpoint["response_config"]["status_code"]
            assert status_code in [401, 403, 422, 429]  # Security-related status codes

        # Should have compliance validation rules
        validation_rules = result["validation_rules"]
        compliance_rules = [
            rule for rule in validation_rules if rule["rule_type"] == "compliance"
        ]
        assert len(compliance_rules) == len(compliance_requirements)

        # Security scenarios should expect high error rates
        assert result["test_parameters"]["error_rate_threshold"] >= 0.8

        # Validate schema compliance
        is_valid, error = validate_json_schema(result, SCENARIO_CONFIG_SCHEMA)
        assert is_valid, f"Schema validation failed: {error}"

    @pytest.mark.asyncio
    async def test_generate_security_test_scenarios_default_focus(
        self, sample_openapi_spec
    ):
        """Test security scenario generation with default focus areas."""
        result = await generate_security_test_scenarios(
            api_spec=sample_openapi_spec,
            security_focus=None,  # Should use defaults
            compliance_requirements=None,
        )

        # Should use default security focus areas
        endpoints = result["endpoints"]
        assert len(endpoints) >= 5  # Default has 5 focus areas

        # Should have default validation rules
        validation_rules = result["validation_rules"]
        security_rules = [
            rule for rule in validation_rules if rule["rule_type"] == "security"
        ]
        assert len(security_rules) >= 5

    def test_validate_json_schema_valid(self):
        """Test JSON schema validation with valid data."""
        valid_data = {
            "scenario_name": "test",
            "description": "test description",
            "scenario_type": "functional_testing",
            "endpoints": [
                {
                    "path": "/test",
                    "method": "GET",
                    "response_config": {"status_code": 200},
                }
            ],
        }

        is_valid, error = validate_json_schema(valid_data, SCENARIO_CONFIG_SCHEMA)
        assert is_valid
        assert error is None

    def test_validate_json_schema_invalid(self):
        """Test JSON schema validation with invalid data."""
        invalid_data = {
            "scenario_name": "test",
            # Missing required fields
        }

        is_valid, error = validate_json_schema(invalid_data, SCENARIO_CONFIG_SCHEMA)
        assert not is_valid
        assert error is not None
        assert "required" in error.lower()

    @patch("src.mockloop_mcp.mcp_prompts.create_audit_logger")
    @pytest.mark.asyncio
    async def test_audit_logging_integration(
        self, mock_create_audit_logger, sample_openapi_spec
    ):
        """Test that audit logging is properly integrated."""
        # Mock the audit logger
        mock_audit_logger = Mock()
        mock_audit_logger.log_prompt_invocation = Mock(return_value="test_entry_id")
        mock_create_audit_logger.return_value = mock_audit_logger

        # Call a prompt function
        await analyze_openapi_for_testing(
            openapi_spec=sample_openapi_spec,
            testing_focus="comprehensive",
            risk_assessment=True,
        )

        # Verify audit logging was called
        assert (
            mock_audit_logger.log_prompt_invocation.call_count >= 2
        )  # Start and completion

        # Verify the calls include proper parameters
        calls = mock_audit_logger.log_prompt_invocation.call_args_list
        start_call = calls[0]
        assert "analyze_openapi_for_testing" in start_call[1]["prompt_name"]
        assert "ai_generation" in start_call[1]["compliance_tags"]

    @pytest.mark.asyncio
    async def test_concurrent_prompt_execution(
        self, sample_openapi_spec, sample_endpoints
    ):
        """Test that multiple prompts can be executed concurrently."""
        # Execute multiple prompts concurrently
        tasks = [
            analyze_openapi_for_testing(sample_openapi_spec, "functional"),
            generate_scenario_config("load_testing", sample_endpoints),
            generate_error_scenarios(sample_endpoints, ["timeout"], "low"),
        ]

        results = await asyncio.gather(*tasks)

        # All should complete successfully
        assert len(results) == 3
        for result in results:
            assert isinstance(result, dict)
            assert "scenario_name" in result or "api_summary" in result

    @pytest.mark.asyncio
    async def test_prompt_performance(self, sample_openapi_spec):
        """Test that prompts execute within reasonable time limits."""
        import time

        start_time = time.time()
        result = await analyze_openapi_for_testing(
            openapi_spec=sample_openapi_spec,
            testing_focus="comprehensive",
            risk_assessment=True,
        )
        end_time = time.time()

        # Should complete within 5 seconds
        execution_time = end_time - start_time
        assert execution_time < 5.0, f"Prompt took too long: {execution_time}s"

        # Should still return valid result
        assert isinstance(result, dict)
        assert "api_summary" in result


if __name__ == "__main__":
    pytest.main([__file__])
