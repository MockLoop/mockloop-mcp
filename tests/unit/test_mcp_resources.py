# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Unit tests for MCP Resources module.

Tests the built-in scenario pack resources, resource discovery functionality,
content validation, and audit logging integration.
"""

import pytest
from unittest.mock import Mock, patch

# Handle imports for different execution contexts
try:
    from src.mockloop_mcp.mcp_resources import (
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
        get_scenario_pack_by_uri,
        validate_scenario_pack_content,
        get_resource_integrity_info,
        _validate_resource_uri,
        _calculate_content_hash,
        SCENARIO_PACK_CATEGORIES,
    )
    from src.mockloop_mcp.community_scenarios import (
        list_community_scenarios,
        get_community_scenario,
        refresh_community_cache,
        search_community_scenarios,
        validate_community_scenario,
        get_community_stats,
        get_community_architecture_info,
        CommunityScenarioManager,
        COMMUNITY_CATEGORIES,
    )
except ImportError:
    # Fallback for direct execution
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

    from mockloop_mcp.mcp_resources import (
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
        get_scenario_pack_by_uri,
        validate_scenario_pack_content,
        get_resource_integrity_info,
        _validate_resource_uri,
        _calculate_content_hash,
        SCENARIO_PACK_CATEGORIES,
    )
    from mockloop_mcp.community_scenarios import (
        list_community_scenarios,
        get_community_scenario,
        refresh_community_cache,
        search_community_scenarios,
        validate_community_scenario,
        get_community_stats,
        get_community_architecture_info,
        CommunityScenarioManager,
        COMMUNITY_CATEGORIES,
    )


class TestMCPResources:
    """Test suite for MCP Resources functionality."""

    @pytest.mark.asyncio
    async def test_4xx_client_errors_pack(self):
        """Test 4xx client errors scenario pack."""
        pack = await get_4xx_client_errors_pack()

        # Validate structure
        assert "metadata" in pack
        assert "scenarios" in pack
        assert "documentation" in pack

        # Validate metadata
        metadata = pack["metadata"]
        assert metadata["name"] == "4xx Client Errors"
        assert metadata["category"] == "errors"
        assert metadata["pack_id"] == "4xx-client-errors"
        assert "4xx" in metadata["tags"]

        # Validate scenarios
        scenarios = pack["scenarios"]
        assert len(scenarios) > 0

        for scenario in scenarios:
            assert "scenario_name" in scenario
            assert "description" in scenario
            assert "scenario_type" in scenario
            assert "endpoints" in scenario
            assert "test_parameters" in scenario
            assert "validation_rules" in scenario

    @pytest.mark.asyncio
    async def test_5xx_server_errors_pack(self):
        """Test 5xx server errors scenario pack."""
        pack = await get_5xx_server_errors_pack()

        assert pack["metadata"]["name"] == "5xx Server Errors"
        assert pack["metadata"]["category"] == "errors"
        assert "5xx" in pack["metadata"]["tags"]
        assert "resilience" in pack["metadata"]["tags"]

    @pytest.mark.asyncio
    async def test_load_testing_pack(self):
        """Test load testing scenario pack."""
        pack = await get_load_testing_pack()

        assert pack["metadata"]["name"] == "Load Testing"
        assert pack["metadata"]["category"] == "performance"
        assert "load-testing" in pack["metadata"]["tags"]
        assert pack["metadata"]["complexity"] == "high"

    @pytest.mark.asyncio
    async def test_auth_bypass_pack(self):
        """Test authentication bypass scenario pack."""
        pack = await get_auth_bypass_pack()

        assert pack["metadata"]["name"] == "Authentication Bypass"
        assert pack["metadata"]["category"] == "security"
        assert "authentication" in pack["metadata"]["tags"]
        assert "bypass" in pack["metadata"]["tags"]

    @pytest.mark.asyncio
    async def test_edge_cases_pack(self):
        """Test edge cases scenario pack."""
        pack = await get_edge_cases_pack()

        assert pack["metadata"]["name"] == "Edge Cases"
        assert pack["metadata"]["category"] == "business"
        assert "edge-cases" in pack["metadata"]["tags"]
        assert "boundaries" in pack["metadata"]["tags"]

    @pytest.mark.asyncio
    async def test_list_scenario_packs_no_filters(self):
        """Test listing all scenario packs without filters."""
        result = await list_scenario_packs()

        assert "total_packs" in result
        assert "packs" in result
        assert "categories" in result
        assert "available_filters" in result

        # Should have all 15 built-in packs
        assert result["total_packs"] == 15
        assert len(result["packs"]) == 15

        # Check categories
        expected_categories = ["errors", "performance", "security", "business"]
        assert set(result["categories"]) == set(expected_categories)

    @pytest.mark.asyncio
    async def test_list_scenario_packs_with_category_filter(self):
        """Test listing scenario packs with category filter."""
        result = await list_scenario_packs(category="errors")

        assert result["total_packs"] == 4  # 4 error scenario packs

        for pack in result["packs"]:
            assert pack["category"] == "errors"

    @pytest.mark.asyncio
    async def test_list_scenario_packs_with_complexity_filter(self):
        """Test listing scenario packs with complexity filter."""
        result = await list_scenario_packs(complexity="high")

        for pack in result["packs"]:
            assert pack["complexity"] == "high"

    @pytest.mark.asyncio
    async def test_list_scenario_packs_with_tags_filter(self):
        """Test listing scenario packs with tags filter."""
        result = await list_scenario_packs(tags=["performance"])

        for pack in result["packs"]:
            assert any("performance" in tag for tag in pack["tags"])

    @pytest.mark.asyncio
    async def test_get_scenario_pack_by_uri_valid(self):
        """Test getting scenario pack by valid URI."""
        uri = "scenario-pack://errors/4xx-client-errors"
        pack = await get_scenario_pack_by_uri(uri)

        assert "error" not in pack
        assert pack["metadata"]["pack_id"] == "4xx-client-errors"

    @pytest.mark.asyncio
    async def test_get_scenario_pack_by_uri_invalid(self):
        """Test getting scenario pack by invalid URI."""
        uri = "invalid://uri/format"
        result = await get_scenario_pack_by_uri(uri)

        assert "error" in result
        assert result["error"] == "Invalid URI"

    @pytest.mark.asyncio
    async def test_get_scenario_pack_by_uri_not_found(self):
        """Test getting scenario pack by non-existent URI."""
        uri = "scenario-pack://errors/non-existent-pack"
        result = await get_scenario_pack_by_uri(uri)

        assert "error" in result
        assert "Unknown pack" in result["message"]

    def test_validate_resource_uri_valid(self):
        """Test URI validation with valid URIs."""
        valid_uris = [
            "scenario-pack://errors/4xx-client-errors",
            "scenario-pack://performance/load-testing",
            "scenario-pack://security/auth-bypass",
            "scenario-pack://business/edge-cases",
        ]

        for uri in valid_uris:
            is_valid, category, pack_name, error = _validate_resource_uri(uri)
            assert is_valid
            assert category in SCENARIO_PACK_CATEGORIES
            assert pack_name in SCENARIO_PACK_CATEGORIES[category]
            assert error == ""

    def test_validate_resource_uri_invalid(self):
        """Test URI validation with invalid URIs."""
        invalid_uris = [
            "http://invalid/scheme",
            "scenario-pack://invalid-category/pack",
            "scenario-pack://errors/invalid-pack",
            "scenario-pack://errors",
            "scenario-pack://errors/pack/extra",
        ]

        for uri in invalid_uris:
            is_valid, category, pack_name, error = _validate_resource_uri(uri)
            assert not is_valid
            assert error != ""

    def test_calculate_content_hash(self):
        """Test content hash calculation."""
        content1 = {"test": "data", "number": 123}
        content2 = {"number": 123, "test": "data"}  # Same content, different order
        content3 = {"test": "different", "number": 123}

        hash1 = _calculate_content_hash(content1)
        hash2 = _calculate_content_hash(content2)
        hash3 = _calculate_content_hash(content3)

        # Same content should produce same hash regardless of order
        assert hash1 == hash2
        # Different content should produce different hash
        assert hash1 != hash3
        # Hash should be a valid SHA-256 hex string
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)

    @pytest.mark.asyncio
    async def test_validate_scenario_pack_content_valid(self):
        """Test scenario pack content validation with valid content."""
        pack = await get_4xx_client_errors_pack()
        is_valid, errors = validate_scenario_pack_content(pack)

        assert is_valid
        assert len(errors) == 0

    def test_validate_scenario_pack_content_invalid(self):
        """Test scenario pack content validation with invalid content."""
        invalid_pack = {
            "metadata": {
                "name": "Test Pack"
                # Missing required fields
            },
            "scenarios": "not_a_list",  # Should be a list
            # Missing documentation
        }

        is_valid, errors = validate_scenario_pack_content(invalid_pack)

        assert not is_valid
        assert len(errors) > 0
        assert any("Missing required field" in error for error in errors)

    @pytest.mark.asyncio
    async def test_get_resource_integrity_info(self):
        """Test resource integrity information generation."""
        pack = await get_4xx_client_errors_pack()
        integrity_info = get_resource_integrity_info(pack)

        assert "content_hash" in integrity_info
        assert "is_valid" in integrity_info
        assert "validation_errors" in integrity_info
        assert "content_size" in integrity_info
        assert "last_validated" in integrity_info

        assert integrity_info["is_valid"] is True
        assert len(integrity_info["validation_errors"]) == 0
        assert integrity_info["content_size"] > 0

    @pytest.mark.asyncio
    async def test_all_scenario_pack_functions(self):
        """Test that all scenario pack functions return valid content."""
        pack_functions = [
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
        ]

        for func in pack_functions:
            pack = await func()

            # Validate basic structure
            assert "metadata" in pack
            assert "scenarios" in pack
            assert "documentation" in pack

            # Validate content
            is_valid, errors = validate_scenario_pack_content(pack)
            assert is_valid, f"Pack {func.__name__} failed validation: {errors}"


class TestCommunityScenarios:
    """Test suite for Community Scenarios placeholder functionality."""

    @pytest.mark.asyncio
    async def test_list_community_scenarios(self):
        """Test listing community scenarios (placeholder)."""
        result = await list_community_scenarios()

        assert result["status"] == "placeholder"
        assert result["total_scenarios"] == 0
        assert "phase_2_features" in result
        assert "placeholder_note" in result

    @pytest.mark.asyncio
    async def test_list_community_scenarios_with_filters(self):
        """Test listing community scenarios with filters (placeholder)."""
        result = await list_community_scenarios(
            category="technology",
            technology="graphql",
            tags=["api", "testing"],
            min_rating=4.0,
            max_age_days=30,
        )

        assert result["status"] == "placeholder"
        assert "categories" in result
        assert "technologies" in result

    @pytest.mark.asyncio
    async def test_get_community_scenario(self):
        """Test getting community scenario (placeholder)."""
        result = await get_community_scenario("test-scenario-id")

        assert result["status"] == "placeholder"
        assert result["scenario_id"] == "test-scenario-id"
        assert "phase_2_features" in result

    @pytest.mark.asyncio
    async def test_get_community_scenario_with_version(self):
        """Test getting community scenario with version (placeholder)."""
        result = await get_community_scenario(
            "test-scenario-id",
            version="1.2.0",
            include_metadata=True,
            validate_integrity=True,
        )

        assert result["status"] == "placeholder"
        assert result["requested_version"] == "1.2.0"

    @pytest.mark.asyncio
    async def test_refresh_community_cache(self):
        """Test refreshing community cache (placeholder)."""
        result = await refresh_community_cache()

        assert result["status"] == "placeholder"
        assert result["cache_status"] == "not_implemented"
        assert result["scenarios_cached"] == 0

    @pytest.mark.asyncio
    async def test_refresh_community_cache_with_options(self):
        """Test refreshing community cache with options (placeholder)."""
        result = await refresh_community_cache(
            force_refresh=True, categories=["technology", "industry"], max_age_hours=48
        )

        assert result["status"] == "placeholder"
        assert "phase_2_features" in result

    @pytest.mark.asyncio
    async def test_search_community_scenarios(self):
        """Test searching community scenarios (placeholder)."""
        result = await search_community_scenarios("graphql testing")

        assert result["status"] == "placeholder"
        assert result["query"] == "graphql testing"
        assert result["total_results"] == 0

    @pytest.mark.asyncio
    async def test_search_community_scenarios_with_options(self):
        """Test searching community scenarios with options (placeholder)."""
        result = await search_community_scenarios(
            "api testing",
            search_fields=["title", "description", "tags"],
            filters={"category": "technology", "min_rating": 4.0},
            sort_by="rating",
            limit=50,
            offset=10,
        )

        assert result["status"] == "placeholder"
        assert "phase_2_features" in result

    @pytest.mark.asyncio
    async def test_validate_community_scenario(self):
        """Test validating community scenario (placeholder)."""
        test_scenario = {
            "scenario_name": "test_scenario",
            "description": "Test scenario",
            "scenario_type": "functional_testing",
        }

        result = await validate_community_scenario(test_scenario)

        assert result["status"] == "placeholder"
        assert result["is_valid"] is False
        assert "phase_2_features" in result

    @pytest.mark.asyncio
    async def test_validate_community_scenario_with_options(self):
        """Test validating community scenario with options (placeholder)."""
        test_scenario = {"test": "data"}

        result = await validate_community_scenario(
            test_scenario,
            security_scan=True,
            schema_validation=True,
            content_analysis=True,
        )

        assert result["status"] == "placeholder"
        assert "security_score" in result
        assert "quality_score" in result

    @pytest.mark.asyncio
    async def test_get_community_stats(self):
        """Test getting community statistics (placeholder)."""
        result = await get_community_stats()

        assert result["status"] == "placeholder"
        assert result["total_scenarios"] == 0
        assert result["total_contributors"] == 0
        assert "categories" in result
        assert "quality_metrics" in result

    def test_get_community_architecture_info(self):
        """Test getting community architecture information."""
        result = get_community_architecture_info()

        assert "architecture" in result
        assert "current_status" in result
        assert "implementation_timeline" in result
        assert "technical_requirements" in result
        assert result["current_status"] == "placeholder_implementation"

    def test_community_scenario_manager_init(self):
        """Test CommunityScenarioManager initialization."""
        manager = CommunityScenarioManager()

        assert manager.config is not None
        assert "repository_url" in manager.config
        assert "cache_directory" in manager.config

    def test_community_scenario_manager_with_config(self):
        """Test CommunityScenarioManager with custom config."""
        custom_config = {
            "repository_url": "https://github.com/custom/repo",
            "cache_directory": "/custom/cache",
            "cache_ttl_hours": 48,
        }

        manager = CommunityScenarioManager(custom_config)

        assert manager.config["repository_url"] == custom_config["repository_url"]
        assert manager.config["cache_directory"] == custom_config["cache_directory"]
        assert manager.config["cache_ttl_hours"] == custom_config["cache_ttl_hours"]

    def test_community_categories_structure(self):
        """Test community categories structure."""
        assert "industry" in COMMUNITY_CATEGORIES
        assert "technology" in COMMUNITY_CATEGORIES
        assert "compliance" in COMMUNITY_CATEGORIES
        assert "advanced" in COMMUNITY_CATEGORIES

        # Check some specific categories
        assert "fintech" in COMMUNITY_CATEGORIES["industry"]
        assert "graphql" in COMMUNITY_CATEGORIES["technology"]
        assert "gdpr" in COMMUNITY_CATEGORIES["compliance"]
        assert "chaos-engineering" in COMMUNITY_CATEGORIES["advanced"]


class TestResourceAuditLogging:
    """Test suite for resource audit logging functionality."""

    @patch("src.mockloop_mcp.mcp_resources.create_audit_logger")
    @pytest.mark.asyncio
    async def test_resource_audit_logging(self, mock_create_audit_logger):
        """Test that resource access is properly audited."""
        mock_logger = Mock()
        mock_create_audit_logger.return_value = mock_logger

        # Test resource access
        await get_4xx_client_errors_pack()

        # Verify audit logger was created and used
        mock_create_audit_logger.assert_called()
        mock_logger.log_resource_access.assert_called()

    @patch("src.mockloop_mcp.community_scenarios.create_audit_logger")
    @pytest.mark.asyncio
    async def test_community_audit_logging(self, mock_create_audit_logger):
        """Test that community scenario access is properly audited."""
        mock_logger = Mock()
        mock_create_audit_logger.return_value = mock_logger

        # Test community scenario access
        await list_community_scenarios()

        # Verify audit logging was attempted
        mock_create_audit_logger.assert_called()


if __name__ == "__main__":
    # Run tests directly
    pytest.main([__file__, "-v"])
