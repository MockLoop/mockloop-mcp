"""
Integration tests for SchemaPin integration with MockLoop MCP.

Tests the complete SchemaPin workflow including:
- End-to-end verification scenarios
- Integration with MockLoop MCP tools
- Database persistence
- Policy enforcement workflows
- Real-world usage patterns
"""

import asyncio
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.mockloop_mcp.schemapin import (
    KeyPinningManager,
    PolicyAction,
    PolicyHandler,
    SchemaPinAuditLogger,
    SchemaPinConfig,
    SchemaVerificationInterceptor,
    VerificationResult,
)


class TestSchemaPinEndToEndWorkflow(unittest.TestCase):
    """Test complete SchemaPin verification workflows."""

    def setUp(self):
        """Set up test environment."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            self.temp_db_name = temp_db.name

        self.config = SchemaPinConfig(
            key_pin_storage_path=self.temp_db_name,
            policy_mode="warn",
            auto_pin_keys=False,
            trusted_domains=["trusted.example.com"],
            interactive_mode=False
        )

        self.interceptor = SchemaVerificationInterceptor(self.config)
        self.key_manager = KeyPinningManager(self.temp_db_name)
        self.policy_handler = PolicyHandler(self.config)
        self.audit_logger = SchemaPinAuditLogger(self.temp_db_name)

    def tearDown(self):
        """Clean up test environment."""
        Path(self.temp_db_name).unlink(missing_ok=True)

    async def test_first_time_tool_verification_trusted_domain(self):
        """Test TOFU scenario with trusted domain."""
        tool_name = "database_query"
        domain = "trusted.example.com"
        schema = {
            "name": "database_query",
            "description": "Query database with SQL",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "database": {"type": "string"}
                },
                "required": ["query"]
            }
        }
        signature = "mock_signature_for_testing"

        # Mock key discovery to return a public key
        with patch.object(self.key_manager, 'discover_public_key') as mock_discovery:
            mock_discovery.return_value = "-----BEGIN PUBLIC KEY-----\nmock_key\n-----END PUBLIC KEY-----"

            # Mock signature verification to succeed
            with patch.object(self.interceptor, '_verify_signature', return_value=True):
                result = await self.interceptor.verify_tool_schema(
                    tool_name, schema, signature, domain
                )

        # Should succeed and auto-pin for trusted domain
        assert result.valid is True
        assert result.domain == domain
        assert result.key_pinned is True

        # Verify key was pinned
        tool_id = f"{domain}/{tool_name}"
        pinned_key = self.key_manager.get_pinned_key(tool_id)
        assert pinned_key is not None

    async def test_subsequent_verification_with_pinned_key(self):
        """Test verification with already pinned key."""
        tool_name = "file_operations"
        domain = "example.com"
        tool_id = f"{domain}/{tool_name}"
        public_key = "-----BEGIN PUBLIC KEY-----\ntest_key\n-----END PUBLIC KEY-----"

        # Pin key first
        self.key_manager.pin_key(tool_id, domain, public_key)

        schema = {
            "name": "file_operations",
            "description": "File system operations",
            "parameters": {"type": "object"}
        }
        signature = "test_signature"

        # Mock signature verification to succeed
        with patch.object(self.interceptor, '_verify_signature', return_value=True):
            result = await self.interceptor.verify_tool_schema(
                tool_name, schema, signature, domain
            )

        assert result.valid is True
        assert result.key_pinned is True
        assert result.public_key == public_key

        # Verify stats were updated
        key_info = self.key_manager.get_key_info(tool_id)
        assert key_info["verification_count"] >= 2

    async def test_verification_failure_with_pinned_key(self):
        """Test verification failure when signature doesn't match pinned key."""
        tool_name = "secure_operation"
        domain = "example.com"
        tool_id = f"{domain}/{tool_name}"
        public_key = "-----BEGIN PUBLIC KEY-----\nlegit_key\n-----END PUBLIC KEY-----"

        # Pin legitimate key
        self.key_manager.pin_key(tool_id, domain, public_key)

        schema = {
            "name": "secure_operation",
            "description": "Secure operation",
            "parameters": {"type": "object"}
        }
        malicious_signature = "malicious_signature"

        # Mock signature verification to fail
        with patch.object(self.interceptor, '_verify_signature', return_value=False):
            result = await self.interceptor.verify_tool_schema(
                tool_name, schema, malicious_signature, domain
            )

        assert result.valid is False
        assert result.key_pinned is True
        assert "Signature verification failed" in result.error

    async def test_policy_enforcement_workflow(self):
        """Test complete policy enforcement workflow."""
        tool_name = "admin_operation"
        domain = "untrusted.com"

        # Test with enforce mode
        self.config.policy_mode = "enforce"
        policy_handler = PolicyHandler(self.config)

        # Create failed verification result
        failed_result = VerificationResult(
            valid=False,
            tool_id=f"{domain}/{tool_name}",
            domain=domain,
            error="Invalid signature"
        )

        decision = await policy_handler.evaluate_verification_result(failed_result, tool_name)
        assert decision.action == PolicyAction.BLOCK
        assert decision.policy_mode == "enforce"

        # Test with warn mode
        self.config.policy_mode = "warn"
        policy_handler = PolicyHandler(self.config)

        decision = await policy_handler.evaluate_verification_result(failed_result, tool_name)
        assert decision.action == PolicyAction.WARN
        assert decision.policy_mode == "warn"

    async def test_audit_logging_integration(self):
        """Test audit logging throughout verification workflow."""
        tool_name = "logged_operation"
        domain = "example.com"
        schema = {"name": "logged_operation", "description": "Test operation"}
        signature = "test_signature"

        # Mock successful verification
        with patch.object(self.interceptor, '_verify_signature', return_value=True):
            with patch.object(self.key_manager, 'discover_public_key') as mock_discovery:
                mock_discovery.return_value = "test_public_key"

                await self.interceptor.verify_tool_schema(
                    tool_name, schema, signature, domain
                )

        # Verify audit logs were created
        stats = self.audit_logger.get_verification_stats()
        assert stats["total_verifications"] >= 1
        assert stats["successful_verifications"] >= 1

    @patch('aiohttp.ClientSession.get')
    async def test_key_discovery_integration(self, mock_get):
        """Test key discovery integration with real HTTP mocking."""
        domain = "api.example.com"
        # tool_name = "api_call"  # Not used in this test

        # Mock successful .well-known endpoint response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "public_key": "-----BEGIN PUBLIC KEY-----\napi_key\n-----END PUBLIC KEY-----",
            "algorithm": "ES256",
            "created_at": "2023-01-01T00:00:00Z"
        })
        mock_get.return_value.__aenter__.return_value = mock_response

        # Attempt key discovery
        discovered_key = await self.key_manager.discover_public_key(domain)
        assert discovered_key == "-----BEGIN PUBLIC KEY-----\napi_key\n-----END PUBLIC KEY-----"

        # Verify correct URL was called
        mock_get.assert_called_once()
        call_args = mock_get.call_args[0]
        assert f"https://{domain}/.well-known/schemapin.json" in str(call_args)

    async def test_multiple_tools_same_domain(self):
        """Test handling multiple tools from the same domain."""
        domain = "toolsuite.com"
        tools = ["tool_a", "tool_b", "tool_c"]
        public_key = "-----BEGIN PUBLIC KEY-----\nshared_key\n-----END PUBLIC KEY-----"

        # Mock key discovery to return same key for domain
        with patch.object(self.key_manager, 'discover_public_key') as mock_discovery:
            mock_discovery.return_value = public_key

            # Mock signature verification to succeed
            with patch.object(self.interceptor, '_verify_signature', return_value=True):
                results = []
                for tool in tools:
                    schema = {"name": tool, "description": f"Tool {tool}"}
                    result = await self.interceptor.verify_tool_schema(
                        tool, schema, "signature", domain
                    )
                    results.append(result)

        # All should succeed
        for result in results:
            assert result.valid is True
            assert result.domain == domain

        # Check that separate tool IDs were created
        pinned_keys = self.key_manager.list_pinned_keys()
        tool_ids = [key["tool_id"] for key in pinned_keys]

        for tool in tools:
            expected_tool_id = f"{domain}/{tool}"
            assert expected_tool_id in tool_ids

    async def test_configuration_persistence(self):
        """Test configuration save/load functionality."""
        # Create custom configuration
        custom_config = SchemaPinConfig(
            enabled=True,
            policy_mode="enforce",
            auto_pin_keys=True,
            trusted_domains=["trusted1.com", "trusted2.com"],
            discovery_timeout=60,
            cache_ttl=7200
        )

        # Save to file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = f.name

        try:
            custom_config.save_to_file(config_path)

            # Load from file
            loaded_config = SchemaPinConfig.load_from_file(config_path)

            # Verify all settings preserved
            assert loaded_config.enabled == custom_config.enabled
            assert loaded_config.policy_mode == custom_config.policy_mode
            assert loaded_config.auto_pin_keys == custom_config.auto_pin_keys
            assert loaded_config.trusted_domains == custom_config.trusted_domains
            assert loaded_config.discovery_timeout == custom_config.discovery_timeout
            assert loaded_config.cache_ttl == custom_config.cache_ttl
        finally:
            Path(config_path).unlink(missing_ok=True)

    async def test_database_persistence_across_sessions(self):
        """Test that pinned keys persist across different sessions."""
        tool_id = "persistent.com/test_tool"
        domain = "persistent.com"
        public_key = "-----BEGIN PUBLIC KEY-----\npersistent_key\n-----END PUBLIC KEY-----"

        # Pin key with first manager instance
        manager1 = KeyPinningManager(self.temp_db_name)
        success = manager1.pin_key(tool_id, domain, public_key, {"session": "1"})
        assert success is True

        # Create new manager instance (simulating new session)
        manager2 = KeyPinningManager(self.temp_db_name)
        retrieved_key = manager2.get_pinned_key(tool_id)
        assert retrieved_key == public_key

        # Verify metadata persisted
        key_info = manager2.get_key_info(tool_id)
        assert key_info["metadata"]["session"] == "1"

    async def test_error_handling_and_recovery(self):
        """Test error handling and graceful recovery."""
        tool_name = "error_prone_tool"
        domain = "unreliable.com"
        schema = {"name": "error_prone_tool"}

        # Test with network timeout during key discovery
        with patch.object(self.key_manager, 'discover_public_key') as mock_discovery:
            mock_discovery.side_effect = TimeoutError("Network timeout")

            result = await self.interceptor.verify_tool_schema(
                tool_name, schema, "signature", domain
            )

            assert result.valid is False
            assert "No public key found" in result.error

    async def test_concurrent_verification_requests(self):
        """Test handling concurrent verification requests."""
        domain = "concurrent.com"
        public_key = "-----BEGIN PUBLIC KEY-----\nconcurrent_key\n-----END PUBLIC KEY-----"

        # Mock key discovery and signature verification
        with patch.object(self.key_manager, 'discover_public_key') as mock_discovery:
            mock_discovery.return_value = public_key

            with patch.object(self.interceptor, '_verify_signature', return_value=True):
                # Create multiple concurrent verification tasks
                tasks = []
                for i in range(5):
                    schema = {"name": f"tool_{i}", "description": f"Concurrent tool {i}"}
                    task = self.interceptor.verify_tool_schema(
                        f"tool_{i}", schema, "signature", domain
                    )
                    tasks.append(task)

                # Wait for all to complete
                results = await asyncio.gather(*tasks)

        # All should succeed
        for result in results:
            assert result.valid is True
            assert result.domain == domain

        # Verify all tools were pinned
        pinned_keys = self.key_manager.list_pinned_keys()
        assert len(pinned_keys) == 5


class TestSchemaPinMockLoopIntegration(unittest.TestCase):
    """Test SchemaPin integration with MockLoop MCP components."""

    def setUp(self):
        """Set up test environment."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            self.temp_db_name = temp_db.name

        self.config = SchemaPinConfig(
            key_pin_storage_path=self.temp_db_name,
            policy_mode="warn"
        )

    def tearDown(self):
        """Clean up test environment."""
        Path(self.temp_db_name).unlink(missing_ok=True)

    def test_mcp_tool_schema_extraction(self):
        """Test extracting schemas from MCP tool functions."""
        from src.mockloop_mcp.schemapin.verification import extract_tool_schema

        def sample_mcp_tool(query: str, database: str = "default") -> dict:
            """Execute a database query.

            Args:
                query: SQL query to execute
                database: Database name (optional)

            Returns:
                Query results
            """
            return {"results": []}

        schema = extract_tool_schema(sample_mcp_tool)

        assert schema["name"] == "sample_mcp_tool"
        assert "Execute a database query" in schema["description"]
        assert "parameters" in schema

    async def test_integration_with_mcp_audit_system(self):
        """Test integration with MockLoop's audit system."""
        audit_logger = SchemaPinAuditLogger(self.temp_db_name)

        # Log various events
        await audit_logger.log_verification_attempt(
            "mcp.tool/test", "mcp.example.com",
            VerificationResult(valid=True, tool_id="mcp.tool/test", key_pinned=True),
            125.5
        )

        await audit_logger.log_policy_decision(
            "mcp.tool/admin", "warn", "Unsigned tool execution", "warn"
        )

        # Verify audit data
        stats = audit_logger.get_verification_stats()
        assert stats["total_verifications"] >= 1
        assert "policy_breakdown" in stats

    def test_database_schema_compatibility(self):
        """Test that SchemaPin tables integrate with MockLoop database."""
        SchemaPinAuditLogger(self.temp_db_name)  # Creates tables automatically

        # Verify tables were created
        with sqlite3.connect(self.temp_db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='schemapin_verification_logs'
            """)
            result = cursor.fetchone()
            assert result is not None

            # Verify indexes were created
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND name LIKE 'idx_schemapin%'
            """)
            indexes = cursor.fetchall()
            assert len(indexes) >= 2  # Should have tool and entry indexes


if __name__ == "__main__":
    # Run integration tests
    unittest.main()
