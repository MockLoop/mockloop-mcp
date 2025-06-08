"""
Unit tests for SchemaPin integration with MockLoop MCP.

Tests cover all core SchemaPin components:
- Configuration management
- Schema verification workflow
- Key pinning and discovery
- Policy enforcement
- Audit logging
- Error handling and graceful fallback
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
    PolicyDecision,
    PolicyHandler,
    SchemaPinAuditLogger,
    SchemaPinConfig,
    SchemaVerificationInterceptor,
    VerificationResult,
)
from src.mockloop_mcp.schemapin.config import SchemaVerificationError


class TestSchemaPinConfig(unittest.TestCase):
    """Test SchemaPin configuration management."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SchemaPinConfig()

        assert config.enabled is True
        assert config.policy_mode == "warn"
        assert config.auto_pin_keys is False
        assert config.key_pin_storage_path == "schemapin_keys.db"
        assert config.discovery_timeout == 30
        assert config.cache_ttl == 3600
        assert config.well_known_endpoints == {}
        assert config.trusted_domains == []
        assert config.revocation_check is True
        assert config.interactive_mode is True

    def test_config_to_dict(self):
        """Test configuration serialization to dictionary."""
        config = SchemaPinConfig(
            enabled=False,
            policy_mode="enforce",
            auto_pin_keys=True,
            trusted_domains=["example.com"]
        )

        config_dict = config.to_dict()

        assert config_dict["enabled"] is False
        assert config_dict["policy_mode"] == "enforce"
        assert config_dict["auto_pin_keys"] is True
        assert config_dict["trusted_domains"] == ["example.com"]

    def test_config_from_dict(self):
        """Test configuration deserialization from dictionary."""
        config_data = {
            "enabled": False,
            "policy_mode": "log",
            "auto_pin_keys": True,
            "discovery_timeout": 60,
            "trusted_domains": ["trusted.com"]
        }

        config = SchemaPinConfig.from_dict(config_data)

        assert config.enabled is False
        assert config.policy_mode == "log"
        assert config.auto_pin_keys is True
        assert config.discovery_timeout == 60
        assert config.trusted_domains == ["trusted.com"]

    def test_config_file_operations(self):
        """Test saving and loading configuration from file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = f.name

        try:
            # Create and save config
            original_config = SchemaPinConfig(
                policy_mode="enforce",
                trusted_domains=["example.com", "test.org"]
            )
            original_config.save_to_file(config_path)

            # Load config from file
            loaded_config = SchemaPinConfig.load_from_file(config_path)

            assert loaded_config.policy_mode == "enforce"
            assert loaded_config.trusted_domains == ["example.com", "test.org"]
            assert loaded_config.enabled is True  # Default value
        finally:
            Path(config_path).unlink(missing_ok=True)


class TestVerificationResult(unittest.TestCase):
    """Test VerificationResult data structure."""

    def test_verification_result_creation(self):
        """Test creating verification results."""
        result = VerificationResult(
            valid=True,
            tool_id="example.com/test_tool",
            domain="example.com",
            key_pinned=True,
            signature="test_signature",
            public_key="test_key",
            timestamp=1234567890.0
        )

        assert result.valid is True
        assert result.tool_id == "example.com/test_tool"
        assert result.domain == "example.com"
        assert result.key_pinned is True
        assert result.signature == "test_signature"
        assert result.public_key == "test_key"
        assert result.timestamp == 1234567890.0
        assert result.error is None

    def test_verification_result_with_error(self):
        """Test verification result with error."""
        result = VerificationResult(
            valid=False,
            tool_id="test_tool",
            error="Signature verification failed"
        )

        assert result.valid is False
        assert result.tool_id == "test_tool"
        assert result.error == "Signature verification failed"
        assert result.domain is None
        assert result.key_pinned is False


class TestPolicyHandler(unittest.TestCase):
    """Test policy enforcement logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = SchemaPinConfig(
            policy_mode="warn",
            trusted_domains=["trusted.com"],
            auto_pin_keys=False,
            interactive_mode=True
        )
        self.policy_handler = PolicyHandler(self.config)

    async def test_evaluate_failed_verification_enforce_mode(self):
        """Test policy evaluation for failed verification in enforce mode."""
        self.config.policy_mode = "enforce"
        self.policy_handler = PolicyHandler(self.config)

        result = VerificationResult(
            valid=False,
            tool_id="test_tool",
            error="Invalid signature"
        )

        decision = await self.policy_handler.evaluate_verification_result(result, "test_tool")

        assert decision.action == PolicyAction.BLOCK
        assert "Invalid signature" in decision.reason
        assert decision.policy_mode == "enforce"

    async def test_evaluate_failed_verification_warn_mode(self):
        """Test policy evaluation for failed verification in warn mode."""
        result = VerificationResult(
            valid=False,
            tool_id="test_tool",
            error="Invalid signature"
        )

        decision = await self.policy_handler.evaluate_verification_result(result, "test_tool")

        assert decision.action == PolicyAction.WARN
        assert "Invalid signature" in decision.reason
        assert decision.policy_mode == "warn"

    async def test_evaluate_failed_verification_log_mode(self):
        """Test policy evaluation for failed verification in log mode."""
        self.config.policy_mode = "log"
        self.policy_handler = PolicyHandler(self.config)

        result = VerificationResult(
            valid=False,
            tool_id="test_tool",
            error="Invalid signature"
        )

        decision = await self.policy_handler.evaluate_verification_result(result, "test_tool")

        assert decision.action == PolicyAction.LOG
        assert "Invalid signature" in decision.reason
        assert decision.policy_mode == "log"

    async def test_evaluate_successful_verification_with_pinned_key(self):
        """Test policy evaluation for successful verification with pinned key."""
        result = VerificationResult(
            valid=True,
            tool_id="test_tool",
            key_pinned=True
        )

        decision = await self.policy_handler.evaluate_verification_result(result, "test_tool")

        assert decision.action == PolicyAction.ALLOW
        assert "successful" in decision.reason.lower()

    async def test_evaluate_tofu_scenario_interactive_mode(self):
        """Test TOFU scenario in interactive mode."""
        result = VerificationResult(
            valid=True,
            tool_id="test_tool",
            key_pinned=False,
            domain="untrusted.com"
        )

        decision = await self.policy_handler.evaluate_verification_result(result, "test_tool")

        assert decision.action == PolicyAction.PROMPT
        assert "user confirmation" in decision.reason.lower()

    async def test_evaluate_tofu_scenario_non_interactive_mode(self):
        """Test TOFU scenario in non-interactive mode."""
        self.config.interactive_mode = False
        self.policy_handler = PolicyHandler(self.config)

        result = VerificationResult(
            valid=True,
            tool_id="test_tool",
            key_pinned=False,
            domain="untrusted.com"
        )

        decision = await self.policy_handler.evaluate_verification_result(result, "test_tool")

        assert decision.action == PolicyAction.ALLOW
        assert "auto-pinning" in decision.reason.lower()

    def test_should_auto_pin_key_trusted_domain(self):
        """Test auto-pinning for trusted domains."""
        should_pin = self.policy_handler.should_auto_pin_key("trusted.com", "test_tool")
        assert should_pin is True

    def test_should_auto_pin_key_untrusted_domain(self):
        """Test auto-pinning for untrusted domains."""
        should_pin = self.policy_handler.should_auto_pin_key("untrusted.com", "test_tool")
        assert should_pin is False

    def test_should_auto_pin_key_with_auto_pin_enabled(self):
        """Test auto-pinning when globally enabled."""
        self.config.auto_pin_keys = True
        self.policy_handler = PolicyHandler(self.config)

        should_pin = self.policy_handler.should_auto_pin_key("untrusted.com", "test_tool")
        assert should_pin is True

    def test_policy_overrides(self):
        """Test tool-specific policy overrides."""
        # Set override
        self.policy_handler.set_policy_override("special_tool", "enforce")

        # Check effective policy
        assert self.policy_handler.get_effective_policy("special_tool") == "enforce"
        assert self.policy_handler.get_effective_policy("normal_tool") == "warn"

        # List overrides
        overrides = self.policy_handler.list_policy_overrides()
        assert overrides["special_tool"] == "enforce"

        # Remove override
        self.policy_handler.remove_policy_override("special_tool")
        assert self.policy_handler.get_effective_policy("special_tool") == "warn"

    def test_invalid_policy_override(self):
        """Test setting invalid policy override."""
        with pytest.raises(ValueError, match="Invalid policy mode"):
            self.policy_handler.set_policy_override("test_tool", "invalid_mode")


class TestKeyPinningManager(unittest.TestCase):
    """Test key pinning and discovery functionality."""

    def setUp(self):
        """Set up test fixtures."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            self.temp_db_name = temp_db.name
        self.key_manager = KeyPinningManager(self.temp_db_name)

    def tearDown(self):
        """Clean up test fixtures."""
        Path(self.temp_db_name).unlink(missing_ok=True)

    def test_pin_and_get_key(self):
        """Test pinning and retrieving keys."""
        tool_id = "example.com/test_tool"
        domain = "example.com"
        public_key = "-----BEGIN PUBLIC KEY-----\ntest_key\n-----END PUBLIC KEY-----"
        metadata = {"developer": "Test Developer"}

        # Pin key
        success = self.key_manager.pin_key(tool_id, domain, public_key, metadata)
        assert success is True

        # Retrieve key
        retrieved_key = self.key_manager.get_pinned_key(tool_id)
        assert retrieved_key == public_key

        # Check if key is pinned
        assert self.key_manager.is_key_pinned(tool_id) is True

    def test_get_nonexistent_key(self):
        """Test retrieving non-existent key."""
        retrieved_key = self.key_manager.get_pinned_key("nonexistent_tool")
        assert retrieved_key is None
        assert self.key_manager.is_key_pinned("nonexistent_tool") is False

    def test_update_verification_stats(self):
        """Test updating verification statistics."""
        tool_id = "example.com/test_tool"
        domain = "example.com"
        public_key = "test_key"

        # Pin key first
        self.key_manager.pin_key(tool_id, domain, public_key)

        # Update stats
        self.key_manager.update_verification_stats(tool_id)

        # Check stats
        key_info = self.key_manager.get_key_info(tool_id)
        assert key_info is not None
        assert key_info["verification_count"] == 2  # 1 from pinning + 1 from update

    def test_revoke_key(self):
        """Test key revocation."""
        tool_id = "example.com/test_tool"
        domain = "example.com"
        public_key = "test_key"

        # Pin key
        self.key_manager.pin_key(tool_id, domain, public_key)
        assert self.key_manager.is_key_pinned(tool_id) is True

        # Revoke key
        success = self.key_manager.revoke_key(tool_id)
        assert success is True
        assert self.key_manager.is_key_pinned(tool_id) is False

    def test_list_pinned_keys(self):
        """Test listing all pinned keys."""
        # Pin multiple keys
        self.key_manager.pin_key("tool1", "domain1.com", "key1")
        self.key_manager.pin_key("tool2", "domain2.com", "key2")

        # List keys
        pinned_keys = self.key_manager.list_pinned_keys()
        assert len(pinned_keys) == 2

        tool_ids = [key["tool_id"] for key in pinned_keys]
        assert "tool1" in tool_ids
        assert "tool2" in tool_ids

    def test_get_key_info(self):
        """Test getting detailed key information."""
        tool_id = "example.com/test_tool"
        domain = "example.com"
        public_key = "test_key"
        metadata = {"developer": "Test Developer", "version": "1.0"}

        # Pin key with metadata
        self.key_manager.pin_key(tool_id, domain, public_key, metadata)

        # Get key info
        key_info = self.key_manager.get_key_info(tool_id)
        assert key_info is not None
        assert key_info["tool_id"] == tool_id
        assert key_info["domain"] == domain
        assert key_info["public_key_pem"] == public_key
        assert key_info["metadata"]["developer"] == "Test Developer"
        assert key_info["metadata"]["version"] == "1.0"

    @patch('aiohttp.ClientSession.get')
    async def test_discover_public_key_success(self, mock_get):
        """Test successful public key discovery."""
        # Mock successful HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "public_key": "-----BEGIN PUBLIC KEY-----\ndiscovered_key\n-----END PUBLIC KEY-----"
        })
        mock_get.return_value.__aenter__.return_value = mock_response

        # Test discovery
        discovered_key = await self.key_manager.discover_public_key("example.com")
        assert discovered_key == "-----BEGIN PUBLIC KEY-----\ndiscovered_key\n-----END PUBLIC KEY-----"

    @patch('aiohttp.ClientSession.get')
    async def test_discover_public_key_failure(self, mock_get):
        """Test failed public key discovery."""
        # Mock failed HTTP response
        mock_response = AsyncMock()
        mock_response.status = 404
        mock_get.return_value.__aenter__.return_value = mock_response

        # Test discovery
        discovered_key = await self.key_manager.discover_public_key("nonexistent.com")
        assert discovered_key is None

    @patch('aiohttp.ClientSession.get')
    async def test_discover_public_key_timeout(self, mock_get):
        """Test public key discovery timeout."""
        # Mock timeout exception
        mock_get.side_effect = TimeoutError()

        # Test discovery
        discovered_key = await self.key_manager.discover_public_key("slow.com", timeout=1)
        assert discovered_key is None


class TestSchemaPinAuditLogger(unittest.TestCase):
    """Test audit logging functionality."""

    def setUp(self):
        """Set up test fixtures."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            self.temp_db_name = temp_db.name
        self.audit_logger = SchemaPinAuditLogger(self.temp_db_name)

    def tearDown(self):
        """Clean up test fixtures."""
        Path(self.temp_db_name).unlink(missing_ok=True)

    async def test_log_verification_attempt(self):
        """Test logging verification attempts."""
        result = VerificationResult(
            valid=True,
            tool_id="example.com/test_tool",
            domain="example.com",
            key_pinned=True
        )

        await self.audit_logger.log_verification_attempt(
            "example.com/test_tool", "example.com", result, 150.5
        )

        # Verify log entry
        with sqlite3.connect(self.temp_db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM schemapin_verification_logs")
            logs = cursor.fetchall()

            assert len(logs) == 1
            log = logs[0]
            assert log[2] == "example.com/test_tool"  # tool_id
            assert log[3] == "example.com"  # domain
            assert log[4] == "success"  # verification_result
            assert log[5] == 1  # signature_valid
            assert log[6] == 1  # key_pinned
            assert log[9] == 150.5  # execution_time_ms

    async def test_log_verification_error(self):
        """Test logging verification errors."""
        await self.audit_logger.log_verification_error(
            "test_tool", "example.com", "Signature verification failed"
        )

        # Verify log entry
        with sqlite3.connect(self.temp_db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM schemapin_verification_logs")
            logs = cursor.fetchall()

            assert len(logs) == 1
            log = logs[0]
            assert log[2] == "test_tool"  # tool_id
            assert log[4] == "error"  # verification_result
            assert log[5] == 0  # signature_valid
            assert "Signature verification failed" in log[8]  # error_details

    async def test_log_key_pinning_event(self):
        """Test logging key pinning events."""
        await self.audit_logger.log_key_pinning_event(
            "test_tool", "example.com", "test_public_key", "pin"
        )

        # Verify log entry
        with sqlite3.connect(self.temp_db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM schemapin_verification_logs")
            logs = cursor.fetchall()

            assert len(logs) == 1
            log = logs[0]
            assert log[2] == "test_tool"  # tool_id
            assert log[4] == "key_pin"  # verification_result
            assert log[7] == "pin"  # policy_action

    async def test_log_policy_decision(self):
        """Test logging policy decisions."""
        await self.audit_logger.log_policy_decision(
            "test_tool", "warn", "Schema verification failed", "warn"
        )

        # Verify log entry
        with sqlite3.connect(self.temp_db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM schemapin_verification_logs")
            logs = cursor.fetchall()

            assert len(logs) == 1
            log = logs[0]
            assert log[2] == "test_tool"  # tool_id
            assert log[4] == "policy_warn"  # verification_result
            assert log[7] == "warn"  # policy_action

    async def test_get_verification_stats(self):
        """Test getting verification statistics."""
        # Log some test data
        result1 = VerificationResult(valid=True, tool_id="tool1", key_pinned=True)
        result2 = VerificationResult(valid=False, tool_id="tool2", error="Failed")

        await self.audit_logger.log_verification_attempt("tool1", "domain1.com", result1, 100)
        await self.audit_logger.log_verification_attempt("tool2", "domain2.com", result2, 200)

        # Get stats
        stats = self.audit_logger.get_verification_stats()

        assert stats["total_verifications"] == 2
        assert stats["successful_verifications"] == 1
        assert stats["failed_verifications"] == 1
        assert stats["unique_tools"] == 2
        assert stats["unique_domains"] == 2


class TestSchemaVerificationInterceptor(unittest.TestCase):
    """Test schema verification interceptor."""

    def setUp(self):
        """Set up test fixtures."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            self.temp_db_name = temp_db.name

        self.config = SchemaPinConfig(
            key_pin_storage_path=self.temp_db_name,
            policy_mode="warn"
        )
        self.interceptor = SchemaVerificationInterceptor(self.config)

    def tearDown(self):
        """Clean up test fixtures."""
        Path(self.temp_db_name).unlink(missing_ok=True)

    async def test_verify_tool_schema_no_signature(self):
        """Test verification with no signature provided."""
        schema = {"name": "test_tool", "description": "Test tool"}

        result = await self.interceptor.verify_tool_schema("test_tool", schema)

        assert result.valid is False
        assert "No signature provided" in result.error
        assert result.tool_id == "test_tool"

    async def test_verify_tool_schema_with_pinned_key(self):
        """Test verification with pinned key."""
        # Pin a key first
        tool_id = "example.com/test_tool"
        public_key = "test_public_key"
        self.interceptor.key_manager.pin_key(tool_id, "example.com", public_key)

        schema = {"name": "test_tool", "description": "Test tool"}
        signature = "test_signature"

        # Mock signature verification to return True
        with patch.object(self.interceptor, '_verify_signature', return_value=True):
            result = await self.interceptor.verify_tool_schema(
                "test_tool", schema, signature, "example.com"
            )

        assert result.valid is True
        assert result.key_pinned is True
        assert result.tool_id == tool_id

    async def test_verify_tool_schema_signature_verification_failure(self):
        """Test verification with signature verification failure."""
        # Pin a key first
        tool_id = "example.com/test_tool"
        public_key = "test_public_key"
        self.interceptor.key_manager.pin_key(tool_id, "example.com", public_key)

        schema = {"name": "test_tool", "description": "Test tool"}
        signature = "invalid_signature"

        # Mock signature verification to return False
        with patch.object(self.interceptor, '_verify_signature', return_value=False):
            result = await self.interceptor.verify_tool_schema(
                "test_tool", schema, signature, "example.com"
            )

        assert result.valid is False
        assert result.key_pinned is True
        assert "Signature verification failed" in result.error

    @patch('aiohttp.ClientSession.get')
    async def test_verify_tool_schema_with_key_discovery(self, mock_get):
        """Test verification with key discovery."""
        # Mock successful key discovery
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "public_key": "discovered_public_key"
        })
        mock_get.return_value.__aenter__.return_value = mock_response

        schema = {"name": "test_tool", "description": "Test tool"}
        signature = "test_signature"

        # Mock signature verification to return True
        with patch.object(self.interceptor, '_verify_signature', return_value=True):
            result = await self.interceptor.verify_tool_schema(
                "test_tool", schema, signature, "example.com"
            )

        assert result.valid is True
        assert result.domain == "example.com"
        assert result.public_key == "discovered_public_key"

    async def test_verify_tool_schema_no_domain(self):
        """Test verification with no domain provided."""
        schema = {"name": "test_tool", "description": "Test tool"}
        signature = "test_signature"

        result = await self.interceptor.verify_tool_schema("test_tool", schema, signature)

        assert result.valid is False
        assert "No domain provided" in result.error

    def test_extract_tool_id(self):
        """Test tool ID extraction."""
        # With domain
        tool_id = self.interceptor._extract_tool_id("test_tool", "example.com")
        assert tool_id == "example.com/test_tool"

        # Without domain
        tool_id = self.interceptor._extract_tool_id("test_tool", None)
        assert tool_id == "test_tool"

    def test_normalize_schema(self):
        """Test schema normalization."""
        schema = {
            "name": "test_tool",
            "description": "Test tool",
            "timestamp": "2023-01-01T00:00:00Z",
            "version": "1.0.0",
            "parameters": {"type": "object"}
        }

        normalized = self.interceptor._normalize_schema(schema)

        assert "name" in normalized
        assert "description" in normalized
        assert "parameters" in normalized
        assert "timestamp" not in normalized
        assert "version" not in normalized

    async def test_legacy_verify_signature(self):
        """Test legacy signature verification."""
        schema = {"name": "test_tool", "description": "Test tool"}
        public_key = "test_public_key"

        # Create a signature that should match the legacy implementation
        import hashlib
        import base64

        normalized_schema = self.interceptor._normalize_schema(schema)
        schema_json = json.dumps(normalized_schema, sort_keys=True, separators=(',', ':'))
        schema_hash = hashlib.sha256(schema_json.encode('utf-8')).digest()
        expected_signature = hashlib.sha256(
            schema_hash + public_key.encode('utf-8')
        ).digest()[:32]

        # Pad to make it longer than 32 bytes
        signature_bytes = expected_signature + b'\x00' * 10
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

        is_valid = await self.interceptor._verify_signature(schema, signature_b64, public_key)
        assert is_valid is True

    async def test_verify_signature_invalid(self):
        """Test signature verification with invalid signature."""
        schema = {"name": "test_tool", "description": "Test tool"}
        signature = "invalid_signature"
        public_key = "test_public_key"

        is_valid = await self.interceptor._verify_signature(schema, signature, public_key)
        assert is_valid is False


class TestSchemaPinIntegrationWithoutLibrary(unittest.TestCase):
    """Test SchemaPin integration graceful fallback when library is unavailable."""

    @patch('src.mockloop_mcp.schemapin.verification.SCHEMAPIN_AVAILABLE', False)
    @patch('src.mockloop_mcp.schemapin.key_management.SCHEMAPIN_AVAILABLE', False)
    def test_fallback_behavior(self):
        """Test that components work without SchemaPin library."""
        config = SchemaPinConfig()

        # Test that components can be created without SchemaPin library
        interceptor = SchemaVerificationInterceptor(config)
        assert interceptor.schemapin_core is None
        assert interceptor.signature_manager is None

        key_manager = KeyPinningManager("test.db")
        assert key_manager.public_key_discovery is None
        assert key_manager.key_pinning is None

    @patch('src.mockloop_mcp.schemapin.verification.SCHEMAPIN_AVAILABLE', False)
    async def test_legacy_verification_workflow(self):
        """Test that legacy verification workflow works without SchemaPin library."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            temp_db_name = temp_db.name

        try:
            config = SchemaPinConfig(key_pin_storage_path=temp_db_name)
            interceptor = SchemaVerificationInterceptor(config)

            schema = {"name": "test_tool", "description": "Test tool"}
            signature = "test_signature"

            # This should use the legacy implementation
            result = await interceptor.verify_tool_schema(
                "test_tool", schema, signature, "example.com"
            )

            # Should fail because no key is pinned and discovery will fail
            assert result.valid is False
            assert result.tool_id == "example.com/test_tool"
        finally:
            Path(temp_db_name).unlink(missing_ok=True)


if __name__ == "__main__":
    # Run tests
    unittest.main()
