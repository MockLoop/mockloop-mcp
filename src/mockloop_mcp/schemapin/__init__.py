"""
SchemaPin Integration for MockLoop MCP

This module provides comprehensive cryptographic schema verification capabilities for MCP tools,
implementing the SchemaPin protocol to prevent "MCP Rug Pull" attacks.

Key Components:
- SchemaPinConfig: Configuration management with extended policy support
- SchemaVerificationInterceptor: Tool execution interception and validation
- SchemaSigner: Schema signing infrastructure with key management
- PolicyHandler: Security policy enforcement with customizable actions
- KeyPinningManager: TOFU key management and validation
- SchemaPinAuditLogger: Comprehensive audit logging integration
- signed_tool: Decorator for automatic schema signing of MCP tools
- Batch utilities: Tools for signing and validating multiple schemas

Usage Examples:
    Basic tool signing:
        @signed_tool(
            domain="mockloop.com",
            private_key_path="/path/to/private.pem"
        )
        async def my_tool(param: str) -> dict:
            return {"result": "success"}

    Batch signing:
        from scripts.sign_all_schemas import BatchSigner
        signer = BatchSigner("mockloop.com", private_key_path="/path/to/key.pem")
        results = signer.sign_tools(discovered_tools)

    Configuration:
        config = SchemaPinConfig(
            enabled=True,
            domain="mockloop.com",
            public_key_path="/path/to/public.pem"
        )
"""

# Core configuration and verification
from .config import (
    SchemaPinConfig,
    PolicyAction,
    PolicyDecision,
    VerificationResult,
    get_schemapin_config,
    SchemaVerificationError
)
from .verification import SchemaVerificationInterceptor, extract_tool_schema
from .policy import PolicyHandler
from .key_management import KeyPinningManager
from .audit import SchemaPinAuditLogger

# Schema signing infrastructure
from .signing import (
    SchemaSigner,
    create_signer_from_file,
    create_signer_from_content
)

# Tool decoration and schema extraction
from .decorators import (
    signed_tool,
    extract_enhanced_tool_schema,
    get_tool_signature,
    get_tool_domain,
    get_tool_schema,
    get_tool_public_key,
    verify_tool_signature,
    list_signed_tools,
    create_test_signer
)

__all__ = [
    "KeyPinningManager",
    "PolicyAction",
    "PolicyDecision",
    "PolicyHandler",
    "SchemaPinAuditLogger",
    "SchemaPinConfig",
    "SchemaSigner",
    "SchemaVerificationError",
    "SchemaVerificationInterceptor",
    "VerificationResult",
    "create_signer_from_content",
    "create_signer_from_file",
    "create_test_signer",
    "extract_enhanced_tool_schema",
    "extract_tool_schema",
    "get_schemapin_config",
    "get_tool_domain",
    "get_tool_public_key",
    "get_tool_schema",
    "get_tool_signature",
    "list_signed_tools",
    "signed_tool",
    "verify_tool_signature",
]

__version__ = "1.0.0"

# Configuration examples for different environments
EXAMPLE_CONFIGS = {
    "development": {
        "domain": "dev.mockloop.com",
        "enabled": True,
        "policy_mode": "warn",
        "auto_generate_keys": True,
    },
    "production": {
        "domain": "mockloop.com",
        "enabled": True,
        "policy_mode": "strict",
        "require_signatures": True,
        "public_key_path": "/etc/mockloop/public.pem",
    },
    "testing": {
        "domain": "test.mockloop.com",
        "enabled": False,
        "policy_mode": "log",
    }
}

# Batch signing configuration template
BATCH_SIGNING_CONFIG_TEMPLATE = {
    "domain": "mockloop.com",
    "private_key_path": "/path/to/private.pem",
    "search_paths": ["src"],
    "force_resign": False,
    "output_file": "signing_results.json"
}
