"""
SchemaPin Integration for MockLoop MCP

This module provides cryptographic schema verification capabilities for MCP tools,
implementing the SchemaPin protocol to prevent "MCP Rug Pull" attacks.

Key Components:
- SchemaPinConfig: Configuration management
- SchemaVerificationInterceptor: Tool execution interception
- PolicyHandler: Security policy enforcement
- KeyPinningManager: TOFU key management
- SchemaPinAuditLogger: Audit logging integration
"""

from .config import SchemaPinConfig, PolicyAction, PolicyDecision, VerificationResult
from .verification import SchemaVerificationInterceptor
from .policy import PolicyHandler
from .key_management import KeyPinningManager
from .audit import SchemaPinAuditLogger

__all__ = [
    "KeyPinningManager",
    "PolicyAction",
    "PolicyDecision",
    "PolicyHandler",
    "SchemaPinAuditLogger",
    "SchemaPinConfig",
    "SchemaVerificationInterceptor",
    "VerificationResult",
]

__version__ = "1.0.0"
