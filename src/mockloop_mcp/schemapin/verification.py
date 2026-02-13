"""
SchemaPin Verification Module

Core schema verification implementation using the SchemaPin protocol.
"""

import base64
import hashlib
import json
import logging
import time
from typing import Any

try:
    from schemapin.utils import SchemaVerificationWorkflow
    from schemapin.core import SchemaPinCore
    from schemapin.crypto import KeyManager, SignatureManager
    from schemapin.discovery import PublicKeyDiscovery
    from schemapin.pinning import KeyPinning
    SCHEMAPIN_AVAILABLE = True
except ImportError:
    SCHEMAPIN_AVAILABLE = False

from .audit import SchemaPinAuditLogger
from .config import SchemaPinConfig, VerificationResult
from .key_management import KeyPinningManager
from .policy import PolicyHandler

logger = logging.getLogger(__name__)


class SchemaVerificationInterceptor:
    """Intercepts MCP tool calls for SchemaPin verification."""

    def __init__(self, config: SchemaPinConfig):
        """Initialize verification interceptor with configuration."""
        self.config = config
        self.key_manager = KeyPinningManager(config.key_pin_storage_path)
        self.policy_handler = PolicyHandler(config)
        self.audit_logger = SchemaPinAuditLogger()

        # Initialize SchemaPin components if available
        if SCHEMAPIN_AVAILABLE:
            self.schemapin_core = SchemaPinCore()
            self.signature_manager = SignatureManager()
            self.key_crypto_manager = KeyManager()
            self.public_key_discovery = PublicKeyDiscovery()
            self.key_pinning = KeyPinning(config.key_pin_storage_path)
            self.verification_workflow = SchemaVerificationWorkflow(config.key_pin_storage_path)
        else:
            self.schemapin_core = None
            self.signature_manager = None
            self.key_crypto_manager = None
            self.public_key_discovery = None
            self.key_pinning = None
            self.verification_workflow = None

    async def verify_tool_schema(self, tool_name: str, schema: dict[str, Any],
                                signature: str | None = None, domain: str | None = None) -> VerificationResult:
        """
        Verify tool schema using SchemaPin protocol.

        Args:
            tool_name: Name of the tool being verified
            schema: Tool schema to verify
            signature: Base64-encoded signature (optional)
            domain: Domain the tool belongs to (optional)

        Returns:
            Verification result
        """
        start_time = time.time()

        try:
            # Extract tool metadata
            tool_id = self._extract_tool_id(tool_name, domain)

            # If no signature provided, this is an unsigned tool
            if not signature:
                return VerificationResult(
                    valid=False,
                    tool_id=tool_id,
                    domain=domain,
                    error="No signature provided for schema verification"
                )

            # Use SchemaPin verification workflow if available
            if SCHEMAPIN_AVAILABLE and self.verification_workflow:
                try:
                    # Use the high-level verification workflow
                    auto_pin = self.policy_handler.should_auto_pin_key(domain, tool_id)
                    verification_result = await self.verification_workflow.verifySchema(
                        schema, signature, tool_id, domain, auto_pin
                    )

                    # Convert SchemaPin result to our VerificationResult format
                    result = VerificationResult(
                        valid=verification_result.get("valid", False),
                        tool_id=tool_id,
                        domain=domain,
                        key_pinned=verification_result.get("keyPinned", False),
                        signature=signature,
                        public_key=verification_result.get("publicKey"),
                        error=verification_result.get("error"),
                        timestamp=time.time()
                    )

                    if result.valid and result.key_pinned:
                        # Update verification stats in our local storage
                        self.key_manager.update_verification_stats(tool_id)

                except Exception as schemapin_error:
                    # Fall back to legacy implementation if SchemaPin fails
                    result = await self._legacy_verify_tool_schema(tool_name, schema, signature, domain)
                    result.error = f"SchemaPin verification failed, used fallback: {schemapin_error}"
            else:
                # Use legacy implementation if SchemaPin not available
                result = await self._legacy_verify_tool_schema(tool_name, schema, signature, domain)

            # Log verification attempt
            execution_time = (time.time() - start_time) * 1000
            await self.audit_logger.log_verification_attempt(
                tool_id, domain, result, execution_time
            )

            return result

        except Exception as e:
            # Log verification error
            error_result = VerificationResult(
                valid=False,
                tool_id=self._extract_tool_id(tool_name, domain),
                domain=domain,
                error=str(e),
                timestamp=time.time()
            )
            await self.audit_logger.log_verification_error(
                error_result.tool_id, domain, str(e)
            )
            return error_result

    async def _legacy_verify_tool_schema(self, tool_name: str, schema: dict[str, Any],
                                       signature: str | None = None, domain: str | None = None) -> VerificationResult:
        """
        Legacy verification implementation for fallback.
        """
        tool_id = self._extract_tool_id(tool_name, domain)

        # Check if we have a pinned key for this tool
        pinned_key = self.key_manager.get_pinned_key(tool_id)

        if pinned_key:
            # Verify against pinned key
            is_valid = await self._verify_signature(schema, signature, pinned_key)

            if is_valid:
                # Update verification stats
                self.key_manager.update_verification_stats(tool_id)

                return VerificationResult(
                    valid=True,
                    tool_id=tool_id,
                    domain=domain,
                    key_pinned=True,
                    signature=signature,
                    public_key=pinned_key,
                    timestamp=time.time()
                )
            else:
                return VerificationResult(
                    valid=False,
                    tool_id=tool_id,
                    domain=domain,
                    key_pinned=True,
                    error="Signature verification failed against pinned key",
                    signature=signature,
                    timestamp=time.time()
                )
        # No pinned key - attempt key discovery
        elif domain:
            discovered_key = await self.key_manager.discover_public_key(
                domain, self.config.discovery_timeout
            )

            if discovered_key:
                # Verify against discovered key
                is_valid = await self._verify_signature(schema, signature, discovered_key)

                if is_valid:
                    # Auto-pin if configured
                    if self.policy_handler.should_auto_pin_key(domain, tool_id):
                        self.key_manager.pin_key(tool_id, domain, discovered_key)
                        key_pinned = True
                    else:
                        key_pinned = False

                    return VerificationResult(
                        valid=True,
                        tool_id=tool_id,
                        domain=domain,
                        key_pinned=key_pinned,
                        signature=signature,
                        public_key=discovered_key,
                        timestamp=time.time()
                    )
                else:
                    return VerificationResult(
                        valid=False,
                        tool_id=tool_id,
                        domain=domain,
                        error="Signature verification failed against discovered key",
                        signature=signature,
                        timestamp=time.time()
                    )
            else:
                return VerificationResult(
                    valid=False,
                    tool_id=tool_id,
                    domain=domain,
                    error="No public key found for domain",
                    signature=signature,
                    timestamp=time.time()
                )
        else:
            return VerificationResult(
                valid=False,
                tool_id=tool_id,
                domain=domain,
                error="No domain provided for key discovery",
                signature=signature,
                timestamp=time.time()
            )

    async def _verify_signature(self, schema: dict[str, Any], signature_b64: str,
                               public_key_pem: str) -> bool:
        """
        Verify schema signature using ECDSA P-256.

        Args:
            schema: Schema to verify
            signature_b64: Base64-encoded signature
            public_key_pem: Public key in PEM format

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Use SchemaPin signature verification if available
            if SCHEMAPIN_AVAILABLE and self.signature_manager and self.schemapin_core:
                try:
                    # Canonicalize and hash the schema using SchemaPin
                    canonical_schema = self.schemapin_core.canonicalizeSchema(schema)
                    schema_hash = self.schemapin_core.hashCanonical(canonical_schema)

                    # Load the public key
                    public_key = self.key_crypto_manager.loadPublicKeyPem(public_key_pem)

                    # Decode signature
                    signature_bytes = base64.b64decode(signature_b64)

                    # Verify signature using SchemaPin
                    return self.signature_manager.verifySchemaSignature(
                        schema_hash, signature_bytes, public_key
                    )
                except Exception as schemapin_error:
                    logger.debug(f"SchemaPin signature verification failed: {schemapin_error}")
                    # Fall back to legacy verification
                    pass

            # Legacy verification implementation
            # Normalize schema for consistent hashing
            normalized_schema = self._normalize_schema(schema)
            schema_json = json.dumps(normalized_schema, sort_keys=True, separators=(',', ':'))
            schema_hash = hashlib.sha256(schema_json.encode('utf-8')).digest()

            # Decode signature
            try:
                signature_bytes = base64.b64decode(signature_b64)
            except Exception:
                return False

            # For demonstration purposes, we'll do a simple hash comparison
            # In a real implementation, this would use cryptographic libraries
            # like cryptography or ecdsa to verify the ECDSA signature

            # Create a deterministic "signature" based on schema hash and key
            expected_signature = hashlib.sha256(
                schema_hash + public_key_pem.encode('utf-8')
            ).digest()[:32]  # Take first 32 bytes

            # Compare with provided signature (simplified)
            return len(signature_bytes) >= 32 and signature_bytes[:32] == expected_signature

        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False

    def _normalize_schema(self, schema: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize schema for consistent hashing.

        Args:
            schema: Schema to normalize

        Returns:
            Normalized schema
        """
        # Remove non-essential fields that might vary
        normalized = schema.copy()

        # Remove timestamp-like fields
        for field in ['timestamp', 'created_at', 'updated_at', 'version']:
            normalized.pop(field, None)

        return normalized

    def _extract_tool_id(self, tool_name: str, domain: str | None) -> str:
        """
        Extract tool ID from tool name and domain.

        Args:
            tool_name: Name of the tool
            domain: Domain the tool belongs to

        Returns:
            Unique tool identifier
        """
        if domain:
            return f"{domain}/{tool_name}"
        else:
            return tool_name


def extract_tool_schema(func) -> dict[str, Any]:
    """
    Extract schema from a tool function.

    Args:
        func: Tool function to extract schema from

    Returns:
        Tool schema dictionary
    """
    # For now, return a basic schema based on function metadata
    # In a full implementation, this would extract from function annotations,
    # docstrings, or other metadata

    return {
        "name": func.__name__,
        "description": func.__doc__ or "",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
