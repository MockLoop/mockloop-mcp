"""
SchemaPin Signing Module

Core schema signing implementation for generating cryptographic signatures
compatible with the SchemaPin verification system.
"""

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    from schemapin.core import SchemaPinCore
    from schemapin.crypto import KeyManager, SignatureManager
    SCHEMAPIN_AVAILABLE = True
except ImportError:
    SCHEMAPIN_AVAILABLE = False

logger = logging.getLogger(__name__)


class SchemaSigner:
    """
    Handles ECDSA P-256 signature generation for schema verification.

    This class provides schema canonicalization, hashing, and signing
    capabilities that are compatible with the SchemaPin verification system.
    """

    def __init__(self, private_key_path: str | None = None, private_key_content: str | None = None):
        """
        Initialize schema signer with private key.

        Args:
            private_key_path: Path to PEM private key file
            private_key_content: Direct PEM private key content

        Raises:
            ValueError: If neither or both key sources are provided
            FileNotFoundError: If key file doesn't exist
            ValueError: If key cannot be loaded
        """
        if not private_key_path and not private_key_content:
            raise ValueError("Either private_key_path or private_key_content must be provided")

        if private_key_path and private_key_content:
            raise ValueError("Only one of private_key_path or private_key_content should be provided")

        # Initialize SchemaPin components if available
        if SCHEMAPIN_AVAILABLE:
            self.schemapin_core = SchemaPinCore()
            self.signature_manager = SignatureManager()
            self.key_crypto_manager = KeyManager()
        else:
            self.schemapin_core = None
            self.signature_manager = None
            self.key_crypto_manager = None

        # Load private key
        self.private_key = self._load_private_key(private_key_path, private_key_content)

    def _load_private_key(self, key_path: str | None, key_content: str | None):
        """
        Load private key from file or content.

        Args:
            key_path: Path to PEM private key file
            key_content: Direct PEM private key content

        Returns:
            Loaded private key object

        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key cannot be loaded
        """
        try:
            if key_path:
                key_file = Path(key_path)
                if not key_file.exists():
                    raise FileNotFoundError(f"Private key file not found: {key_path}")

                with open(key_file, 'rb') as f:
                    key_data = f.read()
            else:
                key_data = key_content.encode('utf-8')

            # Try SchemaPin key loading first
            if SCHEMAPIN_AVAILABLE and self.key_crypto_manager:
                try:
                    return self.key_crypto_manager.loadPrivateKeyPem(key_data.decode('utf-8'))
                except Exception as e:
                    logger.debug(f"SchemaPin key loading failed: {e}")
                    # Fall back to cryptography library

            # Use cryptography library as fallback
            if CRYPTOGRAPHY_AVAILABLE:
                return serialization.load_pem_private_key(key_data, password=None)
            else:
                raise ValueError("Neither SchemaPin nor cryptography library available for key loading")

        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}") from e

    def canonicalize_schema(self, schema: dict[str, Any]) -> str:
        """
        Canonicalize schema for consistent hashing.

        This method ensures the schema is normalized in the same way
        as the verification system for signature compatibility.

        Args:
            schema: Schema dictionary to canonicalize

        Returns:
            Canonical JSON string representation
        """
        # Use SchemaPin canonicalization if available
        if SCHEMAPIN_AVAILABLE and self.schemapin_core:
            try:
                return self.schemapin_core.canonicalizeSchema(schema)
            except Exception as e:
                logger.debug(f"SchemaPin canonicalization failed: {e}")
                # Fall back to legacy implementation

        # Legacy canonicalization (matches verification.py)
        normalized_schema = self._normalize_schema(schema)
        return json.dumps(normalized_schema, sort_keys=True, separators=(',', ':'))

    def _normalize_schema(self, schema: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize schema for consistent hashing (legacy implementation).

        Args:
            schema: Schema to normalize

        Returns:
            Normalized schema
        """
        # Remove non-essential fields that might vary (matches verification.py)
        normalized = schema.copy()

        # Remove timestamp-like fields
        for field in ['timestamp', 'created_at', 'updated_at', 'version']:
            normalized.pop(field, None)

        return normalized

    def hash_schema(self, canonical_schema: str) -> bytes:
        """
        Hash canonical schema representation.

        Args:
            canonical_schema: Canonical JSON string

        Returns:
            SHA-256 hash bytes
        """
        # Use SchemaPin hashing if available
        if SCHEMAPIN_AVAILABLE and self.schemapin_core:
            try:
                return self.schemapin_core.hashCanonical(canonical_schema)
            except Exception as e:
                logger.debug(f"SchemaPin hashing failed: {e}")
                # Fall back to legacy implementation

        # Legacy hashing (matches verification.py)
        return hashlib.sha256(canonical_schema.encode('utf-8')).digest()

    def sign_schema(self, schema: dict[str, Any]) -> str:
        """
        Sign a schema and return base64-encoded signature.

        Args:
            schema: Schema dictionary to sign

        Returns:
            Base64-encoded signature string

        Raises:
            ValueError: If signing fails
        """
        try:
            # Canonicalize and hash schema
            canonical_schema = self.canonicalize_schema(schema)
            schema_hash = self.hash_schema(canonical_schema)

            # Generate signature
            signature_bytes = self._sign_hash(schema_hash)

            # Return base64-encoded signature
            return base64.b64encode(signature_bytes).decode('utf-8')

        except Exception as e:
            raise ValueError(f"Schema signing failed: {e}") from e

    def _sign_hash(self, schema_hash: bytes) -> bytes:
        """
        Sign schema hash using ECDSA P-256.

        Args:
            schema_hash: Hash bytes to sign

        Returns:
            Signature bytes

        Raises:
            ValueError: If signing fails
        """
        try:
            # Use SchemaPin signing if available
            if SCHEMAPIN_AVAILABLE and self.signature_manager:
                try:
                    return self.signature_manager.signSchemaHash(schema_hash, self.private_key)
                except Exception as e:
                    logger.debug(f"SchemaPin signing failed: {e}")
                    # Fall back to cryptography library

            # Use cryptography library as fallback
            if CRYPTOGRAPHY_AVAILABLE:
                signature = self.private_key.sign(schema_hash, ec.ECDSA(hashes.SHA256()))
                return signature
            else:
                # Legacy fallback for demonstration (matches verification.py logic)
                # In production, this should use proper ECDSA signing
                logger.warning("Using legacy signing - not cryptographically secure")

                # Get public key for deterministic signature generation
                public_key_pem = self.get_public_key_pem()

                # Create deterministic signature (matches verification.py expectation)
                expected_signature = hashlib.sha256(
                    schema_hash + public_key_pem.encode('utf-8')
                ).digest()[:32]  # Take first 32 bytes

                return expected_signature

        except Exception as e:
            raise ValueError(f"Hash signing failed: {e}") from e

    def get_public_key_pem(self) -> str:
        """
        Get the corresponding public key in PEM format.

        Returns:
            Public key PEM string

        Raises:
            ValueError: If public key extraction fails
        """
        try:
            # Use SchemaPin key extraction if available
            if SCHEMAPIN_AVAILABLE and self.key_crypto_manager:
                try:
                    return self.key_crypto_manager.getPublicKeyPem(self.private_key)
                except Exception as e:
                    logger.debug(f"SchemaPin public key extraction failed: {e}")
                    # Fall back to cryptography library

            # Use cryptography library as fallback
            if CRYPTOGRAPHY_AVAILABLE:
                public_key = self.private_key.public_key()
                pem_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return pem_bytes.decode('utf-8')
            else:
                # For legacy fallback, return a placeholder
                logger.warning("Using legacy public key extraction")
                return "-----BEGIN PUBLIC KEY-----\nLEGACY_KEY_PLACEHOLDER\n-----END PUBLIC KEY-----"

        except Exception as e:
            raise ValueError(f"Public key extraction failed: {e}") from e

    def verify_own_signature(self, schema: dict[str, Any], signature: str) -> bool:
        """
        Verify a signature generated by this signer (for testing).

        Args:
            schema: Schema that was signed
            signature: Base64-encoded signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Get public key and use verification logic
            public_key_pem = self.get_public_key_pem()

            # Use the same verification logic as in verification.py
            canonical_schema = self.canonicalize_schema(schema)
            schema_hash = self.hash_schema(canonical_schema)

            # Decode signature
            signature_bytes = base64.b64decode(signature)

            # Use SchemaPin verification if available
            if SCHEMAPIN_AVAILABLE and self.signature_manager and self.key_crypto_manager:
                try:
                    public_key = self.key_crypto_manager.loadPublicKeyPem(public_key_pem)
                    return self.signature_manager.verifySchemaSignature(
                        schema_hash, signature_bytes, public_key
                    )
                except Exception as e:
                    logger.debug(f"SchemaPin verification failed: {e}")
                    # Fall back to legacy verification

            # Legacy verification (matches verification.py)
            if CRYPTOGRAPHY_AVAILABLE:
                public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                try:
                    public_key.verify(signature_bytes, schema_hash, ec.ECDSA(hashes.SHA256()))
                    return True
                except Exception:
                    return False
            else:
                # Legacy fallback verification
                expected_signature = hashlib.sha256(
                    schema_hash + public_key_pem.encode('utf-8')
                ).digest()[:32]

                return len(signature_bytes) >= 32 and signature_bytes[:32] == expected_signature

        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False

    @classmethod
    def generate_key_pair(cls) -> tuple[str, str]:
        """
        Generate a new ECDSA P-256 key pair.

        Returns:
            Tuple of (private_key_pem, public_key_pem)

        Raises:
            ValueError: If key generation fails
        """
        try:
            # Use SchemaPin key generation if available
            if SCHEMAPIN_AVAILABLE:
                try:
                    key_manager = KeyManager()
                    key_pair = key_manager.generateKeyPair()
                    return key_pair["privateKeyPem"], key_pair["publicKeyPem"]
                except Exception as e:
                    logger.debug(f"SchemaPin key generation failed: {e}")
                    # Fall back to cryptography library

            # Use cryptography library as fallback
            if CRYPTOGRAPHY_AVAILABLE:
                private_key = ec.generate_private_key(ec.SECP256R1())

                private_pem = private_key.private_key_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')

                public_key = private_key.public_key()
                public_pem = public_key.public_key_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')

                return private_pem, public_pem
            else:
                raise ValueError("Neither SchemaPin nor cryptography library available for key generation")

        except Exception as e:
            raise ValueError(f"Key pair generation failed: {e}") from e


def create_signer_from_file(private_key_path: str) -> SchemaSigner:
    """
    Create a SchemaSigner from a private key file.

    Args:
        private_key_path: Path to PEM private key file

    Returns:
        Configured SchemaSigner instance

    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key cannot be loaded
    """
    return SchemaSigner(private_key_path=private_key_path)


def create_signer_from_content(private_key_content: str) -> SchemaSigner:
    """
    Create a SchemaSigner from private key content.

    Args:
        private_key_content: PEM private key content string

    Returns:
        Configured SchemaSigner instance

    Raises:
        ValueError: If key cannot be loaded
    """
    return SchemaSigner(private_key_content=private_key_content)
