"""
SchemaPin Key Management Module

Handles Trust-On-First-Use (TOFU) key pinning and discovery.
"""

import json
import logging
import sqlite3
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

import aiohttp

try:
    from schemapin.discovery import PublicKeyDiscovery
    from schemapin.pinning import KeyPinning
    SCHEMAPIN_AVAILABLE = True
except ImportError:
    SCHEMAPIN_AVAILABLE = False

logger = logging.getLogger(__name__)


class KeyPinningManager:
    """Manages TOFU key pinning and discovery for SchemaPin."""

    def __init__(self, storage_path: str):
        """Initialize key pinning manager with storage path."""
        self.storage_path = Path(storage_path)
        self._init_storage()

        # Initialize SchemaPin components if available
        if SCHEMAPIN_AVAILABLE:
            self.public_key_discovery = PublicKeyDiscovery()
            self.key_pinning = KeyPinning(str(storage_path))
        else:
            self.public_key_discovery = None
            self.key_pinning = None

    def _init_storage(self) -> None:
        """Initialize the key pinning storage database."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.storage_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS key_pins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_id TEXT UNIQUE NOT NULL,
                    domain TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    pinned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_verified TIMESTAMP,
                    verification_count INTEGER DEFAULT 0,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_key_pins_tool_id ON key_pins(tool_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_key_pins_domain ON key_pins(domain)
            """)

            conn.commit()

    async def discover_public_key(self, domain: str, timeout: int = 30) -> str | None:
        """
        Discover public key for domain via .well-known endpoint.

        Args:
            domain: Domain to discover key for
            timeout: Request timeout in seconds

        Returns:
            Public key PEM string if found, None otherwise
        """
        # Use SchemaPin discovery if available
        if SCHEMAPIN_AVAILABLE and self.public_key_discovery:
            try:
                return await self.public_key_discovery.getPublicKeyPem(domain)
            except Exception as e:
                logger.debug(f"SchemaPin key discovery failed for {domain}: {e}")
                # Fall back to legacy implementation
                pass

        # Legacy implementation
        well_known_url = f"https://{domain}/.well-known/schemapin.json"

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(well_known_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("public_key")
        except Exception as e:
            # Silently fail discovery - this is expected for many domains
            logger.debug(f"Key discovery failed for {domain}: {e}")

        return None

    def pin_key(self, tool_id: str, domain: str, public_key_pem: str, metadata: dict[str, Any] | None = None) -> bool:
        """
        Pin a public key for a tool.

        Args:
            tool_id: Unique tool identifier
            domain: Domain the key belongs to
            public_key_pem: Public key in PEM format
            metadata: Optional metadata to store with the pin

        Returns:
            True if pinning succeeded, False otherwise
        """
        # Use SchemaPin key pinning if available
        if SCHEMAPIN_AVAILABLE and self.key_pinning:
            try:
                developer_name = metadata.get("developer_name", "") if metadata else ""
                return self.key_pinning.pinKey(tool_id, public_key_pem, domain, developer_name)
            except Exception as e:
                logger.debug(f"SchemaPin key pinning failed: {e}")
                # Fall back to legacy implementation
                pass

        # Legacy implementation
        try:
            with sqlite3.connect(str(self.storage_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO key_pins
                    (tool_id, domain, public_key_pem, pinned_at, verification_count, metadata)
                    VALUES (?, ?, ?, ?, 1, ?)
                """, (
                    tool_id,
                    domain,
                    public_key_pem,
                    datetime.now(UTC).isoformat(),
                    json.dumps(metadata) if metadata else None
                ))
                conn.commit()
                return True
        except Exception:
            return False

    def get_pinned_key(self, tool_id: str) -> str | None:
        """
        Get pinned public key for a tool.

        Args:
            tool_id: Unique tool identifier

        Returns:
            Public key PEM string if pinned, None otherwise
        """
        # Use SchemaPin key pinning if available
        if SCHEMAPIN_AVAILABLE and self.key_pinning:
            try:
                pinned_key_info = self.key_pinning.getPinnedKey(tool_id)
                return pinned_key_info.get("publicKeyPem") if pinned_key_info else None
            except Exception as e:
                logger.debug(f"SchemaPin get pinned key failed: {e}")
                # Fall back to legacy implementation
                pass

        # Legacy implementation
        try:
            with sqlite3.connect(str(self.storage_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT public_key_pem FROM key_pins WHERE tool_id = ?
                """, (tool_id,))
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception:
            return None

    def is_key_pinned(self, tool_id: str) -> bool:
        """
        Check if a key is pinned for a tool.

        Args:
            tool_id: Unique tool identifier

        Returns:
            True if key is pinned, False otherwise
        """
        return self.get_pinned_key(tool_id) is not None

    def update_verification_stats(self, tool_id: str) -> None:
        """
        Update verification statistics for a pinned key.

        Args:
            tool_id: Unique tool identifier
        """
        try:
            with sqlite3.connect(str(self.storage_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE key_pins
                    SET last_verified = ?, verification_count = verification_count + 1
                    WHERE tool_id = ?
                """, (datetime.now(UTC).isoformat(), tool_id))
                conn.commit()
        except Exception as e:
            logger.debug(f"Failed to update verification stats for {tool_id}: {e}")

    def revoke_key(self, tool_id: str) -> bool:
        """
        Revoke a pinned key.

        Args:
            tool_id: Unique tool identifier

        Returns:
            True if revocation succeeded, False otherwise
        """
        try:
            with sqlite3.connect(str(self.storage_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM key_pins WHERE tool_id = ?", (tool_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception:
            return False

    def list_pinned_keys(self) -> list[dict[str, Any]]:
        """
        List all pinned keys.

        Returns:
            List of pinned key information
        """
        try:
            with sqlite3.connect(str(self.storage_path)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT tool_id, domain, pinned_at, last_verified, verification_count
                    FROM key_pins
                    ORDER BY pinned_at DESC
                """)
                return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []

    def get_key_info(self, tool_id: str) -> dict[str, Any] | None:
        """
        Get detailed information about a pinned key.

        Args:
            tool_id: Unique tool identifier

        Returns:
            Key information dictionary if found, None otherwise
        """
        try:
            with sqlite3.connect(str(self.storage_path)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM key_pins WHERE tool_id = ?
                """, (tool_id,))
                result = cursor.fetchone()
                if result:
                    data = dict(result)
                    if data.get("metadata"):
                        data["metadata"] = json.loads(data["metadata"])
                    return data
                return None
        except Exception:
            return None
