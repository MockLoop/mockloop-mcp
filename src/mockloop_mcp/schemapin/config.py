"""
SchemaPin Configuration Module

Defines configuration classes and data structures for SchemaPin integration.
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyAction(Enum):
    """Policy enforcement actions."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    PROMPT = "prompt"


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    action: PolicyAction
    reason: str
    policy_mode: str


@dataclass
class VerificationResult:
    """Result of schema verification."""
    valid: bool
    tool_id: str
    domain: str | None = None
    key_pinned: bool = False
    error: str | None = None
    signature: str | None = None
    public_key: str | None = None
    timestamp: float | None = None


@dataclass
class SchemaPinConfig:
    """SchemaPin configuration for MockLoop integration."""

    enabled: bool = True
    policy_mode: str = "warn"  # enforce, warn, log
    auto_pin_keys: bool = False
    key_pin_storage_path: str = "schemapin_keys.db"
    discovery_timeout: int = 30
    cache_ttl: int = 3600
    well_known_endpoints: dict[str, str] = field(default_factory=dict)
    trusted_domains: list[str] = field(default_factory=list)
    revocation_check: bool = True
    interactive_mode: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "enabled": self.enabled,
            "policy_mode": self.policy_mode,
            "auto_pin_keys": self.auto_pin_keys,
            "key_pin_storage_path": self.key_pin_storage_path,
            "discovery_timeout": self.discovery_timeout,
            "cache_ttl": self.cache_ttl,
            "well_known_endpoints": self.well_known_endpoints,
            "trusted_domains": self.trusted_domains,
            "revocation_check": self.revocation_check,
            "interactive_mode": self.interactive_mode,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SchemaPinConfig":
        """Create configuration from dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            policy_mode=data.get("policy_mode", "warn"),
            auto_pin_keys=data.get("auto_pin_keys", False),
            key_pin_storage_path=data.get("key_pin_storage_path", "schemapin_keys.db"),
            discovery_timeout=data.get("discovery_timeout", 30),
            cache_ttl=data.get("cache_ttl", 3600),
            well_known_endpoints=data.get("well_known_endpoints", {}),
            trusted_domains=data.get("trusted_domains", []),
            revocation_check=data.get("revocation_check", True),
            interactive_mode=data.get("interactive_mode", True),
        )

    def save_to_file(self, file_path: str) -> None:
        """Save configuration to JSON file."""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, file_path: str) -> "SchemaPinConfig":
        """Load configuration from JSON file."""
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


class _ConfigManager:
    """Internal configuration manager."""

    def __init__(self) -> None:
        self._config: SchemaPinConfig | None = None

    def get_config(self) -> SchemaPinConfig:
        """Get the global SchemaPin configuration."""
        if self._config is None:
            self._config = SchemaPinConfig()
        return self._config

    def set_config(self, config: SchemaPinConfig) -> None:
        """Set the global SchemaPin configuration."""
        self._config = config


# Global configuration manager instance
_config_manager = _ConfigManager()


def get_schemapin_config() -> SchemaPinConfig:
    """Get the global SchemaPin configuration."""
    return _config_manager.get_config()


def set_schemapin_config(config: SchemaPinConfig) -> None:
    """Set the global SchemaPin configuration."""
    _config_manager.set_config(config)


class SchemaVerificationError(Exception):
    """Exception raised when schema verification fails."""
    pass
