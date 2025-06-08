"""
Proxy Configuration

Configuration models and settings for the MCP proxy functionality.
Defines data structures for proxy, authentication, and plugin configurations.
"""

from typing import Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Import SchemaPin config if available
try:
    from ..schemapin.config import SchemaPinConfig
except ImportError:
    # Fallback if SchemaPin is not available
    SchemaPinConfig = None


class ProxyMode(Enum):
    """Proxy operation modes."""

    MOCK = "mock"
    PROXY = "proxy"
    HYBRID = "hybrid"


class AuthType(Enum):
    """Authentication types."""

    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer" + "_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"


@dataclass
class AuthConfig:
    """Authentication configuration."""

    auth_type: AuthType = AuthType.NONE
    credentials: dict[str, Any] = field(default_factory=dict)
    location: str = "header"  # header, query, cookie
    name: str = "Authorization"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "auth_type": self.auth_type.value,
            "credentials": self.credentials,
            "location": self.location,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthConfig":
        """Create from dictionary."""
        return cls(
            auth_type=AuthType(data.get("auth_type", "none")),
            credentials=data.get("credentials", {}),
            location=data.get("location", "header"),
            name=data.get("name", "Authorization"),
        )


@dataclass
class EndpointConfig:
    """Configuration for a single API endpoint."""

    path: str
    method: str = "GET"
    mock_response: dict[str, Any] | None = None
    proxy_url: str | None = None
    auth_config: AuthConfig | None = None
    timeout: int = 30
    retry_count: int = 3

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path": self.path,
            "method": self.method,
            "mock_response": self.mock_response,
            "proxy_url": self.proxy_url,
            "auth_config": self.auth_config.to_dict() if self.auth_config else None,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointConfig":
        """Create from dictionary."""
        auth_data = data.get("auth_config")
        auth_config = AuthConfig.from_dict(auth_data) if auth_data else None

        return cls(
            path=data["path"],
            method=data.get("method", "GET"),
            mock_response=data.get("mock_response"),
            proxy_url=data.get("proxy_url"),
            auth_config=auth_config,
            timeout=data.get("timeout", 30),
            retry_count=data.get("retry_count", 3),
        )


@dataclass
class RouteRule:
    """Routing rule for hybrid mode."""

    pattern: str
    mode: ProxyMode
    condition: str | None = None  # Python expression for conditional routing
    priority: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern": self.pattern,
            "mode": self.mode.value,
            "condition": self.condition,
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RouteRule":
        """Create from dictionary."""
        return cls(
            pattern=data["pattern"],
            mode=ProxyMode(data.get("mode", "mock")),
            condition=data.get("condition"),
            priority=data.get("priority", 0),
        )


@dataclass
class ProxyConfig:
    """
    Main proxy configuration.

    This class contains all configuration settings for the MCP proxy,
    including mode, endpoints, authentication, and routing rules.
    """

    api_name: str
    base_url: str
    mode: ProxyMode = ProxyMode.MOCK
    endpoints: list[EndpointConfig] = field(default_factory=list)
    default_auth: AuthConfig | None = None
    route_rules: list[RouteRule] = field(default_factory=list)
    timeout: int = 30
    retry_count: int = 3
    rate_limit: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    schemapin_config: Any | None = None  # SchemaPinConfig when available

    def add_endpoint(self, endpoint: EndpointConfig) -> None:
        """Add an endpoint configuration."""
        self.endpoints.append(endpoint)

    def add_route_rule(self, rule: RouteRule) -> None:
        """Add a routing rule."""
        self.route_rules.append(rule)
        # Sort by priority (higher priority first)
        self.route_rules.sort(key=lambda r: r.priority, reverse=True)

    def get_endpoint_config(
        self, path: str, method: str = "GET"
    ) -> EndpointConfig | None:
        """Get endpoint configuration by path and method."""
        for endpoint in self.endpoints:
            if endpoint.path == path and endpoint.method.upper() == method.upper():
                return endpoint
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "api_name": self.api_name,
            "base_url": self.base_url,
            "mode": self.mode.value,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "default_auth": self.default_auth.to_dict() if self.default_auth else None,
            "route_rules": [rule.to_dict() for rule in self.route_rules],
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "rate_limit": self.rate_limit,
            "headers": self.headers,
            "schemapin_config": self.schemapin_config.to_dict() if self.schemapin_config else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProxyConfig":
        """Create from dictionary."""
        endpoints = [EndpointConfig.from_dict(ep) for ep in data.get("endpoints", [])]
        route_rules = [
            RouteRule.from_dict(rule) for rule in data.get("route_rules", [])
        ]

        default_auth_data = data.get("default_auth")
        default_auth = (
            AuthConfig.from_dict(default_auth_data) if default_auth_data else None
        )

        # Handle SchemaPin config
        schemapin_config = None
        schemapin_data = data.get("schemapin_config")
        if schemapin_data and SchemaPinConfig:
            schemapin_config = SchemaPinConfig.from_dict(schemapin_data)

        return cls(
            api_name=data["api_name"],
            base_url=data["base_url"],
            mode=ProxyMode(data.get("mode", "mock")),
            endpoints=endpoints,
            default_auth=default_auth,
            route_rules=route_rules,
            timeout=data.get("timeout", 30),
            retry_count=data.get("retry_count", 3),
            rate_limit=data.get("rate_limit"),
            headers=data.get("headers", {}),
            schemapin_config=schemapin_config,
        )

    def save_to_file(self, file_path: str | Path) -> None:
        """Save configuration to JSON file."""
        import json

        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, file_path: str | Path) -> "ProxyConfig":
        """Load configuration from JSON file."""
        import json

        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)

        return cls.from_dict(data)

    def enable_schemapin_verification(self, policy_mode: str = "warn") -> None:
        """Enable SchemaPin verification with specified policy."""
        if SchemaPinConfig:
            if not self.schemapin_config:
                self.schemapin_config = SchemaPinConfig()
            self.schemapin_config.enabled = True
            self.schemapin_config.policy_mode = policy_mode

    def add_trusted_domain(self, domain: str) -> None:
        """Add domain to trusted list."""
        if SchemaPinConfig:
            if not self.schemapin_config:
                self.schemapin_config = SchemaPinConfig()
            if domain not in self.schemapin_config.trusted_domains:
                self.schemapin_config.trusted_domains.append(domain)

    def set_well_known_endpoint(self, domain: str, endpoint_url: str) -> None:
        """Set custom .well-known endpoint for domain."""
        if SchemaPinConfig:
            if not self.schemapin_config:
                self.schemapin_config = SchemaPinConfig()
            self.schemapin_config.well_known_endpoints[domain] = endpoint_url


@dataclass
class PluginConfig:
    """Configuration for MCP plugin generation."""

    plugin_name: str
    api_spec: dict[str, Any]
    proxy_config: ProxyConfig
    output_dir: Path | None = None
    mcp_server_name: str | None = None
    tools_enabled: bool = True
    resources_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plugin_name": self.plugin_name,
            "api_spec": self.api_spec,
            "proxy_config": self.proxy_config.to_dict(),
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "mcp_server_name": self.mcp_server_name,
            "tools_enabled": self.tools_enabled,
            "resources_enabled": self.resources_enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PluginConfig":
        """Create from dictionary."""
        proxy_config = ProxyConfig.from_dict(data["proxy_config"])
        output_dir = Path(data["output_dir"]) if data.get("output_dir") else None

        return cls(
            plugin_name=data["plugin_name"],
            api_spec=data["api_spec"],
            proxy_config=proxy_config,
            output_dir=output_dir,
            mcp_server_name=data.get("mcp_server_name"),
            tools_enabled=data.get("tools_enabled", True),
            resources_enabled=data.get("resources_enabled", True),
        )
