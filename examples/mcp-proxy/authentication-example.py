# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
Authentication Example

This example demonstrates various authentication scenarios with the MCP proxy,
including API keys, Bearer tokens, Basic auth, and OAuth2 flows.
"""

import asyncio
import json
from pathlib import Path

# MockLoop MCP imports
from mockloop_mcp.mcp_tools import create_mcp_plugin, execute_test_plan


async def main():
    """Demonstrate various authentication scenarios with MCP proxy."""

    print("🔐 Authentication Example - MCP Proxy Authentication Scenarios")
    print("=" * 65)

    # Sample API specification with security schemes
    api_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Secure API",
            "version": "1.0.0",
            "description": "API demonstrating various authentication methods",
        },
        "servers": [
            {
                "url": "https://api.secure-example.com",
                "description": "Production server",
            }
        ],
        "paths": {
            "/public/status": {
                "get": {
                    "summary": "Public status endpoint",
                    "description": "No authentication required",
                    "responses": {
                        "200": {
                            "description": "Service status",
                            "content": {
                                "application/json": {
                                    "example": {"status": "healthy", "version": "1.0.0"}
                                }
                            },
                        }
                    },
                }
            },
            "/api/users": {
                "get": {
                    "summary": "List users (API Key required)",
                    "security": [{"ApiKeyAuth": []}],
                    "responses": {
                        "200": {
                            "description": "List of users",
                            "content": {
                                "application/json": {
                                    "example": [
                                        {"id": 1, "name": "John Doe", "role": "admin"},
                                        {"id": 2, "name": "Jane Smith", "role": "user"},
                                    ]
                                }
                            },
                        },
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
            "/api/profile": {
                "get": {
                    "summary": "Get user profile (Bearer token required)",
                    "security": [{"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "User profile",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "id": 1,
                                        "name": "John Doe",
                                        "email": "john@example.com",
                                        "preferences": {
                                            "theme": "dark",
                                            "notifications": True,
                                        },
                                    }
                                }
                            },
                        },
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
            "/admin/settings": {
                "get": {
                    "summary": "Admin settings (Basic auth required)",
                    "security": [{"BasicAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Admin settings",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "maintenance_mode": False,
                                        "max_users": 1000,
                                        "features": ["analytics", "reporting"],
                                    }
                                }
                            },
                        },
                        "401": {"description": "Unauthorized"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/oauth/userinfo": {
                "get": {
                    "summary": "OAuth2 user info",
                    "security": [{"OAuth2": ["read:user"]}],
                    "responses": {
                        "200": {
                            "description": "OAuth2 user information",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "sub": "user123",
                                        "name": "John Doe",
                                        "email": "john@example.com",
                                        "scope": ["read:user", "write:profile"],
                                    }
                                }
                            },
                        },
                        "401": {"description": "Invalid token"},
                    },
                }
            },
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key authentication",
                },
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Bearer token authentication",
                },
                "BasicAuth": {
                    "type": "http",
                    "scheme": "basic",
                    "description": "Basic HTTP authentication",
                },
                "OAuth2": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://api.secure-example.com/oauth/authorize",
                            "tokenUrl": "https://api.secure-example.com/oauth/token",
                            "scopes": {
                                "read:user": "Read user information",
                                "write:profile": "Update user profile",
                            },
                        }
                    },
                },
            }
        },
    }

    # Authentication configurations for different scenarios
    auth_configs = {
        "api_key": {
            "auth_type": "api_key",
            "credentials": {"api_key": "sk-test-api-key-12345"},
            "location": "header",
            "name": "X-API-Key",
        },
        "bearer_token": {
            "auth_type": "bearer_token",
            "credentials": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test-jwt-token"
            },
        },
        "basic_auth": {
            "auth_type": "basic_auth",
            "credentials": {"username": "admin", "password": "secure-password-123"},
        },
        "oauth2": {
            "auth_type": "oauth2",
            "credentials": {
                "access_token": "ya29.test-oauth2-access-token",
                "refresh_token": "1//test-refresh-token",
                "client_id": "test-client-id.apps.googleusercontent.com",
                "client_secret": "test-client-secret",
            },
        },
    }

    # Scenario 1: API Key Authentication
    print("🔑 Scenario 1: API Key Authentication")
    print("-" * 40)

    try:
        api_key_plugin = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),
            mode="mock",  # Start with mock for demonstration
            plugin_name="secure_api_key",
            target_url="https://api.secure-example.com",
            auth_config=auth_configs["api_key"],
            proxy_config=None,
        )

        print(f"✅ API Key plugin created: {api_key_plugin.get('plugin_id', 'N/A')}")
        print(
            f"   Auth type: {api_key_plugin.get('auth_config', {}).get('auth_type', 'N/A')}"
        )
        print(
            f"   Key location: {api_key_plugin.get('auth_config', {}).get('location', 'N/A')}"
        )

    except Exception as e:
        print(f"❌ API Key plugin creation failed: {e}")

    # Scenario 2: Bearer Token Authentication
    print("\n🎫 Scenario 2: Bearer Token Authentication")
    print("-" * 45)

    try:
        bearer_plugin = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),
            mode="proxy",  # Use proxy mode to demonstrate real auth
            plugin_name="secure_api_bearer",
            target_url="https://api.secure-example.com",
            auth_config=auth_configs["bearer_token"],
            proxy_config=None,
        )

        print(
            f"✅ Bearer token plugin created: {bearer_plugin.get('plugin_id', 'N/A')}"
        )
        print(
            f"   Auth type: {bearer_plugin.get('auth_config', {}).get('auth_type', 'N/A')}"
        )
        print("   Token format: JWT")

    except Exception as e:
        print(f"❌ Bearer token plugin creation failed: {e}")

    # Scenario 3: Basic Authentication
    print("\n🔒 Scenario 3: Basic Authentication")
    print("-" * 35)

    try:
        basic_plugin = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),
            mode="hybrid",  # Use hybrid mode for admin endpoints
            plugin_name="secure_api_basic",
            target_url="https://api.secure-example.com",
            auth_config=auth_configs["basic_auth"],
            proxy_config={
                "route_rules": [
                    {"pattern": "/admin/*", "mode": "proxy", "priority": 10},
                    {"pattern": "/public/*", "mode": "mock", "priority": 5},
                ]
            },
        )

        print(f"✅ Basic auth plugin created: {basic_plugin.get('plugin_id', 'N/A')}")
        print(
            f"   Auth type: {basic_plugin.get('auth_config', {}).get('auth_type', 'N/A')}"
        )
        print(
            f"   Username: {basic_plugin.get('auth_config', {}).get('credentials', {}).get('username', 'N/A')}"
        )

    except Exception as e:
        print(f"❌ Basic auth plugin creation failed: {e}")

    # Scenario 4: OAuth2 Authentication
    print("\n🌐 Scenario 4: OAuth2 Authentication")
    print("-" * 35)

    try:
        oauth2_plugin = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),
            mode="proxy",
            plugin_name="secure_api_oauth2",
            target_url="https://api.secure-example.com",
            auth_config=auth_configs["oauth2"],
            proxy_config=None,
        )

        print(f"✅ OAuth2 plugin created: {oauth2_plugin.get('plugin_id', 'N/A')}")
        print(
            f"   Auth type: {oauth2_plugin.get('auth_config', {}).get('auth_type', 'N/A')}"
        )
        print(
            f"   Has refresh token: {'Yes' if 'refresh_token' in auth_configs['oauth2']['credentials'] else 'No'}"
        )

    except Exception as e:
        print(f"❌ OAuth2 plugin creation failed: {e}")

    # Scenario 5: Multi-Auth Testing
    print("\n🔄 Scenario 5: Multi-Authentication Testing")
    print("-" * 45)

    try:
        # Test with different auth methods
        test_results = await execute_test_plan(
            openapi_spec=api_spec,
            server_url="http://localhost:8000",
            test_focus="security",
            mode="mock",  # Use mock mode for demonstration
            validation_mode="strict",
            auto_generate_scenarios=True,
            execute_immediately=True,
        )

        print("✅ Multi-auth testing completed!")
        print(f"   Total tests: {test_results.get('total_tests', 0)}")
        print(f"   Security tests: {test_results.get('security_tests', 0)}")
        print(f"   Auth scenarios: {test_results.get('auth_scenarios', 0)}")

    except Exception as e:
        print(f"❌ Multi-auth testing failed: {e}")

    # Scenario 6: Authentication Error Handling
    print("\n⚠️  Scenario 6: Authentication Error Handling")
    print("-" * 45)

    # Test with invalid credentials
    invalid_auth_configs = {
        "invalid_api_key": {
            "auth_type": "api_key",
            "credentials": {"api_key": "invalid-key"},
            "location": "header",
            "name": "X-API-Key",
        },
        "expired_token": {
            "auth_type": "bearer_token",
            "credentials": {"token": "expired.jwt.token"},
        },
    }

    for auth_name, auth_config in invalid_auth_configs.items():
        try:
            await create_mcp_plugin(
                spec_url_or_path=json.dumps(api_spec),
                mode="mock",
                plugin_name=f"test_{auth_name}",
                target_url="https://api.secure-example.com",
                auth_config=auth_config,
                proxy_config=None,
            )
            print(f"⚠️  {auth_name} plugin created (will fail on real requests)")

        except Exception as e:
            print(f"❌ {auth_name} plugin creation failed: {e}")

    # Best Practices Summary
    print("\n📋 Authentication Best Practices")
    print("-" * 35)
    print("✅ Store credentials securely (environment variables)")
    print("✅ Use appropriate auth method for each endpoint")
    print("✅ Implement token refresh for OAuth2")
    print("✅ Handle authentication errors gracefully")
    print("✅ Test with both valid and invalid credentials")
    print("✅ Use HTTPS for all authenticated requests")
    print("✅ Implement rate limiting and retry logic")
    print("✅ Log authentication events for security monitoring")

    # Environment Variable Examples
    print("\n🔧 Environment Variable Configuration")
    print("-" * 40)
    print("# API Key Authentication")
    print("export API_KEY='your-api-key-here'")
    print("export API_KEY_HEADER='X-API-Key'")
    print("")
    print("# Bearer Token Authentication")
    print("export BEARER_TOKEN='your-jwt-token-here'")
    print("")
    print("# Basic Authentication")
    print("export BASIC_AUTH_USERNAME='your-username'")
    print("export BASIC_AUTH_PASSWORD='your-password'")
    print("")
    print("# OAuth2 Authentication")
    print("export OAUTH2_CLIENT_ID='your-client-id'")
    print("export OAUTH2_CLIENT_SECRET='your-client-secret'")
    print("export OAUTH2_ACCESS_TOKEN='your-access-token'")
    print("export OAUTH2_REFRESH_TOKEN='your-refresh-token'")

    # Code Example for Environment Variables
    print("\n💻 Code Example: Using Environment Variables")
    print("-" * 50)
    print("""
import os
from mockloop_mcp.mcp_tools import create_mcp_plugin

# Load auth config from environment
auth_config = {
    "auth_type": "api_key",
    "credentials": {
        "api_key": os.getenv("API_KEY", "default-key")
    },
    "location": "header",
    "name": os.getenv("API_KEY_HEADER", "X-API-Key")
}

# Create plugin with environment-based auth
plugin = await create_mcp_plugin(
    spec_url_or_path="api-spec.json",
    mode="proxy",
    plugin_name="secure_api",
    target_url=os.getenv("API_BASE_URL"),
    auth_config=auth_config
)
""")

    print("\n✨ Next Steps:")
    print("   1. Set up environment variables for your API credentials")
    print("   2. Test authentication with your actual API endpoints")
    print("   3. Implement error handling and retry logic")
    print("   4. Monitor authentication events and failures")
    print("   5. Consider implementing credential rotation")


if __name__ == "__main__":
    asyncio.run(main())
