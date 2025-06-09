# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Example demonstrating HYBRID mode with routing rules.

This script shows how to:
1. Define a simple OpenAPI specification with distinct endpoints.
2. Create an MCP plugin in 'hybrid' mode.
3. Configure routing rules within the `proxy_config` to direct:
    - Requests to one path to 'mock' mode.
    - Requests to another path to 'proxy' mode (e.g., JSONPlaceholder).
4. Briefly discuss how `execute_test_plan` would interact with this.
"""

import asyncio
import json
from mockloop_mcp.mcp_tools import create_mcp_plugin
from mockloop_mcp.proxy.config import RouteRule, ProxyMode as PM

# --- 1. Define a simple OpenAPI Specification ---
HYBRID_API_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Hybrid Test API", "version": "1.0.0"},
    "servers": [{"url": "http://localhost:8000"}],  # Mock server base
    "paths": {
        "/mocked/data": {
            "get": {
                "summary": "Get mocked data",
                "operationId": "getMockedData",
                "responses": {
                    "200": {
                        "description": "Successful mock operation",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "message": {"type": "string"},
                                        "source": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/proxied/todos/{todoId}": {
            "get": {
                "summary": "Get a specific todo item via proxy",
                "operationId": "getProxiedTodoById",
                "parameters": [
                    {
                        "name": "todoId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {"description": "Successful proxy operation"},
                    "404": {"description": "Todo not found via proxy"},
                },
            }
        },
    },
}

JSONPLACEHOLDER_TARGET_URL = "https://jsonplaceholder.typicode.com"


async def main():
    """
    Demonstrates creating a HYBRID mode plugin with routing rules.
    """
    print("Demonstrating HYBRID mode plugin with routing rules\n")

    # --- 2. Define Proxy Configuration with Routing Rules ---
    # Rule 1: Route /mocked/data to MOCK mode
    mock_rule = RouteRule(
        pattern="/mocked/data",  # Path pattern to match
        mode=PM.MOCK,  # Target mode for this pattern
        priority=10,  # Higher priority rules are checked first
    )

    # Rule 2: Route /proxied/todos/* to PROXY mode
    proxy_rule = RouteRule(
        pattern="/proxied/todos/*",  # Path pattern with wildcard
        mode=PM.PROXY,  # Target mode for this pattern
        priority=5,
    )

    # The `proxy_config` parameter in `create_mcp_plugin` is used to pass these.
    # Note: `create_mcp_plugin` expects `proxy_config` as a dict.
    # The `ProxyConfig` object itself is used internally by `create_mcp_plugin`.
    # We construct the dictionary representation for `route_rules`.
    custom_proxy_config_dict = {
        "api_name": "hybrid_api_example",
        "base_url": JSONPLACEHOLDER_TARGET_URL,  # Default base for proxied requests
        "mode": "hybrid",  # Overall mode for the plugin
        "route_rules": [mock_rule.to_dict(), proxy_rule.to_dict()],
        # No default_auth needed for JSONPlaceholder GET, but can be added
    }

    # --- 3. Create an MCP plugin in HYBRID mode with these rules ---
    print("Attempting to create a HYBRID mode plugin with custom routing...")
    try:
        hybrid_plugin_result = await create_mcp_plugin(
            spec_url_or_path=json.dumps(HYBRID_API_SPEC),
            plugin_name="hybrid_routing_plugin",
            mode="hybrid",  # This sets the default behavior if no rules match
            target_url=JSONPLACEHOLDER_TARGET_URL,  # Base for proxied requests
            proxy_config=custom_proxy_config_dict,  # Pass the dict with route_rules
            auto_register=False,
        )
        print("HYBRID mode plugin creation result:")
        print(json.dumps(hybrid_plugin_result, indent=2))
        print("-" * 50)

        if hybrid_plugin_result.get("status") == "success":
            print("\nPlugin configured for HYBRID mode with routing rules:")
            print("- Requests to '/mocked/data' should be handled by MOCK logic.")
            print(
                f"- Requests to '/proxied/todos/*' should be PROXIED to {JSONPLACEHOLDER_TARGET_URL}."
            )
        else:
            print("Failed to create hybrid plugin.")

    except Exception as e:
        print(f"Error creating HYBRID mode plugin: {e}")
        print("-" * 50)

    # --- 4. Discussion: Executing a Test Plan ---
    print("\n--- How execute_test_plan would interact ---")
    print(
        "If `execute_test_plan` were run against a MockLoop server hosting this 'hybrid_routing_plugin':"
    )
    print("- It would use the HYBRID_API_SPEC to generate requests.")
    print(
        "- When a request for '/mocked/data' is made, the MockLoop server (using the plugin's routing rules)"
    )
    print("  would internally direct it to its MOCK handler.")
    print(
        "- When a request for '/proxied/todos/1' is made, the MockLoop server would PROXY it to"
    )
    print(
        f"  {JSONPLACEHOLDER_TARGET_URL}/todos/1 based on the '/proxied/todos/*' rule."
    )
    print(
        "The `mode` parameter in `execute_test_plan` itself (e.g., 'auto', 'mock', 'proxy')"
    )
    print(
        "influences how `execute_test_plan` *interprets* the target server, but the actual routing"
    )
    print(
        "for a hybrid plugin is determined by the plugin's own configuration on the MockLoop server."
    )
    print("-" * 50)

    print("\nHybrid mode routing demonstration finished.")


if __name__ == "__main__":
    asyncio.run(main())
