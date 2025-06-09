# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Example demonstrating the create_mcp_plugin tool with PROXY and HYBRID modes.

This script shows how to use the `create_mcp_plugin` tool from `mockloop_mcp.mcp_tools`
to create MCP plugins configured for 'proxy' and 'hybrid' modes.

For a 'mock' mode example, please see `basic-mock-example.py`.
"""

import asyncio
import json
from mockloop_mcp.mcp_tools import create_mcp_plugin

# A publicly available OpenAPI specification for demonstration purposes
PETSTORE_SPEC_URL = "https://petstore.swagger.io/v2/swagger.json"
PETSTORE_TARGET_URL = "https://petstore.swagger.io/v2"


async def main():
    """
    Demonstrates creating MCP plugins in PROXY and HYBRID modes.
    """
    print("Demonstrating MCP Plugin Creation for PROXY and HYBRID Modes\n")

    # --- 1. Create a plugin in PROXY mode ---
    # Proxy mode requires a target_url and potentially auth_config.
    # For Petstore, authentication might not be strictly required for all endpoints,
    # but we'll include a placeholder auth_config.
    print("Attempting to create a plugin in PROXY mode...")
    try:
        proxy_auth_config = {
            "auth_type": "api_key",  # Example: Petstore uses API key in header
            "credentials": {
                "api_key": "YOUR_PETSTORE_API_KEY"
            },  # Replace with a real key if needed
            "location": "header",
            "name": "api_key",
        }
        proxy_plugin_result = await create_mcp_plugin(
            spec_url_or_path=PETSTORE_SPEC_URL,
            plugin_name="petstore_proxy_plugin",
            mode="proxy",  # Explicitly set to proxy mode
            target_url=PETSTORE_TARGET_URL,  # Required for proxy mode
            auth_config=proxy_auth_config,
            auto_register=False,
        )
        print("PROXY mode plugin creation result:")
        print(json.dumps(proxy_plugin_result, indent=2))
        print("-" * 50)
    except Exception as e:
        print(f"Error creating PROXY mode plugin: {e}")
        print("-" * 50)

    # --- 2. Create a plugin in HYBRID mode ---
    # Hybrid mode also requires a target_url and can use auth_config.
    # It combines mock and proxy capabilities.
    print("\nAttempting to create a plugin in HYBRID mode...")
    try:
        hybrid_auth_config = {
            "auth_type": "api_key",
            "credentials": {"api_key": "YOUR_PETSTORE_API_KEY_HYBRID"},
            "location": "header",
            "name": "special_api_key",  # Potentially different for hybrid scenarios
        }
        hybrid_plugin_result = await create_mcp_plugin(
            spec_url_or_path=PETSTORE_SPEC_URL,
            plugin_name="petstore_hybrid_plugin",
            mode="hybrid",  # Explicitly set to hybrid mode
            target_url=PETSTORE_TARGET_URL,  # Required for hybrid mode
            auth_config=hybrid_auth_config,
            auto_register=False,
        )
        print("HYBRID mode plugin creation result:")
        print(json.dumps(hybrid_plugin_result, indent=2))
        print("-" * 50)
    except Exception as e:
        print(f"Error creating HYBRID mode plugin: {e}")
        print("-" * 50)

    print("\nPlugin creation demonstration finished.")


if __name__ == "__main__":
    asyncio.run(main())
