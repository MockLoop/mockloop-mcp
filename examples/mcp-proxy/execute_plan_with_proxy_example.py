# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Example demonstrating execute_test_plan with a plugin in PROXY mode.

This script shows how to:
1. Define a simple OpenAPI specification.
2. Create an MCP plugin in 'proxy' mode targeting a public API (JSONPlaceholder).
3. Use `execute_test_plan` to send requests through the proxy to the live API.
"""

import asyncio
import json
from mockloop_mcp.mcp_tools import create_mcp_plugin, execute_test_plan

# --- 1. Define a simple OpenAPI Specification (inline for this example) ---
# This spec describes a subset of JSONPlaceholder's /todos endpoint.
SIMPLE_API_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Simple Todo API", "version": "1.0.0"},
    "servers": [{"url": "https://jsonplaceholder.typicode.com"}],
    "paths": {
        "/todos/{todoId}": {
            "get": {
                "summary": "Get a specific todo item",
                "operationId": "getTodoById",
                "parameters": [
                    {
                        "name": "todoId",
                        "in": "path",
                        "required": True,
                        "description": "ID of the todo to retrieve",
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successful operation",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "userId": {"type": "integer"},
                                        "id": {"type": "integer"},
                                        "title": {"type": "string"},
                                        "completed": {"type": "boolean"},
                                    },
                                }
                            }
                        },
                    },
                    "404": {"description": "Todo not found"},
                },
            }
        }
    },
}

JSONPLACEHOLDER_TARGET_URL = "https://jsonplaceholder.typicode.com"


async def main():
    """
    Demonstrates creating a proxy plugin and executing a test plan against it.
    """
    print("Demonstrating execute_test_plan with a PROXY mode plugin\n")

    # --- 2. Create an MCP plugin in PROXY mode ---
    # This plugin will proxy requests to JSONPlaceholder.
    # JSONPlaceholder does not require authentication for GET requests.
    print("Attempting to create a PROXY mode plugin for JSONPlaceholder...")
    try:
        proxy_plugin_result = await create_mcp_plugin(
            spec_url_or_path=json.dumps(SIMPLE_API_SPEC),  # Pass spec as JSON string
            plugin_name="jsonplaceholder_proxy_plugin",
            mode="proxy",
            target_url=JSONPLACEHOLDER_TARGET_URL,
            # No auth_config needed for JSONPlaceholder GET requests
            auto_register=False,  # For demonstration
        )
        print("PROXY mode plugin creation result:")
        print(json.dumps(proxy_plugin_result, indent=2))
        print("-" * 50)

        if proxy_plugin_result.get("status") != "success":
            print("Failed to create proxy plugin. Aborting test plan execution.")
            return

    except Exception as e:
        print(f"Error creating PROXY mode plugin: {e}")
        print("-" * 50)
        return

    # --- 3. Execute a test plan using the PROXY mode plugin ---
    # The `server_url` for `execute_test_plan` in this context would typically be
    # the URL where the MockLoop MCP (which hosts the plugin) is running.
    # Since we are demonstrating the tool's capability to *configure* a proxy,
    # and not necessarily running a full MockLoop instance here, we'll use the
    # target_url directly for the `execute_test_plan` for simplicity in this example.
    # In a real scenario, `server_url` would point to your MockLoop instance.
    #
    # The `execute_test_plan` will use the `SIMPLE_API_SPEC` to understand
    # what requests to make. Because the plugin is in 'proxy' mode, these
    # requests will be forwarded to `JSONPLACEHOLDER_TARGET_URL`.

    print(
        f"\nAttempting to execute test plan against the PROXY plugin (targeting {JSONPLACEHOLDER_TARGET_URL})..."
    )
    try:
        # For this example, we'll tell execute_test_plan to use the "proxy" mode logic
        # and point it directly to the target.
        # In a full setup, server_url would be the MockLoop server hosting the plugin.
        test_plan_result = await execute_test_plan(
            openapi_spec=SIMPLE_API_SPEC,
            server_url=JSONPLACEHOLDER_TARGET_URL,  # Simulating direct call for this example
            mode="proxy",  # Instructs execute_test_plan to behave as if hitting a proxy
            test_focus="functional",
            auto_generate_scenarios=True,  # Will generate requests based on SIMPLE_API_SPEC
            execute_immediately=True,
            validation_mode="soft",  # Use soft validation for external APIs
        )
        print("Test plan execution result:")
        print(
            json.dumps(test_plan_result, indent=2, default=str)
        )  # Use default=str for datetime
        print("-" * 50)

        if (
            test_plan_result.get("status") == "success"
            or test_plan_result.get("status") == "partial_success"
        ):
            print("\nTest plan executed. Review the 'execution_results'.")
            print(
                "You should see requests made to JSONPlaceholder for '/todos/{todoId}'."
            )
        else:
            print("\nTest plan execution encountered errors.")

    except Exception as e:
        print(f"Error executing test plan: {e}")
        print("-" * 50)

    print("\nProxy mode test plan demonstration finished.")


if __name__ == "__main__":
    asyncio.run(main())
