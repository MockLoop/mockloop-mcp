#!/usr/bin/env python3
# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Basic Mock Example

This example demonstrates how to create a simple MCP plugin in mock mode
and perform basic API testing with generated mock responses.
"""

import asyncio
import json

# MockLoop MCP imports
from mockloop_mcp.mcp_tools import create_mcp_plugin, execute_test_plan


async def main():
    """Demonstrate basic mock plugin creation and testing."""

    print("🚀 Basic Mock Example - Creating MCP Plugin")
    print("=" * 50)

    # Define a simple API specification
    api_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "User Management API",
            "version": "1.0.0",
            "description": "A simple user management API for demonstration",
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "List all users",
                    "description": "Retrieve a list of all users in the system",
                    "responses": {
                        "200": {
                            "description": "List of users",
                            "content": {
                                "application/json": {
                                    "example": [
                                        {
                                            "id": 1,
                                            "name": "John Doe",
                                            "email": "john@example.com",
                                            "role": "admin",
                                        },
                                        {
                                            "id": 2,
                                            "name": "Jane Smith",
                                            "email": "jane@example.com",
                                            "role": "user",
                                        },
                                    ]
                                }
                            },
                        }
                    },
                },
                "post": {
                    "summary": "Create a new user",
                    "description": "Create a new user in the system",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"},
                                        "role": {"type": "string"},
                                    },
                                    "required": ["name", "email"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "User created successfully",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "id": 3,
                                        "name": "New User",
                                        "email": "newuser@example.com",
                                        "role": "user",
                                    }
                                }
                            },
                        }
                    },
                },
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "description": "Retrieve a specific user by their ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                            "description": "User ID",
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User details",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "id": 1,
                                        "name": "John Doe",
                                        "email": "john@example.com",
                                        "role": "admin",
                                        "created_at": "2023-01-01T00:00:00Z",
                                    }
                                }
                            },
                        },
                        "404": {
                            "description": "User not found",
                            "content": {
                                "application/json": {
                                    "example": {"error": "User not found", "code": 404}
                                }
                            },
                        },
                    },
                }
            },
        },
    }

    # Step 1: Create MCP plugin in mock mode
    print("📝 Step 1: Creating MCP plugin in mock mode...")

    try:
        plugin_result = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),  # Pass spec as JSON string
            mode="mock",  # Start with mock mode
            plugin_name="user_management_api",
            target_url=None,  # No target URL needed for mock mode
            auth_config=None,  # No authentication for this example
            proxy_config=None,  # No proxy config needed for mock mode
        )

        print("✅ Plugin created successfully!")
        print(f"   Plugin ID: {plugin_result.get('plugin_id', 'N/A')}")
        print(f"   Mode: {plugin_result.get('mode', 'N/A')}")
        print(f"   Endpoints: {len(plugin_result.get('endpoints', []))}")

    except Exception as e:
        print(f"❌ Failed to create plugin: {e}")
        return

    # Step 2: Execute test plan with mock responses
    print("\n🧪 Step 2: Executing test plan with mock responses...")

    try:
        test_results = await execute_test_plan(
            openapi_spec=api_spec,
            server_url="http://localhost:8000",  # Mock server URL
            test_focus="basic",  # Basic test coverage
            mode="mock",  # Explicitly use mock mode
            validation_mode="strict",  # Strict validation for development
            auto_generate_scenarios=True,
            execute_immediately=True,
        )

        print("✅ Test execution completed!")
        print(f"   Total tests: {test_results.get('total_tests', 0)}")
        print(f"   Passed: {test_results.get('passed', 0)}")
        print(f"   Failed: {test_results.get('failed', 0)}")
        print(f"   Duration: {test_results.get('duration', 0):.2f}s")

        # Display test details
        if test_results.get("test_details"):
            print("\n📊 Test Details:")
            for test in test_results["test_details"][:3]:  # Show first 3 tests
                status = "✅" if test.get("passed") else "❌"
                print(
                    f"   {status} {test.get('method', 'GET')} {test.get('path', '/')}"
                )
                print(f"      Response: {test.get('status_code', 'N/A')}")
                if test.get("response_time"):
                    print(f"      Time: {test.get('response_time', 0):.3f}s")

    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return

    # Step 3: Demonstrate mock response customization
    print("\n🎨 Step 3: Mock response customization example...")

    # Show how to customize mock responses
    custom_responses = {
        "/users": {
            "GET": {
                "status_code": 200,
                "response": [
                    {
                        "id": 1,
                        "name": "Alice Johnson",
                        "email": "alice@company.com",
                        "role": "admin",
                        "department": "Engineering",
                    },
                    {
                        "id": 2,
                        "name": "Bob Wilson",
                        "email": "bob@company.com",
                        "role": "developer",
                        "department": "Engineering",
                    },
                ],
            }
        },
        "/users/{id}": {
            "GET": {
                "status_code": 200,
                "response": {
                    "id": 1,
                    "name": "Alice Johnson",
                    "email": "alice@company.com",
                    "role": "admin",
                    "department": "Engineering",
                    "last_login": "2023-12-01T10:30:00Z",
                },
            }
        },
    }

    print("📝 Custom mock responses configured:")
    for endpoint, methods in custom_responses.items():
        for method, config in methods.items():
            print(f"   {method} {endpoint} → {config['status_code']}")

    print("\n🎯 Key Benefits of Mock Mode:")
    print("   • Fast development without external dependencies")
    print("   • Predictable responses for consistent testing")
    print("   • Easy testing of edge cases and error scenarios")
    print("   • No API rate limits or authentication requirements")
    print("   • Offline development capability")

    print("\n✨ Next Steps:")
    print(
        "   1. Explore `create_plugin_modes_example.py` to see PROXY and HYBRID mode plugin creation."
    )
    print(
        "   2. Run `execute_plan_with_proxy_example.py` to test PROXY mode against a live API."
    )
    print(
        "   3. Examine `hybrid_mode_routing_example.py` for HYBRID mode with custom routing."
    )
    print("   4. Review `authentication-example.py` for various auth scenarios.")
    print(
        "   5. Check `proxy-validation-example.py` and `hybrid-workflow-example.py` for other advanced use cases."
    )


if __name__ == "__main__":
    asyncio.run(main())
