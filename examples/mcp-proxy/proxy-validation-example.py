#!/usr/bin/env python3
# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Proxy Validation Example

This example demonstrates how to validate mock responses against a live API
using the proxy mode functionality. It shows how to switch from mock to proxy
mode and compare responses for consistency.
"""

import asyncio
import json

# MockLoop MCP imports
from mockloop_mcp.mcp_tools import create_mcp_plugin, execute_test_plan


async def main():
    """Demonstrate proxy validation against a live API."""

    print("🔄 Proxy Validation Example - Mock vs Live API Testing")
    print("=" * 60)

    # Define API specification for a public API (JSONPlaceholder)
    api_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "JSONPlaceholder API",
            "version": "1.0.0",
            "description": "A fake online REST API for testing and prototyping",
        },
        "servers": [
            {"url": "https://jsonplaceholder.typicode.com", "description": "Live API"}
        ],
        "paths": {
            "/posts": {
                "get": {
                    "summary": "Get all posts",
                    "description": "Retrieve all posts from the API",
                    "responses": {
                        "200": {
                            "description": "List of posts",
                            "content": {
                                "application/json": {
                                    "example": [
                                        {
                                            "userId": 1,
                                            "id": 1,
                                            "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
                                            "body": "quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto",
                                        }
                                    ]
                                }
                            },
                        }
                    },
                }
            },
            "/posts/{id}": {
                "get": {
                    "summary": "Get post by ID",
                    "description": "Retrieve a specific post by its ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                            "description": "Post ID",
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Post details",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "userId": 1,
                                        "id": 1,
                                        "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
                                        "body": "quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto",
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/users": {
                "get": {
                    "summary": "Get all users",
                    "description": "Retrieve all users from the API",
                    "responses": {
                        "200": {
                            "description": "List of users",
                            "content": {
                                "application/json": {
                                    "example": [
                                        {
                                            "id": 1,
                                            "name": "Leanne Graham",
                                            "username": "Bret",
                                            "email": "Sincere@april.biz",
                                            "address": {
                                                "street": "Kulas Light",
                                                "suite": "Apt. 556",
                                                "city": "Gwenborough",
                                                "zipcode": "92998-3874",
                                            },
                                        }
                                    ]
                                }
                            },
                        }
                    },
                }
            },
        },
    }

    # Step 1: Create plugin in mock mode first
    print("📝 Step 1: Creating MCP plugin in mock mode...")

    try:
        mock_plugin = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),
            mode="mock",
            plugin_name="jsonplaceholder_mock",
            target_url=None,
            auth_config=None,
            proxy_config=None,
        )

        print("✅ Mock plugin created successfully!")
        print(f"   Plugin ID: {mock_plugin.get('plugin_id', 'N/A')}")
        print(f"   Mode: {mock_plugin.get('mode', 'N/A')}")

    except Exception as e:
        print(f"❌ Failed to create mock plugin: {e}")
        return

    # Step 2: Test with mock responses
    print("\n🧪 Step 2: Testing with mock responses...")

    try:
        mock_results = await execute_test_plan(
            openapi_spec=api_spec,
            server_url="http://localhost:8000",
            test_focus="basic",
            mode="mock",
            validation_mode="strict",
            auto_generate_scenarios=True,
            execute_immediately=True,
        )

        print("✅ Mock tests completed!")
        print(f"   Tests run: {mock_results.get('total_tests', 0)}")
        print(f"   Passed: {mock_results.get('passed', 0)}")
        print(f"   Duration: {mock_results.get('duration', 0):.2f}s")

    except Exception as e:
        print(f"❌ Mock testing failed: {e}")
        return

    # Step 3: Create plugin in proxy mode
    print("\n🔄 Step 3: Creating MCP plugin in proxy mode...")

    try:
        # No authentication needed for JSONPlaceholder API
        proxy_plugin = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),
            mode="proxy",
            plugin_name="jsonplaceholder_proxy",
            target_url="https://jsonplaceholder.typicode.com",
            auth_config=None,  # No auth required for this public API
            proxy_config={
                "timeout": 30,
                "retry_count": 3,
                "rate_limit": {"requests_per_minute": 60},
            },
        )

        print("✅ Proxy plugin created successfully!")
        print(f"   Plugin ID: {proxy_plugin.get('plugin_id', 'N/A')}")
        print("   Target URL: https://jsonplaceholder.typicode.com")

    except Exception as e:
        print(f"❌ Failed to create proxy plugin: {e}")
        return

    # Step 4: Test with live API (proxy mode)
    print("\n🌐 Step 4: Testing with live API (proxy mode)...")

    try:
        proxy_results = await execute_test_plan(
            openapi_spec=api_spec,
            server_url="https://jsonplaceholder.typicode.com",
            test_focus="basic",
            mode="proxy",
            validation_mode="soft",  # Use soft validation for live API
            auto_generate_scenarios=True,
            execute_immediately=True,
        )

        print("✅ Proxy tests completed!")
        print(f"   Tests run: {proxy_results.get('total_tests', 0)}")
        print(f"   Passed: {proxy_results.get('passed', 0)}")
        print(f"   Duration: {proxy_results.get('duration', 0):.2f}s")

    except Exception as e:
        print(f"❌ Proxy testing failed: {e}")
        return

    # Step 5: Compare mock vs proxy responses
    print("\n📊 Step 5: Comparing mock vs proxy responses...")

    try:
        comparison_results = await execute_test_plan(
            openapi_spec=api_spec,
            server_url="http://localhost:8000",  # Mock server
            test_focus="validation",
            mode="auto",  # Auto-detect mode
            validation_mode="soft",
            comparison_config={
                "ignore_fields": [
                    "id",  # IDs might differ between mock and live
                    "userId",  # User IDs might differ
                    "timestamp",  # Timestamps will differ
                    "created_at",
                    "updated_at",
                ],
                "tolerance": 0.1,  # 10% tolerance for numeric values
                "strict_arrays": False,  # Allow array order differences
                "compare_structure": True,  # Focus on structure comparison
                "compare_types": True,  # Ensure data types match
            },
            report_differences=True,
            auto_generate_scenarios=True,
            execute_immediately=True,
        )

        print("✅ Comparison completed!")

        # Display comparison results
        differences = comparison_results.get("differences", [])
        if differences:
            print(f"   Found {len(differences)} differences:")
            for diff in differences[:3]:  # Show first 3 differences
                endpoint = diff.get("endpoint", "Unknown")
                diff_type = diff.get("type", "Unknown")
                print(f"   • {endpoint}: {diff_type}")
        else:
            print("   🎉 No significant differences found!")

        # Show validation summary
        validation_summary = comparison_results.get("validation_summary", {})
        if validation_summary:
            print("\n📈 Validation Summary:")
            print(
                f"   Structure match: {validation_summary.get('structure_match', 'N/A')}%"
            )
            print(
                f"   Type consistency: {validation_summary.get('type_consistency', 'N/A')}%"
            )
            print(
                f"   Response similarity: {validation_summary.get('similarity_score', 'N/A')}%"
            )

    except Exception as e:
        print(f"❌ Comparison failed: {e}")
        return

    # Step 6: Demonstrate authentication example (conceptual)
    print("\n🔐 Step 6: Authentication example (for APIs requiring auth)...")

    # Example of how to configure authentication for APIs that require it
    auth_examples = {
        "API Key (Header)": {
            "auth_type": "api_key",
            "credentials": {"api_key": "your-api-key-here"},
            "location": "header",
            "name": "X-API-Key",
        },
        "API Key (Query)": {
            "auth_type": "api_key",
            "credentials": {"api_key": "your-api-key-here"},
            "location": "query",
            "name": "key",
        },
        "Bearer Token": {
            "auth_type": "bearer_token",
            "credentials": {"token": "your-bearer-token-here"},
        },
        "Basic Auth": {
            "auth_type": "basic_auth",
            "credentials": {"username": "your-username", "password": "your-password"},
        },
    }

    print("📝 Authentication configuration examples:")
    for auth_name, config in auth_examples.items():
        print(f"   • {auth_name}: {config['auth_type']}")

    print("\n💡 To use authentication, set the API_KEY environment variable:")
    print("   export API_KEY=your-actual-api-key")
    print("   python proxy-validation-example.py")

    # Step 7: Performance comparison
    print("\n⚡ Step 7: Performance comparison...")

    mock_duration = mock_results.get("duration", 0)
    proxy_duration = proxy_results.get("duration", 0)

    if mock_duration > 0 and proxy_duration > 0:
        speed_ratio = proxy_duration / mock_duration
        print(f"   Mock tests: {mock_duration:.2f}s")
        print(f"   Proxy tests: {proxy_duration:.2f}s")
        print(f"   Proxy is {speed_ratio:.1f}x slower than mock (expected)")

        if speed_ratio > 10:
            print(
                "   💡 Consider using mock mode for development and proxy for validation"
            )
        elif speed_ratio < 3:
            print("   🚀 Live API is quite fast - suitable for regular testing")

    print("\n🎯 Key Benefits of Proxy Validation:")
    print("   • Verify mock responses match real API behavior")
    print("   • Catch API changes early in development")
    print("   • Validate authentication and authorization flows")
    print("   • Test with real data and edge cases")
    print("   • Ensure mock accuracy for reliable development")

    print("\n✨ Next Steps:")
    print("   1. Run hybrid-workflow-example.py for mixed testing")
    print("   2. Try authentication-examples.py for auth scenarios")
    print("   3. Set up CI/CD pipeline for automated validation")


if __name__ == "__main__":
    asyncio.run(main())
