# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
Hybrid Workflow Example

This example demonstrates the complete mock-to-proxy workflow using hybrid mode.
It shows how to gradually transition from mock responses to live API calls
based on routing rules and conditions.
"""

import asyncio
import json
import os
from pathlib import Path

# MockLoop MCP imports
from mockloop_mcp.mcp_tools import create_mcp_plugin, execute_test_plan
from mockloop_mcp.proxy.config import (
    ProxyConfig,
    AuthConfig,
    AuthType,
    RouteRule,
    ProxyMode,
)


async def main():
    """Demonstrate hybrid workflow with intelligent routing."""

    print("🔀 Hybrid Workflow Example - Smart Mock-to-Proxy Routing")
    print("=" * 60)

    # Define a comprehensive API specification
    api_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "E-commerce API",
            "version": "1.0.0",
            "description": "A comprehensive e-commerce API with multiple endpoints",
        },
        "servers": [
            {
                "url": "https://api.ecommerce.example.com",
                "description": "Production API",
            }
        ],
        "paths": {
            "/products": {
                "get": {
                    "summary": "List products",
                    "description": "Get a list of all products",
                    "parameters": [
                        {
                            "name": "category",
                            "in": "query",
                            "schema": {"type": "string"},
                            "description": "Filter by category",
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "default": 20},
                            "description": "Number of products to return",
                        },
                    ],
                    "responses": {
                        "200": {
                            "description": "List of products",
                            "content": {
                                "application/json": {
                                    "example": [
                                        {
                                            "id": 1,
                                            "name": "Laptop",
                                            "price": 999.99,
                                            "category": "electronics",
                                            "in_stock": True,
                                        }
                                    ]
                                }
                            },
                        }
                    },
                }
            },
            "/products/{id}": {
                "get": {
                    "summary": "Get product by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Product details",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "id": 1,
                                        "name": "Laptop",
                                        "price": 999.99,
                                        "category": "electronics",
                                        "description": "High-performance laptop",
                                        "in_stock": True,
                                        "reviews_count": 42,
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/orders": {
                "post": {
                    "summary": "Create order",
                    "description": "Create a new order (critical operation)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "product_id": {"type": "integer"},
                                        "quantity": {"type": "integer"},
                                        "customer_id": {"type": "integer"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Order created",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "order_id": 12345,
                                        "status": "pending",
                                        "total": 999.99,
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/orders/{id}": {
                "get": {
                    "summary": "Get order status",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Order details",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "order_id": 12345,
                                        "status": "shipped",
                                        "total": 999.99,
                                        "tracking_number": "TRK123456",
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/analytics/stats": {
                "get": {
                    "summary": "Get analytics data",
                    "description": "Internal analytics endpoint",
                    "responses": {
                        "200": {
                            "description": "Analytics data",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "total_orders": 1000,
                                        "revenue": 50000.00,
                                        "top_products": ["laptop", "phone"],
                                    }
                                }
                            },
                        }
                    },
                }
            },
        },
    }

    # Step 1: Create hybrid plugin with intelligent routing rules
    print("📝 Step 1: Creating hybrid plugin with routing rules...")

    # Define routing rules for hybrid mode
    routing_rules = [
        {
            "pattern": "/orders*",  # All order operations
            "mode": "proxy",  # Use live API for critical operations
            "condition": "request.method in ['POST', 'PUT', 'DELETE']",
            "priority": 10,
            "description": "Route critical order operations to live API",
        },
        {
            "pattern": "/analytics/*",  # Analytics endpoints
            "mode": "mock",  # Use mock for internal analytics
            "condition": None,
            "priority": 8,
            "description": "Use mock responses for analytics during development",
        },
        {
            "pattern": "/products*",  # Product endpoints
            "mode": "proxy",  # Use live API for product data
            "condition": "'test' not in request.headers.get('User-Agent', '').lower()",
            "priority": 5,
            "description": "Use live API for products unless in test mode",
        },
        {
            "pattern": "*",  # Default fallback
            "mode": "mock",  # Default to mock
            "condition": None,
            "priority": 1,
            "description": "Default to mock for all other endpoints",
        },
    ]

    try:
        hybrid_plugin = await create_mcp_plugin(
            spec_url_or_path=json.dumps(api_spec),
            mode="hybrid",
            plugin_name="ecommerce_hybrid",
            target_url="https://api.ecommerce.example.com",
            auth_config={
                "auth_type": "bearer_token",
                "credentials": {"token": os.getenv("API_TOKEN", "demo-token")},
                "location": "header",
                "name": "Authorization",
            },
            proxy_config={
                "timeout": 30,
                "retry_count": 3,
                "rate_limit": {"requests_per_minute": 100},
                "routing_rules": routing_rules,
            },
        )

        print("✅ Hybrid plugin created successfully!")
        print(f"   Plugin ID: {hybrid_plugin.get('plugin_id', 'N/A')}")
        print(f"   Mode: {hybrid_plugin.get('mode', 'N/A')}")
        print(f"   Routing rules: {len(routing_rules)}")

        # Display routing rules
        print("\n📋 Routing Rules Configuration:")
        for i, rule in enumerate(routing_rules, 1):
            print(
                f"   {i}. {rule['pattern']} → {rule['mode']} (priority: {rule['priority']})"
            )
            if rule["condition"]:
                print(f"      Condition: {rule['condition']}")

    except Exception as e:
        print(f"❌ Failed to create hybrid plugin: {e}")
        return

    # Step 2: Test different routing scenarios
    print("\n🧪 Step 2: Testing routing scenarios...")

    test_scenarios = [
        {
            "name": "Product Browsing (Mock Mode)",
            "description": "Test product endpoints with test user agent",
            "headers": {"User-Agent": "test-client/1.0"},
            "expected_mode": "mock",
        },
        {
            "name": "Product Browsing (Proxy Mode)",
            "description": "Test product endpoints with regular user agent",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "expected_mode": "proxy",
        },
        {
            "name": "Order Creation (Proxy Mode)",
            "description": "Test critical order operations",
            "headers": {"User-Agent": "app-client/1.0"},
            "expected_mode": "proxy",
        },
        {
            "name": "Analytics (Mock Mode)",
            "description": "Test internal analytics endpoints",
            "headers": {"User-Agent": "admin-dashboard/1.0"},
            "expected_mode": "mock",
        },
    ]

    for scenario in test_scenarios:
        print(f"\n   🔍 Testing: {scenario['name']}")
        print(f"      Expected mode: {scenario['expected_mode']}")

        try:
            # Simulate test execution for this scenario
            scenario_results = await execute_test_plan(
                openapi_spec=api_spec,
                server_url="http://localhost:8000",
                test_focus="routing",
                mode="hybrid",
                validation_mode="soft",
                comparison_config={
                    "ignore_fields": ["timestamp", "request_id"],
                    "tolerance": 0.1,
                },
                auto_generate_scenarios=True,
                execute_immediately=True,
                # Pass scenario-specific headers
                request_headers=scenario["headers"],
            )

            detected_mode = scenario_results.get("detected_mode", "unknown")
            print(f"      ✅ Detected mode: {detected_mode}")

            if detected_mode == scenario["expected_mode"]:
                print("      🎯 Routing worked as expected!")
            else:
                print(
                    f"      ⚠️  Unexpected routing (expected {scenario['expected_mode']})"
                )

        except Exception as e:
            print(f"      ❌ Scenario failed: {e}")

    # Step 3: Demonstrate gradual migration
    print("\n🔄 Step 3: Demonstrating gradual migration...")

    migration_phases = [
        {
            "phase": "Development Phase",
            "description": "Mostly mock with some proxy for critical paths",
            "mock_percentage": 80,
            "proxy_percentage": 20,
        },
        {
            "phase": "Integration Testing",
            "description": "Balanced mix for comprehensive testing",
            "mock_percentage": 50,
            "proxy_percentage": 50,
        },
        {
            "phase": "Pre-Production",
            "description": "Mostly proxy with mock for non-critical paths",
            "mock_percentage": 20,
            "proxy_percentage": 80,
        },
        {
            "phase": "Production Validation",
            "description": "Full proxy mode for production readiness",
            "mock_percentage": 0,
            "proxy_percentage": 100,
        },
    ]

    print("📈 Migration phases:")
    for phase in migration_phases:
        print(
            f"   • {phase['phase']}: {phase['proxy_percentage']}% proxy, {phase['mock_percentage']}% mock"
        )
        print(f"     {phase['description']}")

    # Step 4: Performance and reliability comparison
    print("\n⚡ Step 4: Performance and reliability analysis...")

    try:
        # Simulate performance testing
        performance_results = await execute_test_plan(
            openapi_spec=api_spec,
            server_url="http://localhost:8000",
            test_focus="performance",
            mode="hybrid",
            validation_mode="soft",
            parallel_execution=True,
            monitor_performance=True,
            auto_generate_scenarios=True,
            execute_immediately=True,
        )

        # Display performance metrics
        metrics = performance_results.get("performance_metrics", {})
        print("📊 Performance Analysis:")
        print(
            f"   Mock endpoints avg response time: {metrics.get('mock_avg_time', 'N/A')}ms"
        )
        print(
            f"   Proxy endpoints avg response time: {metrics.get('proxy_avg_time', 'N/A')}ms"
        )
        print(f"   Overall success rate: {metrics.get('success_rate', 'N/A')}%")
        print(f"   Routing accuracy: {metrics.get('routing_accuracy', 'N/A')}%")

        # Reliability metrics
        reliability = performance_results.get("reliability_metrics", {})
        print("\n🛡️  Reliability Analysis:")
        print(
            f"   Mock endpoint availability: {reliability.get('mock_availability', 'N/A')}%"
        )
        print(
            f"   Proxy endpoint availability: {reliability.get('proxy_availability', 'N/A')}%"
        )
        print(f"   Fallback success rate: {reliability.get('fallback_rate', 'N/A')}%")

    except Exception as e:
        print(f"❌ Performance analysis failed: {e}")

    # Step 5: Advanced routing conditions
    print("\n🎯 Step 5: Advanced routing conditions...")

    advanced_conditions = [
        {
            "name": "Time-based routing",
            "condition": "datetime.now().hour >= 9 and datetime.now().hour <= 17",
            "description": "Use proxy during business hours, mock otherwise",
        },
        {
            "name": "Load-based routing",
            "condition": "request.headers.get('X-Load-Test') is None",
            "description": "Use mock for load testing to avoid impacting production",
        },
        {
            "name": "Feature flag routing",
            "condition": "request.headers.get('X-Feature-Flag') == 'new-api'",
            "description": "Route to proxy only when feature flag is enabled",
        },
        {
            "name": "User-based routing",
            "condition": "request.headers.get('X-User-Type') == 'internal'",
            "description": "Use proxy for internal users, mock for external",
        },
    ]

    print("🔧 Advanced routing conditions:")
    for condition in advanced_conditions:
        print(f"   • {condition['name']}")
        print(f"     Condition: {condition['condition']}")
        print(f"     Use case: {condition['description']}")

    # Step 6: Error handling and fallback strategies
    print("\n🛡️ Step 6: Error handling and fallback strategies...")

    fallback_strategies = [
        {
            "scenario": "Proxy endpoint unavailable",
            "strategy": "Automatic fallback to mock",
            "implementation": "Circuit breaker pattern with health checks",
        },
        {
            "scenario": "Authentication failure",
            "strategy": "Retry with refresh token, then fallback to mock",
            "implementation": "Token refresh middleware with fallback",
        },
        {
            "scenario": "Rate limit exceeded",
            "strategy": "Queue requests or fallback to cached mock responses",
            "implementation": "Rate limiting with intelligent queuing",
        },
        {
            "scenario": "Network timeout",
            "strategy": "Immediate fallback to mock with logging",
            "implementation": "Timeout detection with fast failover",
        },
    ]

    print("🔄 Fallback strategies:")
    for strategy in fallback_strategies:
        print(f"   • {strategy['scenario']}")
        print(f"     Strategy: {strategy['strategy']}")
        print(f"     Implementation: {strategy['implementation']}")

    # Step 7: Monitoring and observability
    print("\n📊 Step 7: Monitoring and observability...")

    monitoring_metrics = [
        "Request routing decisions (mock vs proxy)",
        "Response time differences between modes",
        "Error rates by endpoint and mode",
        "Fallback trigger frequency",
        "Authentication success/failure rates",
        "Cache hit/miss ratios",
        "Network latency and availability",
    ]

    print("📈 Key monitoring metrics:")
    for metric in monitoring_metrics:
        print(f"   • {metric}")

    print("\n🎯 Benefits of Hybrid Mode:")
    print("   • Gradual migration from mock to live API")
    print("   • Risk mitigation through intelligent routing")
    print("   • Performance optimization with selective proxying")
    print("   • Comprehensive testing across different scenarios")
    print("   • Fallback capabilities for reliability")
    print("   • Cost optimization by reducing unnecessary API calls")

    print("\n✨ Next Steps:")
    print("   1. Try authentication-examples.py for auth scenarios")
    print("   2. Set up monitoring dashboards for hybrid mode")
    print("   3. Implement custom routing rules for your use case")
    print("   4. Configure fallback strategies for production")


if __name__ == "__main__":
    asyncio.run(main())
