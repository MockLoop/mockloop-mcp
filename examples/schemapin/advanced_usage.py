#!/usr/bin/env python3
"""
Advanced SchemaPin Usage Example

This example demonstrates advanced SchemaPin integration scenarios including:
- Custom verification workflows
- Integration with MCP proxy
- Batch operations
- Error handling and recovery
- Performance monitoring
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mockloop_mcp.schemapin import (
    SchemaPinConfig,
    SchemaVerificationInterceptor,
    KeyPinningManager,
    PolicyHandler,
    SchemaPinAuditLogger,
    VerificationResult,
    PolicyAction,
    PolicyDecision
)


class SchemaPinWorkflowManager:
    """Advanced workflow manager for SchemaPin operations."""

    def __init__(self, config: SchemaPinConfig):
        self.config = config
        self.interceptor = SchemaVerificationInterceptor(config)
        self.key_manager = KeyPinningManager(config.key_pin_storage_path)
        self.policy_handler = PolicyHandler(config)
        self.audit_logger = SchemaPinAuditLogger()
        self.performance_metrics = {}

    async def verify_tool_batch(self, tools: list[dict[str, Any]]) -> list[VerificationResult]:
        """Verify multiple tools in batch with performance tracking."""
        start_time = time.time()
        results = []

        print(f"Starting batch verification of {len(tools)} tools...")

        # Process tools concurrently for better performance
        tasks = []
        for tool in tools:
            task = self.interceptor.verify_tool_schema(
                tool_name=tool["name"],
                schema=tool["schema"],
                signature=tool.get("signature"),
                domain=tool.get("domain")
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                error_result = VerificationResult(
                    valid=False,
                    tool_id=tools[i]["name"],
                    error=str(result)
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        execution_time = (time.time() - start_time) * 1000
        self.performance_metrics["batch_verification"] = {
            "tools_count": len(tools),
            "execution_time_ms": execution_time,
            "avg_time_per_tool": execution_time / len(tools)
        }

        print(f"Batch verification completed in {execution_time:.2f}ms")
        return processed_results

    async def setup_trusted_domain(self, domain: str, public_key: str,
                                 tools: list[str]) -> dict[str, bool]:
        """Set up a trusted domain with multiple tools."""
        print(f"Setting up trusted domain: {domain}")

        results = {}
        for tool_name in tools:
            tool_id = f"{domain}/{tool_name}"
            success = self.key_manager.pin_key(
                tool_id=tool_id,
                domain=domain,
                public_key_pem=public_key,
                metadata={
                    "setup_type": "trusted_domain",
                    "setup_time": time.time(),
                    "tool_name": tool_name
                }
            )
            results[tool_name] = success

            if success:
                await self.audit_logger.log_key_pinning_event(
                    tool_id, domain, public_key, "pin"
                )

        print(f"Domain setup complete: {sum(results.values())}/{len(tools)} tools pinned")
        return results

    async def handle_verification_failure(self, result: VerificationResult,
                                        tool_name: str) -> PolicyDecision:
        """Advanced failure handling with custom recovery strategies."""
        print(f"Handling verification failure for {tool_name}")

        # Get policy decision
        decision = await self.policy_handler.evaluate_verification_result(result, tool_name)

        # Log the decision
        await self.audit_logger.log_policy_decision(
            result.tool_id, decision.action.value, decision.reason, decision.policy_mode
        )

        # Implement custom recovery strategies
        if decision.action == PolicyAction.BLOCK:
            print(f"🚫 BLOCKED: {tool_name} - {decision.reason}")

            # Check if we can attempt key recovery
            if result.domain and "key" in result.error.lower():
                print("Attempting key recovery...")
                recovered_key = await self._attempt_key_recovery(result.domain)
                if recovered_key:
                    print("✓ Key recovery successful, retrying verification")
                    # In a real implementation, you'd retry verification here

        elif decision.action == PolicyAction.WARN:
            print(f"⚠️  WARNING: {tool_name} - {decision.reason}")
            print("Tool execution will proceed with monitoring")

        elif decision.action == PolicyAction.LOG:
            print(f"📝 LOGGED: {tool_name} - {decision.reason}")

        return decision

    async def _attempt_key_recovery(self, domain: str) -> str | None:
        """Attempt to recover a public key through alternative methods."""
        # Try alternative discovery endpoints
        alternative_endpoints = [
            f"https://{domain}/security/schemapin.json",
            f"https://{domain}/api/v1/schemapin",
            f"https://security.{domain}/schemapin.json"
        ]

        for endpoint in alternative_endpoints:
            try:
                # In a real implementation, you'd make HTTP requests here
                print(f"Trying alternative endpoint: {endpoint}")
                # Simulate discovery attempt
                await asyncio.sleep(0.1)
            except Exception as e:
                # Log the exception for debugging
                print(f"Failed to connect to {endpoint}: {e}")
                continue

        return None

    def get_performance_report(self) -> dict[str, Any]:
        """Generate performance report."""
        return {
            "metrics": self.performance_metrics,
            "key_stats": {
                "total_pinned_keys": len(self.key_manager.list_pinned_keys()),
                "audit_stats": self.audit_logger.get_verification_stats()
            }
        }


async def advanced_verification_workflow():
    """Demonstrate advanced verification workflows."""
    print("=== Advanced Verification Workflow ===\n")

    # Configure for production-like scenario
    config = SchemaPinConfig(
        policy_mode="enforce",
        auto_pin_keys=False,
        key_pin_storage_path="advanced_keys.db",
        trusted_domains=["api.corp.com", "tools.internal.com"],
        discovery_timeout=30,
        interactive_mode=False
    )

    workflow_manager = SchemaPinWorkflowManager(config)

    # Set up trusted domain with multiple tools
    trusted_domain = "api.corp.com"
    trusted_key = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETrustedKey1234567890abcdefgh
ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890trusted
-----END PUBLIC KEY-----"""

    trusted_tools = ["database_query", "file_operations", "api_gateway", "auth_service"]

    setup_results = await workflow_manager.setup_trusted_domain(
        trusted_domain, trusted_key, trusted_tools
    )
    print(f"✓ Trusted domain setup: {setup_results}\n")

    # Prepare batch of tools for verification
    tools_batch = [
        {
            "name": "database_query",
            "domain": "api.corp.com",
            "schema": {
                "name": "database_query",
                "description": "Execute database queries",
                "parameters": {"type": "object"}
            },
            "signature": "valid_signature_1"
        },
        {
            "name": "file_operations",
            "domain": "api.corp.com",
            "schema": {
                "name": "file_operations",
                "description": "File system operations",
                "parameters": {"type": "object"}
            },
            "signature": "valid_signature_2"
        },
        {
            "name": "suspicious_tool",
            "domain": "malicious.com",
            "schema": {
                "name": "suspicious_tool",
                "description": "Suspicious operations",
                "parameters": {"type": "object"}
            },
            "signature": "invalid_signature"
        },
        {
            "name": "unsigned_tool",
            "domain": "unknown.com",
            "schema": {
                "name": "unsigned_tool",
                "description": "Tool without signature",
                "parameters": {"type": "object"}
            },
            "signature": None
        }
    ]

    # Mock signature verification for demonstration
    def mock_verify_signature(schema, signature, public_key):
        # Simulate verification logic
        if signature and "valid_signature" in signature:
            return True
        return False

    with patch.object(workflow_manager.interceptor, '_verify_signature', side_effect=mock_verify_signature):
        # Perform batch verification
        results = await workflow_manager.verify_tool_batch(tools_batch)

        print("--- Batch Verification Results ---")
        for i, result in enumerate(results):
            tool = tools_batch[i]
            print(f"Tool: {tool['name']}")
            print(f"  Valid: {result.valid}")
            print(f"  Domain: {result.domain}")
            print(f"  Key pinned: {result.key_pinned}")
            if result.error:
                print(f"  Error: {result.error}")

            # Handle failures with advanced strategies
            if not result.valid:
                await workflow_manager.handle_verification_failure(result, tool['name'])

            print()

    # Generate performance report
    report = workflow_manager.get_performance_report()
    print("--- Performance Report ---")
    print(json.dumps(report, indent=2, default=str))


async def mcp_proxy_integration_example():
    """Demonstrate integration with MCP proxy patterns."""
    print("\n=== MCP Proxy Integration Example ===\n")

    class SchemaPinMCPProxy:
        """MCP Proxy with SchemaPin integration."""

        def __init__(self, config: SchemaPinConfig):
            self.config = config
            self.interceptor = SchemaVerificationInterceptor(config)
            self.request_cache = {}

        async def proxy_tool_request(self, tool_name: str, tool_schema: dict[str, Any],
                                   signature: str | None, domain: str | None,
                                   request_data: dict[str, Any]) -> dict[str, Any]:
            """Proxy tool request with SchemaPin verification."""
            print(f"Proxying request for tool: {tool_name}")

            # Verify schema first
            verification_result = await self.interceptor.verify_tool_schema(
                tool_name, tool_schema, signature, domain
            )

            if not verification_result.valid:
                return {
                    "error": "Schema verification failed",
                    "details": verification_result.error,
                    "tool_id": verification_result.tool_id
                }

            # Cache verification result for performance
            cache_key = f"{domain}/{tool_name}"
            self.request_cache[cache_key] = {
                "verified_at": time.time(),
                "result": verification_result
            }

            # Simulate tool execution
            print(f"✓ Schema verified, executing tool: {tool_name}")
            return {
                "success": True,
                "tool_id": verification_result.tool_id,
                "verified": True,
                "key_pinned": verification_result.key_pinned,
                "result": f"Executed {tool_name} with data: {request_data}"
            }

        def get_verification_cache_stats(self) -> dict[str, Any]:
            """Get cache statistics."""
            return {
                "cached_verifications": len(self.request_cache),
                "cache_entries": list(self.request_cache.keys())
            }

    # Initialize proxy
    proxy_config = SchemaPinConfig(
        policy_mode="warn",
        cache_ttl=3600,
        key_pin_storage_path="proxy_keys.db"
    )

    proxy = SchemaPinMCPProxy(proxy_config)

    # Simulate proxy requests
    requests = [
        {
            "tool_name": "secure_api_call",
            "domain": "api.secure.com",
            "schema": {"name": "secure_api_call", "description": "Secure API operations"},
            "signature": "proxy_signature_1",
            "request_data": {"endpoint": "/api/v1/data", "method": "GET"}
        },
        {
            "tool_name": "data_processor",
            "domain": "processing.com",
            "schema": {"name": "data_processor", "description": "Process data"},
            "signature": None,  # Unsigned tool
            "request_data": {"data": [1, 2, 3, 4, 5]}
        }
    ]

    for request in requests:
        result = await proxy.proxy_tool_request(
            request["tool_name"],
            request["schema"],
            request["signature"],
            request["domain"],
            request["request_data"]
        )

        print(f"Proxy result for {request['tool_name']}:")
        print(json.dumps(result, indent=2))
        print()

    # Show cache stats
    cache_stats = proxy.get_verification_cache_stats()
    print("Proxy cache statistics:")
    print(json.dumps(cache_stats, indent=2))


async def error_recovery_and_monitoring():
    """Demonstrate error recovery and monitoring capabilities."""
    print("\n=== Error Recovery and Monitoring ===\n")

    class SchemaPinMonitor:
        """Monitor SchemaPin operations and handle errors."""

        def __init__(self, config: SchemaPinConfig):
            self.config = config
            self.interceptor = SchemaVerificationInterceptor(config)
            self.audit_logger = SchemaPinAuditLogger()
            self.error_counts = {}
            self.recovery_attempts = {}

        async def monitored_verification(self, tool_name: str, schema: dict[str, Any],
                                       signature: str | None, domain: str | None) -> dict[str, Any]:
            """Perform verification with monitoring and recovery."""
            tool_id = f"{domain}/{tool_name}" if domain else tool_name

            try:
                result = await self.interceptor.verify_tool_schema(
                    tool_name, schema, signature, domain
                )

                if not result.valid:
                    await self._handle_verification_error(tool_id, result.error)

                return {
                    "verification_result": result,
                    "monitoring_data": {
                        "error_count": self.error_counts.get(tool_id, 0),
                        "recovery_attempts": self.recovery_attempts.get(tool_id, 0)
                    }
                }

            except Exception as e:
                await self._handle_system_error(tool_id, str(e))
                return {
                    "verification_result": VerificationResult(
                        valid=False,
                        tool_id=tool_id,
                        error=f"System error: {e}"
                    ),
                    "monitoring_data": {
                        "system_error": True,
                        "error_count": self.error_counts.get(tool_id, 0)
                    }
                }

        async def _handle_verification_error(self, tool_id: str, error: str):
            """Handle verification errors with recovery strategies."""
            self.error_counts[tool_id] = self.error_counts.get(tool_id, 0) + 1

            print(f"⚠️  Verification error for {tool_id}: {error}")

            # Implement recovery strategies based on error type
            if "key" in error.lower() and "not found" in error.lower():
                await self._attempt_key_rediscovery(tool_id)
            elif "signature" in error.lower():
                await self._log_signature_failure(tool_id, error)
            elif "timeout" in error.lower():
                await self._handle_timeout_error(tool_id)

        async def _handle_system_error(self, tool_id: str, error: str):
            """Handle system-level errors."""
            print(f"🚨 System error for {tool_id}: {error}")
            await self.audit_logger.log_verification_error(tool_id, None, f"System: {error}")

        async def _attempt_key_rediscovery(self, tool_id: str):
            """Attempt to rediscover keys for failed tools."""
            self.recovery_attempts[tool_id] = self.recovery_attempts.get(tool_id, 0) + 1
            print(f"🔄 Attempting key rediscovery for {tool_id} (attempt #{self.recovery_attempts[tool_id]})")

            # In a real implementation, this would attempt actual key rediscovery
            await asyncio.sleep(0.1)  # Simulate recovery attempt

        async def _log_signature_failure(self, tool_id: str, error: str):
            """Log signature verification failures for security analysis."""
            await self.audit_logger.log_verification_error(tool_id, None, f"Signature failure: {error}")
            print(f"🔐 Signature failure logged for security analysis: {tool_id}")

        async def _handle_timeout_error(self, tool_id: str):
            """Handle timeout errors with retry logic."""
            print(f"⏱️  Timeout error for {tool_id}, implementing backoff strategy")
            # In a real implementation, this would implement exponential backoff

        def get_monitoring_summary(self) -> dict[str, Any]:
            """Get monitoring summary."""
            return {
                "total_errors": sum(self.error_counts.values()),
                "tools_with_errors": len(self.error_counts),
                "total_recovery_attempts": sum(self.recovery_attempts.values()),
                "error_breakdown": self.error_counts.copy(),
                "recovery_breakdown": self.recovery_attempts.copy()
            }

    # Initialize monitor
    monitor_config = SchemaPinConfig(
        policy_mode="log",
        discovery_timeout=5,  # Short timeout to trigger errors
        key_pin_storage_path="monitor_keys.db"
    )

    monitor = SchemaPinMonitor(monitor_config)

    # Test various error scenarios
    test_scenarios = [
        {
            "name": "valid_tool",
            "domain": "valid.com",
            "schema": {"name": "valid_tool"},
            "signature": "valid_sig",
            "expected": "success"
        },
        {
            "name": "missing_key_tool",
            "domain": "unknown.com",
            "schema": {"name": "missing_key_tool"},
            "signature": "some_sig",
            "expected": "key_not_found"
        },
        {
            "name": "invalid_signature_tool",
            "domain": "malicious.com",
            "schema": {"name": "invalid_signature_tool"},
            "signature": "bad_signature",
            "expected": "signature_failure"
        },
        {
            "name": "unsigned_tool",
            "domain": "unsigned.com",
            "schema": {"name": "unsigned_tool"},
            "signature": None,
            "expected": "no_signature"
        }
    ]

    print("Testing error scenarios...")
    for scenario in test_scenarios:
        print(f"\n--- Testing: {scenario['name']} ---")
        result = await monitor.monitored_verification(
            scenario["name"],
            scenario["schema"],
            scenario["signature"],
            scenario["domain"]
        )

        print(f"Valid: {result['verification_result'].valid}")
        if result['verification_result'].error:
            print(f"Error: {result['verification_result'].error}")
        print(f"Monitoring: {result['monitoring_data']}")

    # Show monitoring summary
    summary = monitor.get_monitoring_summary()
    print("\n--- Monitoring Summary ---")
    print(json.dumps(summary, indent=2))


async def main():
    """Run all advanced examples."""
    print("Advanced SchemaPin Integration Examples")
    print("=" * 60)

    try:
        await advanced_verification_workflow()
        await mcp_proxy_integration_example()
        await error_recovery_and_monitoring()

        print("\n" + "=" * 60)
        print("✓ All advanced examples completed successfully!")
        print("\nKey takeaways:")
        print("1. Batch verification improves performance for multiple tools")
        print("2. MCP proxy integration provides seamless security")
        print("3. Error recovery and monitoring ensure robust operations")
        print("4. Performance metrics help optimize SchemaPin usage")

    except Exception as e:
        print(f"\n❌ Error running advanced examples: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Clean up example files
        cleanup_files = [
            "advanced_keys.db",
            "proxy_keys.db",
            "monitor_keys.db"
        ]

        print("\nCleaning up example files...")
        for file_path in cleanup_files:
            try:
                Path(file_path).unlink(missing_ok=True)
                print(f"✓ Removed {file_path}")
            except Exception as e:
                print(f"⚠ Could not remove {file_path}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
