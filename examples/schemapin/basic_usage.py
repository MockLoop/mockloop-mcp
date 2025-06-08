#!/usr/bin/env python3
"""
Basic SchemaPin Usage Example

This example demonstrates how to use SchemaPin integration with MockLoop MCP
for basic schema verification and key pinning scenarios.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mockloop_mcp.schemapin import (
    SchemaPinConfig,
    SchemaVerificationInterceptor,
    KeyPinningManager,
    PolicyHandler,
    SchemaPinAuditLogger,
    VerificationResult,
    PolicyAction
)


async def basic_verification_example():
    """Demonstrate basic schema verification workflow."""
    print("=== Basic Schema Verification Example ===\n")

    # 1. Configure SchemaPin
    config = SchemaPinConfig(
        enabled=True,
        policy_mode="warn",  # Options: enforce, warn, log
        auto_pin_keys=False,
        key_pin_storage_path="example_keys.db",
        trusted_domains=["api.example.com"],
        interactive_mode=False
    )

    print(f"✓ SchemaPin configured: policy_mode={config.policy_mode}")

    # 2. Initialize verification interceptor
    interceptor = SchemaVerificationInterceptor(config)
    print("✓ Verification interceptor initialized")

    # 3. Define a tool schema (what you'd get from an MCP tool)
    tool_schema = {
        "name": "database_query",
        "description": "Execute SQL queries against database",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "SQL query to execute"
                },
                "database": {
                    "type": "string",
                    "description": "Target database name",
                    "default": "main"
                }
            },
            "required": ["query"]
        }
    }

    # 4. Simulate verification scenarios
    print("\n--- Scenario 1: Unsigned tool (no signature) ---")
    result = await interceptor.verify_tool_schema(
        tool_name="database_query",
        schema=tool_schema,
        signature=None,  # No signature provided
        domain="api.example.com"
    )

    print(f"Valid: {result.valid}")
    print(f"Error: {result.error}")
    print(f"Tool ID: {result.tool_id}")

    print("\n--- Scenario 2: Tool with signature but no pinned key ---")
    # In real usage, this would be a cryptographic signature
    mock_signature = "eyJhbGciOiJFUzI1NiJ9.mock_signature_data"

    result = await interceptor.verify_tool_schema(
        tool_name="database_query",
        schema=tool_schema,
        signature=mock_signature,
        domain="api.example.com"
    )

    print(f"Valid: {result.valid}")
    print(f"Domain: {result.domain}")
    print(f"Key pinned: {result.key_pinned}")
    if result.error:
        print(f"Error: {result.error}")


async def key_management_example():
    """Demonstrate key pinning and management."""
    print("\n=== Key Management Example ===\n")

    # Initialize key manager
    key_manager = KeyPinningManager("example_keys.db")
    print("✓ Key manager initialized")

    # Example public key (in real usage, this would be discovered or provided)
    example_public_key = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEExample1234567890abcdefghijklmn
opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890example
-----END PUBLIC KEY-----"""

    # Pin a key for a tool
    tool_id = "api.example.com/database_query"
    domain = "api.example.com"
    metadata = {
        "developer": "Example Corp",
        "version": "1.0.0",
        "description": "Database query tool"
    }

    success = key_manager.pin_key(tool_id, domain, example_public_key, metadata)
    print(f"✓ Key pinned successfully: {success}")

    # Retrieve pinned key
    retrieved_key = key_manager.get_pinned_key(tool_id)
    print(f"✓ Key retrieved: {retrieved_key is not None}")

    # Check if key is pinned
    is_pinned = key_manager.is_key_pinned(tool_id)
    print(f"✓ Key is pinned: {is_pinned}")

    # Get detailed key information
    key_info = key_manager.get_key_info(tool_id)
    if key_info:
        print(f"✓ Key info - Domain: {key_info['domain']}")
        print(f"✓ Key info - Pinned at: {key_info['pinned_at']}")
        print(f"✓ Key info - Verification count: {key_info['verification_count']}")
        print(f"✓ Key info - Developer: {key_info['metadata']['developer']}")

    # List all pinned keys
    pinned_keys = key_manager.list_pinned_keys()
    print(f"✓ Total pinned keys: {len(pinned_keys)}")

    # Update verification stats (simulating successful verification)
    key_manager.update_verification_stats(tool_id)
    print("✓ Verification stats updated")

    # Get updated info
    updated_info = key_manager.get_key_info(tool_id)
    if updated_info:
        print(f"✓ Updated verification count: {updated_info['verification_count']}")


async def policy_enforcement_example():
    """Demonstrate policy enforcement scenarios."""
    print("\n=== Policy Enforcement Example ===\n")

    # Test different policy modes
    policy_modes = ["enforce", "warn", "log"]

    for mode in policy_modes:
        print(f"--- Testing {mode.upper()} mode ---")

        config = SchemaPinConfig(policy_mode=mode)
        policy_handler = PolicyHandler(config)

        # Simulate failed verification
        failed_result = VerificationResult(
            valid=False,
            tool_id="untrusted.com/suspicious_tool",
            domain="untrusted.com",
            error="Signature verification failed"
        )

        decision = await policy_handler.evaluate_verification_result(
            failed_result, "suspicious_tool"
        )

        print(f"  Action: {decision.action.value}")
        print(f"  Reason: {decision.reason}")
        print(f"  Policy mode: {decision.policy_mode}")

        # Show what each action means
        if decision.action == PolicyAction.BLOCK:
            print("  → Tool execution would be BLOCKED")
        elif decision.action == PolicyAction.WARN:
            print("  → Tool execution would proceed with WARNING")
        elif decision.action == PolicyAction.LOG:
            print("  → Tool execution would proceed with LOGGING only")

        print()


async def audit_logging_example():
    """Demonstrate audit logging capabilities."""
    print("\n=== Audit Logging Example ===\n")

    # Initialize audit logger
    audit_logger = SchemaPinAuditLogger("example_audit.db")
    print("✓ Audit logger initialized")

    # Log various events
    print("Logging verification events...")

    # Successful verification
    success_result = VerificationResult(
        valid=True,
        tool_id="api.example.com/secure_tool",
        domain="api.example.com",
        key_pinned=True
    )

    await audit_logger.log_verification_attempt(
        "api.example.com/secure_tool",
        "api.example.com",
        success_result,
        execution_time_ms=125.5
    )

    # Failed verification
    await audit_logger.log_verification_error(
        "malicious.com/bad_tool",
        "malicious.com",
        "Invalid signature detected"
    )

    # Key pinning event
    await audit_logger.log_key_pinning_event(
        "new.com/new_tool",
        "new.com",
        "new_public_key",
        "pin"
    )

    # Policy decision
    await audit_logger.log_policy_decision(
        "questionable.com/tool",
        "warn",
        "Unsigned tool execution",
        "warn"
    )

    print("✓ Events logged")

    # Get verification statistics
    stats = audit_logger.get_verification_stats()
    print("\n--- Audit Statistics ---")
    print(f"Total verifications: {stats.get('total_verifications', 0)}")
    print(f"Successful verifications: {stats.get('successful_verifications', 0)}")
    print(f"Failed verifications: {stats.get('failed_verifications', 0)}")
    print(f"Unique tools: {stats.get('unique_tools', 0)}")
    print(f"Unique domains: {stats.get('unique_domains', 0)}")

    if 'policy_breakdown' in stats:
        print("\nPolicy action breakdown:")
        for action, count in stats['policy_breakdown'].items():
            print(f"  {action}: {count}")


async def configuration_example():
    """Demonstrate configuration management."""
    print("\n=== Configuration Management Example ===\n")

    # Create custom configuration
    config = SchemaPinConfig(
        enabled=True,
        policy_mode="enforce",
        auto_pin_keys=True,
        key_pin_storage_path="production_keys.db",
        discovery_timeout=60,
        cache_ttl=7200,
        well_known_endpoints={
            "api.example.com": "https://api.example.com/.well-known/schemapin.json",
            "tools.corp.com": "https://tools.corp.com/security/schemapin.json"
        },
        trusted_domains=[
            "api.example.com",
            "tools.corp.com",
            "internal.company.com"
        ],
        revocation_check=True,
        interactive_mode=False
    )

    print("✓ Custom configuration created")

    # Save configuration to file
    config.save_to_file("schemapin_config.json")
    print("✓ Configuration saved to file")

    # Load configuration from file
    loaded_config = SchemaPinConfig.load_from_file("schemapin_config.json")
    print("✓ Configuration loaded from file")

    # Verify configuration
    print(f"Policy mode: {loaded_config.policy_mode}")
    print(f"Auto-pin keys: {loaded_config.auto_pin_keys}")
    print(f"Trusted domains: {len(loaded_config.trusted_domains)}")
    print(f"Discovery timeout: {loaded_config.discovery_timeout}s")

    # Convert to dictionary for inspection
    config_dict = loaded_config.to_dict()
    print("\nConfiguration as dictionary:")
    print(json.dumps(config_dict, indent=2))


async def main():
    """Run all examples."""
    print("SchemaPin Integration Examples")
    print("=" * 50)

    try:
        await basic_verification_example()
        await key_management_example()
        await policy_enforcement_example()
        await audit_logging_example()
        await configuration_example()

        print("\n" + "=" * 50)
        print("✓ All examples completed successfully!")
        print("\nNext steps:")
        print("1. Review the generated database files (example_keys.db, example_audit.db)")
        print("2. Examine the configuration file (schemapin_config.json)")
        print("3. Integrate SchemaPin verification into your MCP tools")
        print("4. Set up proper key discovery endpoints for your domains")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Clean up example files
        cleanup_files = [
            "example_keys.db",
            "example_audit.db",
            "schemapin_config.json"
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
