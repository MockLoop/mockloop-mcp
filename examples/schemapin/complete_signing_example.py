#!/usr/bin/env python3
"""
Complete Schema Signing Example

This example demonstrates how to use the MockLoop MCP schema signing system
for securing MCP tools with cryptographic signatures.
"""

import asyncio
import os
from pathlib import Path

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mockloop_mcp.schemapin import (
    signed_tool,
    SchemaSigner,
    create_test_signer,
    get_tool_signature,
    get_tool_domain,
    verify_tool_signature,
    list_signed_tools
)


# Example 1: Basic tool signing with file-based private key
@signed_tool(
    domain="example.com",
    private_key_path="./examples/schemapin/test-private.pem"  # You would use a real key
)
async def example_tool_with_file_key(name: str, count: int = 5) -> dict:
    """
    Example MCP tool signed with file-based private key.

    Args:
        name: The name parameter
        count: Number of items (default: 5)

    Returns:
        Dictionary with results
    """
    return {"name": name, "count": count, "status": "success"}


# Example 2: Tool signing with private key content
EXAMPLE_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB...
-----END PRIVATE KEY-----"""

@signed_tool(
    domain="example.com",
    private_key_content=EXAMPLE_PRIVATE_KEY
)
async def example_tool_with_key_content(data: dict, validate: bool = True) -> dict:
    """
    Example MCP tool signed with private key content.

    Args:
        data: Input data dictionary
        validate: Whether to validate input (default: True)

    Returns:
        Processed data dictionary
    """
    if validate:
        # Perform validation
        pass
    return {"processed": data, "validated": validate}


# Example 3: Using environment variables for configuration
@signed_tool(
    domain=os.getenv("MOCKLOOP_SIGNING_DOMAIN", "example.com"),
    private_key_path=os.getenv("MOCKLOOP_PRIVATE_KEY_PATH"),
    private_key_content=os.getenv("MOCKLOOP_PRIVATE_KEY_CONTENT")
)
async def example_tool_with_env_config(message: str) -> dict:
    """
    Example MCP tool using environment variables for signing configuration.

    Args:
        message: Message to process

    Returns:
        Response dictionary
    """
    return {"message": f"Processed: {message}", "timestamp": "2024-01-01T00:00:00Z"}


async def demonstrate_signing_system():
    """Demonstrate the complete signing system."""
    print("MockLoop MCP Schema Signing Demonstration")
    print("=" * 50)

    # Create a test signer for demonstration
    print("\n1. Creating test signer...")
    create_test_signer("demo.example.com")
    print("   Test signer created for domain: demo.example.com")

    # Demonstrate tool signature verification
    print("\n2. Verifying tool signatures...")

    # Note: In a real scenario, these tools would be properly signed
    # For demonstration, we'll show the verification process
    tools_to_check = [
        example_tool_with_file_key,
        example_tool_with_key_content,
        example_tool_with_env_config
    ]

    for tool in tools_to_check:
        signature = get_tool_signature(tool)
        domain = get_tool_domain(tool)
        is_valid = verify_tool_signature(tool)

        print(f"   Tool: {tool.__name__}")
        print(f"   Domain: {domain}")
        print(f"   Has signature: {signature is not None}")
        print(f"   Signature valid: {is_valid}")
        print()

    # List all signed tools in current module
    print("3. Listing signed tools...")
    signed_tools = list_signed_tools(sys.modules[__name__])
    print(f"   Found {len(signed_tools)} signed tools:")
    for tool_info in signed_tools:
        print(f"   - {tool_info['name']} (domain: {tool_info['domain']})")

    # Demonstrate tool execution with signature injection
    print("\n4. Executing signed tool...")
    try:
        # The @signed_tool decorator automatically injects signature metadata
        result = await example_tool_with_env_config("Hello, MockLoop!")
        print(f"   Tool execution result: {result}")
    except Exception as e:
        print(f"   Tool execution failed: {e}")

    print("\n5. Configuration examples:")
    print("   Environment variables:")
    print("   export MOCKLOOP_SIGNING_DOMAIN=your-domain.com")
    print("   export MOCKLOOP_PRIVATE_KEY_PATH=/path/to/private.pem")
    print("   # OR")
    print("   export MOCKLOOP_PRIVATE_KEY_CONTENT=\"$(cat /path/to/private.pem)\"")

    print("\n   Batch signing:")
    print("   python scripts/sign_all_schemas.py --domain your-domain.com --private-key /path/to/key.pem")

    print("\n   Signature validation:")
    print("   python scripts/validate_signatures.py --domain your-domain.com --public-key /path/to/public.pem")


if __name__ == "__main__":
    asyncio.run(demonstrate_signing_system())

