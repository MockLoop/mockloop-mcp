# SchemaPin Integration Examples

This directory contains comprehensive examples demonstrating how to use SchemaPin integration with MockLoop MCP for cryptographic schema verification and security.

## Overview

SchemaPin provides cryptographic verification of MCP tool schemas to prevent "MCP Rug Pull" attacks where malicious actors could modify tool behavior without detection. The integration supports:

- **Schema Verification**: Cryptographic verification of tool schemas using ECDSA signatures
- **Key Pinning**: Trust-On-First-Use (TOFU) key management for domains
- **Policy Enforcement**: Configurable security policies (enforce/warn/log modes)
- **Audit Logging**: Comprehensive logging of verification events
- **Graceful Fallback**: Works with or without the SchemaPin library

## Examples

### 1. Basic Usage (`basic_usage.py`)

Demonstrates fundamental SchemaPin operations:

```bash
python examples/schemapin/basic_usage.py
```

**Features covered:**
- Configuration management
- Basic schema verification workflow
- Key pinning and retrieval
- Policy enforcement scenarios
- Audit logging
- Configuration persistence

**Key concepts:**
- Setting up SchemaPin configuration
- Verifying tool schemas with signatures
- Managing pinned keys for trusted tools
- Understanding policy actions (ALLOW, BLOCK, WARN, LOG)

### 2. Advanced Usage (`advanced_usage.py`)

Shows production-ready patterns and advanced scenarios:

```bash
python examples/schemapin/advanced_usage.py
```

**Features covered:**
- Batch verification for performance
- MCP proxy integration patterns
- Error recovery and monitoring
- Performance metrics collection
- Concurrent verification handling
- Custom workflow management

**Key concepts:**
- Building robust verification workflows
- Integrating with MCP proxy systems
- Handling verification failures gracefully
- Monitoring and performance optimization

## Configuration Examples

### Basic Configuration

```python
from mockloop_mcp.schemapin import SchemaPinConfig

config = SchemaPinConfig(
    enabled=True,
    policy_mode="warn",  # enforce, warn, or log
    auto_pin_keys=False,
    trusted_domains=["api.example.com"],
    interactive_mode=False
)
```

### Production Configuration

```python
config = SchemaPinConfig(
    enabled=True,
    policy_mode="enforce",
    auto_pin_keys=True,
    key_pin_storage_path="/secure/path/keys.db",
    discovery_timeout=60,
    cache_ttl=7200,
    trusted_domains=[
        "api.corp.com",
        "tools.internal.com"
    ],
    well_known_endpoints={
        "api.corp.com": "https://api.corp.com/.well-known/schemapin.json"
    },
    revocation_check=True,
    interactive_mode=False
)
```

## Usage Patterns

### 1. Tool Verification

```python
from mockloop_mcp.schemapin import SchemaVerificationInterceptor

interceptor = SchemaVerificationInterceptor(config)

# Verify a tool schema
result = await interceptor.verify_tool_schema(
    tool_name="database_query",
    schema=tool_schema,
    signature="base64_encoded_signature",
    domain="api.example.com"
)

if result.valid:
    print("✓ Schema verification successful")
else:
    print(f"✗ Verification failed: {result.error}")
```

### 2. Key Management

```python
from mockloop_mcp.schemapin import KeyPinningManager

key_manager = KeyPinningManager("keys.db")

# Pin a key for a tool
success = key_manager.pin_key(
    tool_id="api.example.com/database_query",
    domain="api.example.com",
    public_key_pem=public_key,
    metadata={"developer": "Example Corp"}
)

# Check if key is pinned
if key_manager.is_key_pinned("api.example.com/database_query"):
    print("Key is pinned for this tool")
```

### 3. Policy Enforcement

```python
from mockloop_mcp.schemapin import PolicyHandler

policy_handler = PolicyHandler(config)

# Evaluate verification result
decision = await policy_handler.evaluate_verification_result(
    verification_result, "tool_name"
)

if decision.action == PolicyAction.BLOCK:
    print("Tool execution blocked by policy")
elif decision.action == PolicyAction.WARN:
    print("Tool execution allowed with warning")
```

### 4. Audit Logging

```python
from mockloop_mcp.schemapin import SchemaPinAuditLogger

audit_logger = SchemaPinAuditLogger("audit.db")

# Log verification attempt
await audit_logger.log_verification_attempt(
    tool_id, domain, verification_result, execution_time_ms
)

# Get verification statistics
stats = audit_logger.get_verification_stats()
print(f"Total verifications: {stats['total_verifications']}")
```

## Security Considerations

### 1. Key Discovery

SchemaPin attempts to discover public keys via `.well-known/schemapin.json` endpoints:

```
https://example.com/.well-known/schemapin.json
```

Expected format:
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "algorithm": "ES256",
  "created_at": "2023-01-01T00:00:00Z"
}
```

### 2. Trust-On-First-Use (TOFU)

- First encounter with a domain triggers key discovery
- Keys are pinned automatically for trusted domains
- Subsequent verifications use pinned keys
- Key rotation requires manual intervention

### 3. Policy Modes

- **enforce**: Block execution on verification failure
- **warn**: Allow execution with warning logged
- **log**: Allow execution with event logged only

### 4. Signature Verification

- Uses ECDSA P-256 signatures
- Schema canonicalization ensures consistent hashing
- Supports both SchemaPin library and fallback implementation

## Integration with MockLoop

### MCP Tool Integration

```python
from mockloop_mcp.schemapin.verification import extract_tool_schema

def my_mcp_tool(param1: str, param2: int = 10) -> dict:
    """My MCP tool function."""
    return {"result": "success"}

# Extract schema for verification
schema = extract_tool_schema(my_mcp_tool)
```

### Proxy Integration

```python
class SchemaPinMCPProxy:
    async def proxy_tool_request(self, tool_name, schema, signature, domain, request_data):
        # Verify schema before proxying
        result = await self.interceptor.verify_tool_schema(
            tool_name, schema, signature, domain
        )
        
        if not result.valid:
            return {"error": "Schema verification failed"}
        
        # Proceed with tool execution
        return await self.execute_tool(tool_name, request_data)
```

## Testing

Run the comprehensive test suite:

```bash
# Unit tests
python -m pytest tests/unit/test_schemapin_integration.py -v

# Integration tests  
python -m pytest tests/integration/test_schemapin_integration.py -v

# Run examples
python examples/schemapin/basic_usage.py
python examples/schemapin/advanced_usage.py
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `src/` is in Python path
2. **Database Permissions**: Check write permissions for key storage
3. **Network Timeouts**: Adjust `discovery_timeout` for slow networks
4. **Key Discovery Failures**: Verify `.well-known` endpoint accessibility

### Debug Mode

Enable debug logging:

```python
import logging
logging.getLogger('mockloop_mcp.schemapin').setLevel(logging.DEBUG)
```

### Fallback Behavior

SchemaPin gracefully falls back to legacy implementation when the SchemaPin library is unavailable:

```python
# Check if SchemaPin library is available
from mockloop_mcp.schemapin.verification import SCHEMAPIN_AVAILABLE
print(f"SchemaPin library available: {SCHEMAPIN_AVAILABLE}")
```

## Performance Considerations

### Batch Operations

For multiple tools, use batch verification:

```python
# Instead of individual verifications
results = await workflow_manager.verify_tool_batch(tools_list)
```

### Caching

- Verification results can be cached based on `cache_ttl`
- Pinned keys are stored persistently in SQLite
- Consider implementing application-level caching for frequently used tools

### Concurrent Operations

SchemaPin supports concurrent verification requests:

```python
tasks = [
    interceptor.verify_tool_schema(tool, schema, sig, domain)
    for tool, schema, sig, domain in tool_list
]
results = await asyncio.gather(*tasks)
```

## Best Practices

1. **Use enforce mode in production** for critical tools
2. **Pin keys for trusted domains** to avoid repeated discovery
3. **Monitor audit logs** for security events
4. **Implement proper error handling** for verification failures
5. **Test both with and without** SchemaPin library available
6. **Use batch operations** for better performance
7. **Configure appropriate timeouts** for your network environment
8. **Regularly review pinned keys** and revoke when necessary

## Further Reading

- [SchemaPin Protocol Specification](https://github.com/schemapin/schemapin)
- [MockLoop MCP Documentation](../../docs/)
- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Integration Architecture](../../SchemaPin_MockLoop_Integration_Architecture.md)