# SchemaPin Integration Guide

## Table of Contents

- [Introduction](#introduction)
- [Installation & Setup](#installation--setup)
- [Configuration Reference](#configuration-reference)
- [Usage Patterns](#usage-patterns)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Migration Guide](#migration-guide)
- [API Reference](#api-reference)
- [Examples](#examples)

## Introduction

### What is SchemaPin?

SchemaPin is a cryptographic schema verification system that prevents "MCP Rug Pull" attacks by ensuring the integrity and authenticity of MCP tool schemas through ECDSA signature verification and Trust-On-First-Use (TOFU) key pinning.

### The MCP Rug Pull Problem

MCP Rug Pull attacks occur when malicious actors modify tool schemas to:
- Change tool behavior without detection
- Inject malicious parameters or responses
- Bypass security controls
- Steal sensitive data through modified schemas

### How SchemaPin Solves This

SchemaPin provides cryptographic verification through:

1. **ECDSA P-256 Signatures**: Every tool schema is cryptographically signed
2. **Trust-On-First-Use (TOFU)**: Automatic key discovery and pinning
3. **Policy Enforcement**: Configurable responses to verification failures
4. **Comprehensive Auditing**: Complete verification logs for compliance

### Key Benefits

- **🔐 Cryptographic Security**: ECDSA P-256 signatures ensure schema integrity
- **🔑 Automatic Key Management**: TOFU model with automatic key discovery
- **📋 Policy Flexibility**: Configurable enforcement (enforce/warn/log modes)
- **📊 Compliance Ready**: Complete audit trails for regulatory requirements
- **🔄 Graceful Fallback**: Works with or without SchemaPin library
- **⚡ Minimal Performance Impact**: ~5-15ms verification time

## Installation & Setup

### Prerequisites

- Python 3.10+
- MockLoop MCP 2.3.0+
- Optional: SchemaPin library (`pip install schemapin>=1.0.0`)

### Installation

SchemaPin integration is included with MockLoop MCP 2.3.0+:

```bash
# Install MockLoop MCP with SchemaPin support
pip install mockloop-mcp>=2.3.0

# Optional: Install SchemaPin library for enhanced features
pip install schemapin>=1.0.0
```

### Verification

Verify the installation:

```python
from mockloop_mcp.schemapin import SchemaPinConfig, SchemaVerificationInterceptor

# Test basic functionality
config = SchemaPinConfig()
interceptor = SchemaVerificationInterceptor(config)
print("✓ SchemaPin integration ready")
```

### Initial Setup

1. **Create Configuration**:
```python
from mockloop_mcp.schemapin import SchemaPinConfig

config = SchemaPinConfig(
    enabled=True,
    policy_mode="warn",  # Start with warn mode
    auto_pin_keys=False,
    key_pin_storage_path="./schemapin_keys.db"
)
```

2. **Initialize Components**:
```python
from mockloop_mcp.schemapin import (
    SchemaVerificationInterceptor,
    KeyPinningManager,
    SchemaPinAuditLogger
)

interceptor = SchemaVerificationInterceptor(config)
key_manager = KeyPinningManager(config.key_pin_storage_path)
audit_logger = SchemaPinAuditLogger()
```

## Configuration Reference

### SchemaPinConfig Options

#### Core Settings

```python
@dataclass
class SchemaPinConfig:
    # Enable/disable SchemaPin verification
    enabled: bool = True
    
    # Policy enforcement mode: "enforce", "warn", "log"
    policy_mode: str = "warn"
    
    # Automatically pin keys for trusted domains
    auto_pin_keys: bool = False
    
    # Path to key pinning database
    key_pin_storage_path: str = "schemapin_keys.db"
```

#### Network Settings

```python
    # Timeout for key discovery requests (seconds)
    discovery_timeout: int = 30
    
    # Cache TTL for verification results (seconds)
    cache_ttl: int = 3600
    
    # Custom .well-known endpoints
    well_known_endpoints: Dict[str, str] = field(default_factory=dict)
```

#### Security Settings

```python
    # Domains trusted for auto-pinning
    trusted_domains: List[str] = field(default_factory=list)
    
    # Check key revocation lists
    revocation_check: bool = True
    
    # Enable interactive key confirmation prompts
    interactive_mode: bool = True
```

### Policy Modes

#### Enforce Mode
```python
config = SchemaPinConfig(policy_mode="enforce")
```
- **Behavior**: Blocks tool execution on verification failure
- **Use Case**: Production environments with critical security requirements
- **Risk**: May break functionality if schemas aren't properly signed

#### Warn Mode
```python
config = SchemaPinConfig(policy_mode="warn")
```
- **Behavior**: Logs warnings but allows execution
- **Use Case**: Gradual rollout and monitoring
- **Risk**: Low - maintains functionality while providing security visibility

#### Log Mode
```python
config = SchemaPinConfig(policy_mode="log")
```
- **Behavior**: Logs verification events without blocking
- **Use Case**: Initial deployment and testing
- **Risk**: Minimal - provides monitoring without impact

### Environment-Specific Configurations

#### Development Environment
```python
dev_config = SchemaPinConfig(
    enabled=True,
    policy_mode="log",
    auto_pin_keys=True,
    interactive_mode=False,
    discovery_timeout=10
)
```

#### Staging Environment
```python
staging_config = SchemaPinConfig(
    enabled=True,
    policy_mode="warn",
    auto_pin_keys=False,
    trusted_domains=["staging-api.company.com"],
    interactive_mode=True
)
```

#### Production Environment
```python
prod_config = SchemaPinConfig(
    enabled=True,
    policy_mode="enforce",
    auto_pin_keys=True,
    key_pin_storage_path="/secure/path/keys.db",
    trusted_domains=[
        "api.company.com",
        "tools.company.com"
    ],
    well_known_endpoints={
        "api.company.com": "https://api.company.com/.well-known/schemapin.json"
    },
    revocation_check=True,
    interactive_mode=False,
    cache_ttl=7200
)
```

## Usage Patterns

### Basic Verification

```python
from mockloop_mcp.schemapin import SchemaVerificationInterceptor

# Initialize interceptor
interceptor = SchemaVerificationInterceptor(config)

# Verify tool schema
result = await interceptor.verify_tool_schema(
    tool_name="database_query",
    schema={
        "name": "database_query",
        "description": "Execute SQL queries",
        "parameters": {"type": "object"}
    },
    signature="eyJhbGciOiJFUzI1NiJ9...",  # Base64 ECDSA signature
    domain="api.example.com"
)

if result.valid:
    print("✓ Schema verification successful")
    print(f"Key pinned: {result.key_pinned}")
else:
    print(f"✗ Verification failed: {result.error}")
```

### Batch Verification

For better performance when verifying multiple tools:

```python
from mockloop_mcp.schemapin import SchemaPinWorkflowManager

workflow = SchemaPinWorkflowManager(config)

tools = [
    {
        "name": "tool1",
        "schema": schema1,
        "signature": sig1,
        "domain": "api.example.com"
    },
    {
        "name": "tool2", 
        "schema": schema2,
        "signature": sig2,
        "domain": "api.example.com"
    }
]

results = await workflow.verify_tool_batch(tools)

for i, result in enumerate(results):
    tool = tools[i]
    print(f"{tool['name']}: {'✓' if result.valid else '✗'}")
```

### Key Management

#### Manual Key Pinning
```python
from mockloop_mcp.schemapin import KeyPinningManager

key_manager = KeyPinningManager("keys.db")

# Pin a key manually
success = key_manager.pin_key(
    tool_id="api.example.com/database_query",
    domain="api.example.com",
    public_key_pem=public_key,
    metadata={
        "developer": "Example Corp",
        "version": "1.0.0",
        "pinned_by": "admin"
    }
)

if success:
    print("✓ Key pinned successfully")
```

#### Key Discovery
```python
# Discover public key from .well-known endpoint
discovered_key = await key_manager.discover_public_key(
    domain="api.example.com",
    timeout=30
)

if discovered_key:
    print("✓ Public key discovered")
    print(f"Key: {discovered_key[:50]}...")
```

#### Key Information
```python
# Get detailed key information
key_info = key_manager.get_key_info("api.example.com/database_query")

if key_info:
    print(f"Domain: {key_info['domain']}")
    print(f"Pinned at: {key_info['pinned_at']}")
    print(f"Verification count: {key_info['verification_count']}")
    print(f"Metadata: {key_info['metadata']}")
```

### Policy Enforcement

#### Custom Policy Handler
```python
from mockloop_mcp.schemapin import PolicyHandler, PolicyAction

policy_handler = PolicyHandler(config)

# Set tool-specific policy overrides
policy_handler.set_policy_override("critical_tool", "enforce")
policy_handler.set_policy_override("dev_tool", "log")

# Evaluate verification result
decision = await policy_handler.evaluate_verification_result(
    verification_result, "tool_name"
)

if decision.action == PolicyAction.BLOCK:
    print("🚫 Tool execution blocked")
elif decision.action == PolicyAction.WARN:
    print("⚠️ Tool execution allowed with warning")
elif decision.action == PolicyAction.LOG:
    print("📝 Tool execution logged")
```

### MCP Proxy Integration

```python
class SecureMCPProxy:
    def __init__(self, config: SchemaPinConfig):
        self.interceptor = SchemaVerificationInterceptor(config)
        self.request_cache = {}
    
    async def proxy_tool_request(self, tool_name: str, schema: dict,
                               signature: str, domain: str, request_data: dict):
        # Verify schema before proxying
        result = await self.interceptor.verify_tool_schema(
            tool_name, schema, signature, domain
        )
        
        if not result.valid:
            return {
                "error": "Schema verification failed",
                "details": result.error,
                "tool_id": result.tool_id
            }
        
        # Cache verification result
        cache_key = f"{domain}/{tool_name}"
        self.request_cache[cache_key] = {
            "verified_at": time.time(),
            "result": result
        }
        
        # Execute tool with verified schema
        return await self.execute_tool(tool_name, request_data)
```

### Audit and Monitoring

#### Audit Logging
```python
from mockloop_mcp.schemapin import SchemaPinAuditLogger

audit_logger = SchemaPinAuditLogger("audit.db")

# Get verification statistics
stats = audit_logger.get_verification_stats()

print(f"Total verifications: {stats['total_verifications']}")
print(f"Success rate: {stats['successful_verifications'] / stats['total_verifications'] * 100:.1f}%")
print(f"Unique tools: {stats['unique_tools']}")
print(f"Unique domains: {stats['unique_domains']}")

# Policy breakdown
if 'policy_breakdown' in stats:
    print("\nPolicy actions:")
    for action, count in stats['policy_breakdown'].items():
        print(f"  {action}: {count}")
```

#### Compliance Reporting
```python
from mockloop_mcp.mcp_compliance import MCPComplianceReporter

reporter = MCPComplianceReporter("audit.db")

# Generate SchemaPin compliance report
report = reporter.generate_schemapin_compliance_report(
    start_date="2023-01-01T00:00:00Z",
    end_date="2023-12-31T23:59:59Z"
)

print(f"Compliance score: {report['compliance_score']:.1f}%")
print(f"Total verifications: {report['verification_statistics']['total_verifications']}")
print(f"Policy enforcement: {report['policy_enforcement']}")
```

## Security Considerations

### Threat Model

#### MCP Rug Pull Attacks
- **Attack Vector**: Malicious modification of tool schemas
- **Impact**: Unauthorized data access, privilege escalation, data exfiltration
- **Mitigation**: Cryptographic signature verification with ECDSA P-256

#### Man-in-the-Middle Attacks
- **Attack Vector**: Interception of key discovery requests
- **Impact**: Compromised public key verification
- **Mitigation**: HTTPS for key discovery, key pinning with TOFU model

#### Key Compromise
- **Attack Vector**: Theft or unauthorized access to private keys
- **Impact**: Ability to sign malicious schemas
- **Mitigation**: Secure key storage, key rotation, revocation checking

### Best Practices

#### Key Management
1. **Secure Storage**: Store private keys in HSMs or encrypted storage
2. **Key Rotation**: Regularly rotate signing keys
3. **Access Control**: Limit access to signing keys
4. **Revocation**: Implement key revocation procedures

#### Policy Configuration
1. **Gradual Rollout**: Start with log mode, progress to warn, then enforce
2. **Tool-Specific Policies**: Use different policies for different risk levels
3. **Regular Review**: Periodically review and update policies
4. **Exception Handling**: Plan for verification failures

#### Monitoring and Alerting
1. **Verification Monitoring**: Track verification success rates
2. **Policy Violations**: Alert on blocked executions
3. **Key Events**: Monitor key pinning and discovery events
4. **Compliance Reporting**: Regular compliance assessments

### Production Deployment

#### Security Checklist
- [ ] Private keys stored securely (HSM/encrypted storage)
- [ ] HTTPS enabled for all key discovery endpoints
- [ ] Audit logging configured and monitored
- [ ] Policy modes appropriate for environment
- [ ] Trusted domains properly configured
- [ ] Revocation checking enabled
- [ ] Backup and recovery procedures in place

#### Performance Considerations
- **Verification Latency**: ~5-15ms per tool (acceptable for most use cases)
- **Caching**: Enable result caching to reduce repeated verifications
- **Batch Operations**: Use batch verification for multiple tools
- **Database Optimization**: Regular database maintenance for key storage

## Troubleshooting

### Common Issues

#### Import Errors
```python
# Error: Cannot import SchemaPin components
# Solution: Ensure MockLoop MCP 2.3.0+ is installed
pip install --upgrade mockloop-mcp>=2.3.0

# Verify installation
from mockloop_mcp.schemapin import SchemaPinConfig
print("✓ SchemaPin integration available")
```

#### Key Discovery Failures
```python
# Error: No public key found for domain
# Check 1: Verify .well-known endpoint exists
curl https://api.example.com/.well-known/schemapin.json

# Check 2: Verify network connectivity
import aiohttp
async with aiohttp.ClientSession() as session:
    async with session.get("https://api.example.com/.well-known/schemapin.json") as resp:
        print(f"Status: {resp.status}")
        print(f"Content: {await resp.text()}")

# Check 3: Custom endpoint configuration
config = SchemaPinConfig(
    well_known_endpoints={
        "api.example.com": "https://api.example.com/custom/schemapin.json"
    }
)
```

#### Signature Verification Failures
```python
# Error: Signature verification failed
# Check 1: Verify signature format (base64 encoded)
import base64
try:
    decoded = base64.b64decode(signature)
    print(f"✓ Signature is valid base64: {len(decoded)} bytes")
except Exception as e:
    print(f"✗ Invalid base64 signature: {e}")

# Check 2: Verify schema normalization
from mockloop_mcp.schemapin.verification import SchemaVerificationInterceptor
interceptor = SchemaVerificationInterceptor(config)
normalized = interceptor._normalize_schema(schema)
print(f"Normalized schema: {normalized}")

# Check 3: Manual verification with known good key
result = await interceptor._verify_signature(schema, signature, public_key)
print(f"Manual verification: {result}")
```

#### Database Issues
```python
# Error: Database permission denied
# Solution: Check file permissions
import os
db_path = "schemapin_keys.db"
if os.path.exists(db_path):
    stat = os.stat(db_path)
    print(f"Database permissions: {oct(stat.st_mode)[-3:]}")
else:
    print("Database file does not exist")

# Create with proper permissions
import sqlite3
conn = sqlite3.connect(db_path)
conn.close()
os.chmod(db_path, 0o600)  # Read/write for owner only
```

#### Performance Issues
```python
# Issue: Slow verification times
# Solution 1: Enable caching
config = SchemaPinConfig(cache_ttl=3600)  # 1 hour cache

# Solution 2: Use batch verification
workflow = SchemaPinWorkflowManager(config)
results = await workflow.verify_tool_batch(tools)

# Solution 3: Optimize database
import sqlite3
conn = sqlite3.connect("schemapin_keys.db")
conn.execute("VACUUM")
conn.execute("ANALYZE")
conn.close()
```

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging

# Enable SchemaPin debug logging
logging.getLogger('mockloop_mcp.schemapin').setLevel(logging.DEBUG)

# Create console handler
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add handler to logger
logger = logging.getLogger('mockloop_mcp.schemapin')
logger.addHandler(handler)

print("Debug logging enabled for SchemaPin")
```

### Fallback Behavior

SchemaPin gracefully handles missing dependencies:

```python
# Check if SchemaPin library is available
from mockloop_mcp.schemapin.verification import SCHEMAPIN_AVAILABLE

if SCHEMAPIN_AVAILABLE:
    print("✓ SchemaPin library available - full functionality")
else:
    print("⚠ SchemaPin library not available - using fallback implementation")
    print("Install with: pip install schemapin>=1.0.0")
```

## Migration Guide

### For Existing MockLoop Users

SchemaPin integration is **completely backward compatible**:

#### Phase 1: Installation (Week 1)
```bash
# Upgrade MockLoop MCP
pip install --upgrade mockloop-mcp>=2.3.0

# Optional: Install SchemaPin library
pip install schemapin>=1.0.0
```

#### Phase 2: Monitoring (Weeks 2-3)
```python
# Enable in log mode for monitoring
config = SchemaPinConfig(
    enabled=True,
    policy_mode="log",  # No impact on functionality
    auto_pin_keys=True,
    interactive_mode=False
)

# Monitor verification events
audit_logger = SchemaPinAuditLogger()
stats = audit_logger.get_verification_stats()
print(f"Verification coverage: {stats['unique_tools']} tools")
```

#### Phase 3: Gradual Enforcement (Weeks 4-6)
```python
# Switch to warn mode
config = SchemaPinConfig(
    enabled=True,
    policy_mode="warn",  # Warnings but no blocking
    trusted_domains=["your-trusted-domain.com"]
)

# Monitor warnings and address verification failures
```

#### Phase 4: Full Enforcement (Weeks 7-8)
```python
# Enable enforce mode for critical tools
policy_handler = PolicyHandler(config)
policy_handler.set_policy_override("critical_tool", "enforce")
policy_handler.set_policy_override("admin_tool", "enforce")

# Keep warn mode as default
config = SchemaPinConfig(policy_mode="warn")
```

### Migration Checklist

- [ ] MockLoop MCP upgraded to 2.3.0+
- [ ] SchemaPin library installed (optional)
- [ ] Configuration created and tested
- [ ] Monitoring enabled (log mode)
- [ ] Trusted domains identified
- [ ] Key discovery endpoints verified
- [ ] Audit logging configured
- [ ] Team training completed
- [ ] Rollback plan prepared

### Rollback Plan

If issues arise, SchemaPin can be disabled instantly:

```python
# Disable SchemaPin verification
config = SchemaPinConfig(enabled=False)

# Or set to log-only mode
config = SchemaPinConfig(policy_mode="log")
```

## API Reference

### Core Classes

#### SchemaPinConfig
Configuration class for SchemaPin integration.

```python
@dataclass
class SchemaPinConfig:
    enabled: bool = True
    policy_mode: str = "warn"
    auto_pin_keys: bool = False
    key_pin_storage_path: str = "schemapin_keys.db"
    discovery_timeout: int = 30
    cache_ttl: int = 3600
    well_known_endpoints: Dict[str, str] = field(default_factory=dict)
    trusted_domains: List[str] = field(default_factory=list)
    revocation_check: bool = True
    interactive_mode: bool = True
```

**Methods:**
- `to_dict() -> Dict[str, Any]`: Convert to dictionary
- `from_dict(data: Dict[str, Any]) -> SchemaPinConfig`: Create from dictionary
- `save_to_file(path: str)`: Save configuration to file
- `load_from_file(path: str) -> SchemaPinConfig`: Load from file

#### SchemaVerificationInterceptor
Main verification component.

```python
class SchemaVerificationInterceptor:
    def __init__(self, config: SchemaPinConfig)
    
    async def verify_tool_schema(
        self, 
        tool_name: str, 
        schema: Dict[str, Any],
        signature: str | None = None, 
        domain: str | None = None
    ) -> VerificationResult
```

#### KeyPinningManager
Key management and discovery.

```python
class KeyPinningManager:
    def __init__(self, storage_path: str)
    
    def pin_key(self, tool_id: str, domain: str, public_key_pem: str, 
                metadata: Dict[str, Any] = None) -> bool
    def get_pinned_key(self, tool_id: str) -> str | None
    def is_key_pinned(self, tool_id: str) -> bool
    def revoke_key(self, tool_id: str) -> bool
    def list_pinned_keys(self) -> List[Dict[str, Any]]
    def get_key_info(self, tool_id: str) -> Dict[str, Any] | None
    
    async def discover_public_key(self, domain: str, timeout: int = 30) -> str | None
```

### Data Classes

#### VerificationResult
```python
@dataclass
class VerificationResult:
    valid: bool
    tool_id: str
    domain: str | None = None
    key_pinned: bool = False
    error: str | None = None
    signature: str | None = None
    public_key: str | None = None
    timestamp: float | None = None
```

#### PolicyDecision
```python
@dataclass
class PolicyDecision:
    action: PolicyAction
    reason: str
    policy_mode: str
```

#### PolicyAction
```python
class PolicyAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    PROMPT = "prompt"
```

## Examples

### Complete Integration Example

```python
import asyncio
from mockloop_mcp.schemapin import (
    SchemaPinConfig,
    SchemaVerificationInterceptor,
    KeyPinningManager,
    PolicyHandler,
    SchemaPinAuditLogger
)

async def main():
    # Configuration
    config = SchemaPinConfig(
        enabled=True,
        policy_mode="warn",
        trusted_domains=["api.example.com"],
        auto_pin_keys=True
    )
    
    # Initialize components
    interceptor = SchemaVerificationInterceptor(config)
    key_manager = KeyPinningManager("keys.db")
    audit_logger = SchemaPinAuditLogger("audit.db")
    
    # Example tool schema
    tool_schema = {
        "name": "database_query",
        "description": "Execute SQL queries",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "database": {"type": "string", "default": "main"}
            },
            "required": ["query"]
        }
    }
    
    # Verify schema
    result = await interceptor.verify_tool_schema(
        tool_name="database_query",
        schema=tool_schema,
        signature="eyJhbGciOiJFUzI1NiJ9...",
        domain="api.example.com"
    )
    
    print(f"Verification result: {'✓' if result.valid else '✗'}")
    if result.valid:
        print(f"Key pinned: {result.key_pinned}")
    else:
        print(f"Error: {result.error}")
    
    # Get audit statistics
    stats = audit_logger.get_verification_stats()
    print(f"Total verifications: {stats.get('total_verifications', 0)}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Production Deployment Example

```python
# production_schemapin.py
import os
from mockloop_mcp.schemapin import SchemaPinConfig

def create_production_config():
    """Create production SchemaPin configuration."""
    return SchemaPinConfig(
        enabled=True,
        policy_mode="enforce",
        auto_pin_keys=True,
        key_pin_storage_path=os.getenv("SCHEMAPIN_DB_PATH", "/secure/keys.db"),
        discovery_timeout=60,
        cache_ttl=7200,
        trusted_domains=[
            "api.company.com",
            "tools.company.com",
            "internal.company.com"
        ],
        well_known_endpoints={
            "api.company.com": "https://api.company.com/.well-known/schemapin.json",
            "legacy.company.com": "https://legacy.company.com/security/schemapin.json"
        },
        revocation_check=True,
        interactive_mode=False
    )

# Usage
config = create_production_config()
config.save_to_file("/etc/mockloop/schemapin.json")
```

For more examples, see:
- [`examples/schemapin/basic_usage.py`](../../examples/schemapin/basic_usage.py)
- [`examples/schemapin/advanced_usage.py`](../../examples/schemapin/advanced_usage.py)

---

## Support

For additional support:
- **Documentation**: [MockLoop MCP Documentation](https://docs.mockloop.com)
- **Issues**: [GitHub Issues](https://github.com/mockloop/mockloop-mcp/issues)
- **Examples**: [`examples/schemapin/`](../../examples/schemapin/)
- **Architecture**: [Integration Architecture](../../SchemaPin_MockLoop_Integration_Architecture.md)