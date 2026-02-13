# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [2.3.0] - 2025-06-08

### Added
- **🔐 SchemaPin Integration**: Revolutionary cryptographic schema verification for MCP tools
  - ECDSA P-256 signature verification with SHA-256 hashing
  - Trust-On-First-Use (TOFU) key pinning with automatic discovery
  - Configurable security policies: enforce, warn, and log modes
  - Comprehensive audit logging and compliance tracking
  - Hybrid architecture with graceful fallback when SchemaPin library unavailable
  - Complete integration with MockLoop's existing audit and proxy systems
  - 56 comprehensive tests (42 unit + 14 integration tests)
  - Extensive examples and documentation in `examples/schemapin/`
  - New dependency: `schemapin>=1.0.0`
- **📚 Comprehensive Documentation**: Complete SchemaPin integration guide
  - Detailed integration guide at `docs/guides/schemapin-integration.md`
  - Updated main README.md with SchemaPin section
  - Migration guide for existing users
  - Security best practices and threat analysis
  - Troubleshooting guide and API reference

### Security
- **MCP Rug Pull Protection**: Prevents malicious schema modifications through cryptographic verification
- **Enhanced Audit Logging**: SchemaPin verification events integrated with MockLoop's compliance system
- **Key Pinning Security**: TOFU model prevents man-in-the-middle attacks on schema verification
- **Policy-Based Security**: Configurable enforcement levels for different environments
- **Compliance Support**: Audit trails support GDPR, SOX, HIPAA regulatory requirements

### Changed
- Enhanced MCP tool execution flow to include optional schema verification
- Extended audit logging system to support SchemaPin verification events
- Updated proxy configuration to support SchemaPin integration
- Improved security posture with cryptographic schema verification

## [2.2.9] - 2025-06-02

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [2.2.7] - 2025-06-02

### Fixed
- Version synchronization across project files
- Updated version consistency between pyproject.toml and __init__.py

### Changed
- Maintenance release with version alignment improvements

## [2.2.6] - 2025-06-01

### Added
- Comprehensive MCP Proxy functionality enabling mock, proxy, and hybrid modes for API testing.
  - Includes core proxy handling ([`ProxyHandler`](src/mockloop_mcp/proxy/proxy_handler.py:23)), configuration ([`ProxyConfig`](src/mockloop_mcp/proxy/config.py:128), [`AuthConfig`](src/mockloop_mcp/proxy/config.py:32), [`RouteRule`](src/mockloop_mcp/proxy/config.py:100)), authentication management ([`AuthHandler`](src/mockloop_mcp/proxy/auth_handler.py:25)), and plugin management ([`PluginManager`](src/mockloop_mcp/proxy/plugin_manager.py:15)).
  - Integrated proxy capabilities into MCP tools: [`create_mcp_plugin()`](src/mockloop_mcp/mcp_tools.py:997) and [`execute_test_plan()`](src/mockloop_mcp/mcp_tools.py:539).
- Detailed documentation guide for MCP Proxy: [`docs/mcp-proxy-guide.md`](docs/mcp-proxy-guide.md).
- New example scripts in [`examples/mcp-proxy/`](examples/mcp-proxy) demonstrating:
  - Plugin creation in `proxy` and `hybrid` modes: [`create_plugin_modes_example.py`](examples/mcp-proxy/create_plugin_modes_example.py).
  - Executing test plans with a `proxy` mode plugin: [`execute_plan_with_proxy_example.py`](examples/mcp-proxy/execute_plan_with_proxy_example.py).
  - Configuring `hybrid` mode with routing rules: [`hybrid_mode_routing_example.py`](examples/mcp-proxy/hybrid_mode_routing_example.py).
- New end-to-end integration tests for MCP Proxy in [`tests/integration/test_mcp_proxy_integration.py`](tests/integration/test_mcp_proxy_integration.py), covering `proxy` and `hybrid` mode configurations and execution.

### Changed
- Updated [`README.md`](README.md) to include a new section detailing the MCP Proxy functionality and linking to the guide.
- Refined existing example [`examples/mcp-proxy/basic-mock-example.py`](examples/mcp-proxy/basic-mock-example.py) to serve as the primary `mock` mode example and updated its "Next Steps" to reference new, more specific proxy examples.
- Modified [`examples/mcp-proxy/create_plugin_modes_example.py`](examples/mcp-proxy/create_plugin_modes_example.py) to focus solely on `proxy` and `hybrid` modes, deferring `mock` mode to `basic-mock-example.py`.
### Security

## [2.2.5] - 2025-06-01

### Added
- Added `--stdio` support for Claude Code integration
- Dual-mode MCP server supporting both stdio and SSE communication
- Backward compatibility with existing SSE-based MCP clients

### Changed
- Enhanced server startup logic to detect communication mode via command-line flags
- Maintained existing `--cli` and default SSE functionality

## [2.2.4] - 2025-06-01

### Fixed
- Fixed indent errors causing docker containers to fail to start
- Fixed TestPyPI installation failure caused by broken FastAPI package on TestPyPI
- Updated GitHub workflow to use `--index-url` for TestPyPI and `--extra-index-url` for PyPI dependencies
- Updated issue templates with correct TestPyPI installation commands

## [2.2.3] - 2025-05-30

### Fixed
- Fixed critical release workflow issues preventing successful PyPI publication
- Corrected version extraction and validation in GitHub Actions
- Updated workflow permissions for trusted publishing

## [2.2.2] - 2025-05-30

### Security
- Fixed critical SQL injection vulnerability in database migration module
- Added input validation using `isidentifier()` for table and column names
- Prevented malicious SQL injection through PRAGMA table_info queries
- Added proper error handling for invalid database identifiers

## [2.2.1] - 2025-05-30

### Added
- GitHub Actions CI/CD pipeline with comprehensive OIDC permissions
- Workflow-level permissions for trusted publishing to PyPI
- Tag-based release triggers for automated deployment

### Fixed
- OIDC token permission issues in GitHub Actions workflows
- pyproject.toml configuration errors for ruff, mypy, and pytest
- Updated to current stable action versions (v4/v5)
- Resolved TOML parse errors in CI/CD pipeline

### Security
- Enhanced CI/CD security with proper permission scoping

## [2.2.0] - 2025-05-30

### Added
- GitHub Actions CI/CD pipeline for automated testing and PyPI publishing
- Automated release workflow with PyPI trusted publishing
- Comprehensive test matrix for Python 3.10, 3.11, and 3.12
- Security scanning with ruff and bandit in CI pipeline
- Code coverage reporting with Codecov integration
- Package build validation and distribution checks

### Changed
- Updated project version to 2.2.0 for major release
- Enhanced release automation and deployment process
- Improved development workflow with automated quality checks

### Fixed
- Version consistency across all project files
- Configuration file formatting and validation

## [0.1.0] - 2025-05-30

### Added
- Initial release of MockLoop MCP server
- FastAPI mock server generation from OpenAPI specifications
- Authentication middleware support with configurable auth types
- Webhook functionality for external integrations
- Admin UI for server management and monitoring
- Storage capabilities for persistent mock data
- Docker support with automated containerization
- Comprehensive logging and request/response tracking
- MCP tools for generating, querying, and managing mock servers
- Support for dynamic response scenarios and data management
- Integration with MockLoop ecosystem
- Comprehensive test suite with unit and integration tests
- Security workflows and quality assurance tools
- Pre-commit hooks for code quality enforcement
- GitHub Actions CI/CD pipeline
- Code coverage reporting and analysis
- Dependency vulnerability scanning
- Static security analysis with multiple tools

### Security
- Implemented security policy and vulnerability reporting process
- Added automated dependency vulnerability scanning with Dependabot
- Integrated multiple security analysis tools (Bandit, Safety, Semgrep, pip-audit)
- Configured secure coding practices and validation

[2.2.8] - 2025-06-02: https://github.com/mockloop/mockloop-mcp/compare/v2.2.7...HEAD
[2.2.7]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.7
[2.2.6]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.6
[2.2.5]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.5
[2.2.4]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.4
[2.2.3]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.3
[2.2.2]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.2
[2.2.1]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.1
[2.2.0]: https://github.com/mockloop/mockloop-mcp/releases/tag/v2.2.0
[0.1.0]: https://github.com/mockloop/mockloop-mcp/releases/tag/v0.1.0
