#!/usr/bin/env python3
"""
Batch Schema Signing Utility

This script discovers and signs all MCP tools in the codebase using the
SchemaSigner class. It supports specifying private keys and domains via
command line arguments.

Usage:
    python scripts/sign_all_schemas.py --domain example.com --private-key /path/to/key.pem
    python scripts/sign_all_schemas.py --domain example.com --private-key-content "-----BEGIN PRIVATE KEY-----..."
    python scripts/sign_all_schemas.py --config /path/to/config.json
"""

import argparse
import ast
import importlib.util
import inspect
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any
from collections.abc import Callable

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mockloop_mcp.schemapin.signing import SchemaSigner
from mockloop_mcp.schemapin.decorators import extract_enhanced_tool_schema, list_signed_tools
from mockloop_mcp.schemapin.config import SchemaPinConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ToolDiscovery:
    """Discovers MCP tools in the codebase."""

    def __init__(self, search_paths: list[Path] | None = None):
        """Initialize tool discovery with search paths."""
        self.search_paths = search_paths or [Path("src")]
        self.discovered_tools: list[dict[str, Any]] = []

    def discover_tools(self) -> list[dict[str, Any]]:
        """Discover all MCP tools in the search paths."""
        logger.info(f"Discovering tools in paths: {self.search_paths}")

        for search_path in self.search_paths:
            if not search_path.exists():
                logger.warning(f"Search path does not exist: {search_path}")
                continue

            self._scan_directory(search_path)

        logger.info(f"Discovered {len(self.discovered_tools)} tools")
        return self.discovered_tools

    def _scan_directory(self, directory: Path) -> None:
        """Recursively scan directory for Python files containing MCP tools."""
        for file_path in directory.rglob("*.py"):
            if file_path.name.startswith("__"):
                continue

            try:
                self._scan_file(file_path)
            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")

    def _scan_file(self, file_path: Path) -> None:
        """Scan a Python file for MCP tool functions."""
        try:
            logger.debug(f"Scanning file: {file_path}")
            # Read and parse the file
            with open(file_path, encoding='utf-8') as f:
                content = f.read()

            tree = ast.parse(content)

            # Look for function definitions with MCP tool decorators
            function_count = 0
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    function_count += 1
                    logger.debug(f"Found function: {node.name} (async: {isinstance(node, ast.AsyncFunctionDef)})")

                    # Debug decorator information
                    for i, decorator in enumerate(node.decorator_list):
                        logger.debug(f"  Decorator {i}: {ast.dump(decorator)}")

                    if self._is_mcp_tool_function(node):
                        logger.debug(f"  -> MCP tool function detected: {node.name}")
                        tool_info = self._extract_tool_info(node, file_path)
                        if tool_info:
                            self.discovered_tools.append(tool_info)
                            logger.debug(f"  -> Tool info extracted: {tool_info}")

            logger.debug(f"File {file_path.name}: {function_count} functions found")

        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")

    def _is_mcp_tool_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if a function is an MCP tool based on decorators."""
        for decorator in node.decorator_list:
            # Handle simple decorator names
            if isinstance(decorator, ast.Name):
                if decorator.id in ["mcp_tool_audit", "signed_tool"]:
                    return True
            # Handle decorator calls like @signed_tool(...) or @mcp_tool_audit(...)
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    if decorator.func.id in ["mcp_tool_audit", "signed_tool"]:
                        return True
                # Handle attribute access like @module.decorator
                elif isinstance(decorator.func, ast.Attribute) and decorator.func.attr in ["mcp_tool_audit", "signed_tool"]:
                    return True
        return False

    def _extract_tool_info(self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: Path) -> dict[str, Any] | None:
        """Extract tool information from AST node."""
        try:
            return {
                "name": node.name,
                "file_path": str(file_path),
                "line_number": node.lineno,
                "is_async": isinstance(node, ast.AsyncFunctionDef),
                "docstring": ast.get_docstring(node),
                "already_signed": self._has_signed_tool_decorator(node),
            }
        except Exception as e:
            logger.debug(f"Error extracting tool info for {node.name}: {e}")
            return None

    def _has_signed_tool_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if function already has @signed_tool decorator."""
        for decorator in node.decorator_list:
            if (isinstance(decorator, ast.Call) and
                isinstance(decorator.func, ast.Name) and
                decorator.func.id == "signed_tool"):
                return True
        return False


class BatchSigner:
    """Handles batch signing of MCP tools."""

    def __init__(self, domain: str, private_key_path: str | None = None,
                 private_key_content: str | None = None):
        """Initialize batch signer with signing configuration."""
        self.domain = domain
        self.signer = SchemaSigner(
            private_key_path=private_key_path,
            private_key_content=private_key_content
        )
        self.signed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.results: list[dict[str, Any]] = []

    def sign_tools(self, tools: list[dict[str, Any]], force_resign: bool = False) -> dict[str, Any]:
        """Sign all discovered tools."""
        logger.info(f"Starting batch signing of {len(tools)} tools for domain: {self.domain}")

        for tool in tools:
            try:
                result = self._sign_tool(tool, force_resign)
                self.results.append(result)

                if result["status"] == "signed":
                    self.signed_count += 1
                elif result["status"] == "skipped":
                    self.skipped_count += 1
                else:
                    self.failed_count += 1

            except Exception as e:
                logger.exception(f"Error signing tool {tool['name']}")
                self.failed_count += 1
                self.results.append({
                    "tool_name": tool["name"],
                    "status": "error",
                    "error": str(e),
                    "file_path": tool["file_path"]
                })

        return self._generate_summary()

    def _sign_tool(self, tool: dict[str, Any], force_resign: bool) -> dict[str, Any]:
        """Sign a single tool."""
        tool_name = tool["name"]

        # Skip if already signed and not forcing re-sign
        if tool["already_signed"] and not force_resign:
            logger.info(f"Skipping {tool_name} - already signed")
            return {
                "tool_name": tool_name,
                "status": "skipped",
                "reason": "already_signed",
                "file_path": tool["file_path"]
            }

        try:
            # Load the module and get the function
            func = self._load_function_from_file(tool["file_path"], tool_name)
            if not func:
                return {
                    "tool_name": tool_name,
                    "status": "error",
                    "error": "Could not load function",
                    "file_path": tool["file_path"]
                }

            # Extract schema
            schema = extract_enhanced_tool_schema(func)

            # Generate signature
            signature = self.signer.sign_schema(schema)

            # Verify signature
            is_valid = self.signer.verify_own_signature(schema, signature)

            logger.info(f"Signed {tool_name} - signature valid: {is_valid}")

            return {
                "tool_name": tool_name,
                "status": "signed",
                "signature": signature,
                "domain": self.domain,
                "schema_hash": self.signer.hash_schema(
                    self.signer.canonicalize_schema(schema)
                ).hex(),
                "signature_valid": is_valid,
                "file_path": tool["file_path"],
                "public_key": self.signer.get_public_key_pem()
            }

        except Exception as e:
            logger.exception(f"Failed to sign {tool_name}")
            return {
                "tool_name": tool_name,
                "status": "error",
                "error": str(e),
                "file_path": tool["file_path"]
            }

    def _load_function_from_file(self, file_path: str, function_name: str) -> Callable | None:
        """Load a function from a Python file."""
        try:
            # Convert file path to module path
            file_path_obj = Path(file_path)

            # Handle the specific case of mcp_tools.py
            if file_path_obj.name == "mcp_tools.py":
                # Import the module directly using the package structure
                import sys
                if str(file_path_obj.parent.parent) not in sys.path:
                    sys.path.insert(0, str(file_path_obj.parent.parent))

                try:
                    import mockloop_mcp.mcp_tools as mcp_tools_module
                    return getattr(mcp_tools_module, function_name, None)
                except ImportError as e:
                    logger.debug(f"Import error for mcp_tools: {e}")
                    return None

            # Fallback to generic module loading
            spec = importlib.util.spec_from_file_location("module", file_path)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            return getattr(module, function_name, None)
        except Exception as e:
            logger.debug(f"Error loading function {function_name} from {file_path}: {e}")
            return None

    def _generate_summary(self) -> dict[str, Any]:
        """Generate signing summary."""
        return {
            "status": "completed",
            "domain": self.domain,
            "total_tools": len(self.results),
            "signed_count": self.signed_count,
            "skipped_count": self.skipped_count,
            "failed_count": self.failed_count,
            "success_rate": (self.signed_count / len(self.results)) * 100 if self.results else 0,
            "results": self.results
        }


def load_config_file(config_path: str) -> dict[str, Any]:
    """Load configuration from JSON file."""
    try:
        with open(config_path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        logger.exception(f"Error loading config file {config_path}")
        sys.exit(1)


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    if args.config:
        if not Path(args.config).exists():
            logger.error(f"Config file not found: {args.config}")
            sys.exit(1)
        return

    # Check command line args and environment variables
    domain = args.domain or os.getenv("MOCKLOOP_SIGNING_DOMAIN")
    private_key_path = args.private_key or os.getenv("MOCKLOOP_PRIVATE_KEY_PATH")
    private_key_content = args.private_key_content

    if not domain:
        logger.error("Domain is required (use --domain or MOCKLOOP_SIGNING_DOMAIN env var)")
        sys.exit(1)

    if not private_key_path and not private_key_content:
        logger.error("Either --private-key, --private-key-content, or MOCKLOOP_PRIVATE_KEY_PATH env var is required")
        sys.exit(1)

    if args.private_key and args.private_key_content:
        logger.error("Cannot specify both --private-key and --private-key-content")
        sys.exit(1)

    if private_key_path and not Path(private_key_path).exists():
        logger.error(f"Private key file not found: {private_key_path}")
        sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Batch sign all MCP tools in the codebase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --domain example.com --private-key /path/to/key.pem
  %(prog)s --domain example.com --private-key-content "-----BEGIN PRIVATE KEY-----..."
  %(prog)s --config /path/to/config.json --force-resign
        """
    )

    parser.add_argument(
        "--domain",
        help="Domain for signing (e.g., example.com)"
    )

    parser.add_argument(
        "--private-key",
        help="Path to private key file"
    )

    parser.add_argument(
        "--private-key-content",
        help="Private key content as string"
    )

    parser.add_argument(
        "--config",
        help="Path to configuration JSON file"
    )

    parser.add_argument(
        "--search-paths",
        nargs="+",
        default=["src"],
        help="Paths to search for MCP tools (default: src)"
    )

    parser.add_argument(
        "--force-resign",
        action="store_true",
        help="Force re-signing of already signed tools"
    )

    parser.add_argument(
        "--output",
        help="Output file for signing results (JSON format)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    validate_arguments(args)

    # Load configuration
    if args.config:
        config_data = load_config_file(args.config)
        domain = config_data.get("domain")
        private_key_path = config_data.get("private_key_path")
        private_key_content = config_data.get("private_key_content")
        search_paths = config_data.get("search_paths", ["src"])
        force_resign = config_data.get("force_resign", args.force_resign)
    else:
        # Check environment variables if not provided via command line
        domain = args.domain or os.getenv("MOCKLOOP_SIGNING_DOMAIN")
        private_key_path = args.private_key or os.getenv("MOCKLOOP_PRIVATE_KEY_PATH")
        private_key_content = args.private_key_content
        search_paths = args.search_paths
        force_resign = args.force_resign

    if not domain:
        logger.error("Domain must be specified in config or command line")
        sys.exit(1)

    # Convert search paths to Path objects
    search_path_objects = [Path(p) for p in search_paths]

    try:
        # Discover tools
        discovery = ToolDiscovery(search_path_objects)
        tools = discovery.discover_tools()

        if not tools:
            logger.warning("No MCP tools found")
            return

        # Sign tools
        signer = BatchSigner(
            domain=domain,
            private_key_path=private_key_path,
            private_key_content=private_key_content
        )

        results = signer.sign_tools(tools, force_resign)

        # Output results
        logger.info("Batch signing completed:")
        logger.info(f"  Total tools: {results['total_tools']}")
        logger.info(f"  Signed: {results['signed_count']}")
        logger.info(f"  Skipped: {results['skipped_count']}")
        logger.info(f"  Failed: {results['failed_count']}")
        logger.info(f"  Success rate: {results['success_rate']:.1f}%")

        # Save results to file if specified
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {args.output}")

        # Exit with error code if any failures
        if results['failed_count'] > 0:
            sys.exit(1)

    except Exception:
        logger.exception("Batch signing failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
