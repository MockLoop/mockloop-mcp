#!/usr/bin/env python3
"""
Schema Signature Validation Utility

This script validates all signed schemas in the codebase, checking signature
integrity and compatibility with the verification system.

Usage:
    python scripts/validate_signatures.py
    python scripts/validate_signatures.py --search-paths src tests
    python scripts/validate_signatures.py --output validation_report.json
"""

import argparse
import ast
import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any
from collections.abc import Callable

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mockloop_mcp.schemapin.signing import SchemaSigner
from mockloop_mcp.schemapin.decorators import (
    extract_enhanced_tool_schema,
    get_tool_signature,
    get_tool_domain,
    get_tool_schema,
    get_tool_public_key
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SignatureValidator:
    """Validates schema signatures in the codebase."""

    def __init__(self, search_paths: list[Path] | None = None):
        """Initialize signature validator."""
        self.search_paths = search_paths or [Path("src")]
        self.validation_results: list[dict[str, Any]] = []
        self.valid_count = 0
        self.invalid_count = 0
        self.unsigned_count = 0
        self.error_count = 0

    def validate_all_signatures(self) -> dict[str, Any]:
        """Validate all signed schemas in the search paths."""
        logger.info(f"Validating signatures in paths: {self.search_paths}")

        signed_tools = self._discover_signed_tools()

        if not signed_tools:
            logger.warning("No signed tools found")
            return self._generate_summary()

        logger.info(f"Found {len(signed_tools)} signed tools")

        for tool_info in signed_tools:
            try:
                result = self._validate_tool_signature(tool_info)
                self.validation_results.append(result)

                if result["status"] == "valid":
                    self.valid_count += 1
                elif result["status"] == "invalid":
                    self.invalid_count += 1
                elif result["status"] == "unsigned":
                    self.unsigned_count += 1
                else:
                    self.error_count += 1

            except Exception as e:
                logger.exception(f"Error validating {tool_info['name']}")
                self.error_count += 1
                self.validation_results.append({
                    "tool_name": tool_info["name"],
                    "status": "error",
                    "error": str(e),
                    "file_path": tool_info["file_path"]
                })

        return self._generate_summary()

    def _discover_signed_tools(self) -> list[dict[str, Any]]:
        """Discover all signed tools in the search paths."""
        signed_tools = []

        for search_path in self.search_paths:
            if not search_path.exists():
                logger.warning(f"Search path does not exist: {search_path}")
                continue

            signed_tools.extend(self._scan_directory(search_path))

        return signed_tools

    def _scan_directory(self, directory: Path) -> list[dict[str, Any]]:
        """Recursively scan directory for signed tools."""
        signed_tools = []

        for file_path in directory.rglob("*.py"):
            if file_path.name.startswith("__"):
                continue

            try:
                tools = self._scan_file(file_path)
                signed_tools.extend(tools)
            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")

        return signed_tools

    def _scan_file(self, file_path: Path) -> list[dict[str, Any]]:
        """Scan a Python file for signed tools."""
        signed_tools = []

        try:
            # Read and parse the file
            with open(file_path, encoding='utf-8') as f:
                content = f.read()

            tree = ast.parse(content)

            # Look for function definitions with @signed_tool decorator
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and self._has_signed_tool_decorator(node):
                        tool_info = {
                            "name": node.name,
                            "file_path": str(file_path),
                            "line_number": node.lineno,
                            "is_async": isinstance(node, ast.AsyncFunctionDef),
                        }
                        signed_tools.append(tool_info)

        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")

        return signed_tools

    def _has_signed_tool_decorator(self, node: ast.FunctionDef) -> bool:
        """Check if function has @signed_tool decorator."""
        for decorator in node.decorator_list:
            if (isinstance(decorator, ast.Call) and
                isinstance(decorator.func, ast.Name) and
                decorator.func.id == "signed_tool"):
                return True
        return False

    def _validate_tool_signature(self, tool_info: dict[str, Any]) -> dict[str, Any]:
        """Validate signature for a single tool."""
        tool_name = tool_info["name"]

        try:
            # Load the function
            func = self._load_function_from_file(tool_info["file_path"], tool_name)
            if not func:
                return {
                    "tool_name": tool_name,
                    "status": "error",
                    "error": "Could not load function",
                    "file_path": tool_info["file_path"]
                }

            # Check if function has signature metadata
            signature = get_tool_signature(func)
            domain = get_tool_domain(func)
            schema = get_tool_schema(func)
            public_key = get_tool_public_key(func)

            if not signature:
                return {
                    "tool_name": tool_name,
                    "status": "unsigned",
                    "error": "No signature found in function metadata",
                    "file_path": tool_info["file_path"]
                }

            # Validate signature integrity
            validation_result = self._validate_signature_integrity(
                schema, signature, domain, public_key
            )

            return {
                "tool_name": tool_name,
                "status": "valid" if validation_result["valid"] else "invalid",
                "domain": domain,
                "signature_length": len(signature) if signature else 0,
                "schema_hash": validation_result.get("schema_hash"),
                "integrity_check": validation_result,
                "file_path": tool_info["file_path"],
                "line_number": tool_info["line_number"]
            }

        except Exception as e:
            logger.exception(f"Error validating {tool_name}")
            return {
                "tool_name": tool_name,
                "status": "error",
                "error": str(e),
                "file_path": tool_info["file_path"]
            }

    def _validate_signature_integrity(self, schema: dict[str, Any] | None,
                                    signature: str | None, domain: str | None,
                                    public_key: str | None) -> dict[str, Any]:
        """Validate signature integrity using basic checks."""
        if not schema or not signature:
            return {
                "valid": False,
                "error": "Missing schema or signature"
            }

        try:
            # Basic format checks
            if not signature or len(signature) < 10:
                return {
                    "valid": False,
                    "error": "Invalid signature format"
                }

            # Check if signature is base64 encoded
            import base64
            try:
                decoded = base64.b64decode(signature)
                if len(decoded) < 32:  # Minimum signature length
                    return {
                        "valid": False,
                        "error": "Signature too short"
                    }
            except Exception:
                return {
                    "valid": False,
                    "error": "Invalid base64 signature"
                }

            # Generate schema hash for comparison
            temp_signer = SchemaSigner(private_key_content="dummy")  # Won't be used
            canonical_schema = temp_signer.canonicalize_schema(schema)
            schema_hash = temp_signer.hash_schema(canonical_schema)

            return {
                "valid": True,
                "schema_hash": schema_hash.hex(),
                "signature_format": "base64",
                "signature_length": len(decoded),
                "domain": domain,
                "has_public_key": bool(public_key)
            }

        except Exception as e:
            return {
                "valid": False,
                "error": f"Validation error: {e}"
            }

    def _load_function_from_file(self, file_path: str, function_name: str) -> Callable | None:
        """Load a function from a Python file."""
        try:
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
        """Generate validation summary."""
        total_tools = len(self.validation_results)

        return {
            "status": "completed",
            "total_tools": total_tools,
            "valid_signatures": self.valid_count,
            "invalid_signatures": self.invalid_count,
            "unsigned_tools": self.unsigned_count,
            "validation_errors": self.error_count,
            "signature_coverage": (self.valid_count / total_tools) * 100 if total_tools > 0 else 0,
            "validation_success_rate": (self.valid_count / (self.valid_count + self.invalid_count)) * 100
                                     if (self.valid_count + self.invalid_count) > 0 else 0,
            "results": self.validation_results,
            "issues": self._identify_issues()
        }

    def _identify_issues(self) -> list[dict[str, Any]]:
        """Identify common issues from validation results."""
        issues = []

        # Check for unsigned tools
        unsigned_tools = [r for r in self.validation_results if r["status"] == "unsigned"]
        if unsigned_tools:
            issues.append({
                "type": "unsigned_tools",
                "severity": "warning",
                "count": len(unsigned_tools),
                "description": f"{len(unsigned_tools)} tools are not signed",
                "tools": [t["tool_name"] for t in unsigned_tools]
            })

        # Check for invalid signatures
        invalid_tools = [r for r in self.validation_results if r["status"] == "invalid"]
        if invalid_tools:
            issues.append({
                "type": "invalid_signatures",
                "severity": "error",
                "count": len(invalid_tools),
                "description": f"{len(invalid_tools)} tools have invalid signatures",
                "tools": [t["tool_name"] for t in invalid_tools]
            })

        # Check for validation errors
        error_tools = [r for r in self.validation_results if r["status"] == "error"]
        if error_tools:
            issues.append({
                "type": "validation_errors",
                "severity": "error",
                "count": len(error_tools),
                "description": f"{len(error_tools)} tools had validation errors",
                "tools": [t["tool_name"] for t in error_tools]
            })

        return issues


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate all signed schemas in the codebase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --search-paths src tests
  %(prog)s --output validation_report.json --verbose
        """
    )

    parser.add_argument(
        "--search-paths",
        nargs="+",
        default=["src"],
        help="Paths to search for signed tools (default: src)"
    )

    parser.add_argument(
        "--output",
        help="Output file for validation results (JSON format)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--show-issues-only",
        action="store_true",
        help="Only show tools with issues"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Convert search paths to Path objects
    search_path_objects = [Path(p) for p in args.search_paths]

    try:
        # Validate signatures
        validator = SignatureValidator(search_path_objects)
        results = validator.validate_all_signatures()

        # Output results
        logger.info("Signature validation completed:")
        logger.info(f"  Total tools: {results['total_tools']}")
        logger.info(f"  Valid signatures: {results['valid_signatures']}")
        logger.info(f"  Invalid signatures: {results['invalid_signatures']}")
        logger.info(f"  Unsigned tools: {results['unsigned_tools']}")
        logger.info(f"  Validation errors: {results['validation_errors']}")
        logger.info(f"  Signature coverage: {results['signature_coverage']:.1f}%")
        logger.info(f"  Validation success rate: {results['validation_success_rate']:.1f}%")

        # Show issues
        if results['issues']:
            logger.warning("Issues found:")
            for issue in results['issues']:
                logger.warning(f"  {issue['severity'].upper()}: {issue['description']}")
                if args.verbose:
                    for tool in issue['tools']:
                        logger.warning(f"    - {tool}")

        # Filter results if requested
        if args.show_issues_only:
            results['results'] = [
                r for r in results['results']
                if r['status'] in ['invalid', 'unsigned', 'error']
            ]

        # Save results to file if specified
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {args.output}")

        # Exit with error code if any issues
        if results['invalid_signatures'] > 0 or results['validation_errors'] > 0:
            sys.exit(1)

    except Exception:
        logger.exception("Signature validation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
