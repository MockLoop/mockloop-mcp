#!/usr/bin/env python3
"""
Embed Signature Metadata Script

This script takes the output from sign_all_schemas.py and embeds the signature
metadata directly into the @signed_tool decorators in the source code.
This allows committing signatures to Git for public verification.

Usage:
    python scripts/embed_signatures.py --input signing_results.json
    python scripts/embed_signatures.py --domain mockloop.com --public-key-url https://mockloop.com/.well-known/schemapin/public-key.pem
"""

import argparse
import ast
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SignatureEmbedder:
    """Embeds signature metadata into @signed_tool decorators."""

    def __init__(self, domain: str, public_key_url: str | None = None):
        """Initialize signature embedder."""
        self.domain = domain
        self.public_key_url = public_key_url or f"https://{domain}/.well-known/schemapin/public-key.pem"
        self.updated_files: set[str] = set()

    def embed_from_results(self, results_file: str) -> None:
        """Embed signatures from signing results file."""
        logger.info(f"Loading signing results from {results_file}")
        
        with open(results_file, encoding='utf-8') as f:
            results = json.load(f)
        
        if results.get("status") != "completed":
            raise ValueError(f"Invalid results file: {results_file}")
        
        logger.info(f"Processing {len(results['results'])} signed tools")
        
        for tool_result in results["results"]:
            if tool_result["status"] == "signed":
                self._embed_tool_signature(tool_result)
        
        logger.info(f"Updated {len(self.updated_files)} files")

    def embed_from_environment(self) -> None:
        """Generate signatures and embed them using environment variables."""
        # Import here to avoid circular imports
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        sys.path.insert(0, str(Path(__file__).parent))
        
        # Import the classes directly from the sign_all_schemas module
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "sign_all_schemas",
            Path(__file__).parent / "sign_all_schemas.py"
        )
        if not spec or not spec.loader:
            raise ImportError("Could not load sign_all_schemas module")
        
        sign_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sign_module)
        
        ToolDiscovery = sign_module.ToolDiscovery
        BatchSigner = sign_module.BatchSigner
        
        # Get environment variables
        domain = os.getenv("MOCKLOOP_SIGNING_DOMAIN")
        private_key_path = os.getenv("MOCKLOOP_PRIVATE_KEY_PATH")
        
        if not domain or not private_key_path:
            raise ValueError("MOCKLOOP_SIGNING_DOMAIN and MOCKLOOP_PRIVATE_KEY_PATH environment variables required")
        
        logger.info(f"Generating signatures for domain: {domain}")
        
        # Discover and sign tools
        discovery = ToolDiscovery([Path("src")])
        tools = discovery.discover_tools()
        
        signer = BatchSigner(
            domain=domain,
            private_key_path=private_key_path
        )
        
        results = signer.sign_tools(tools, force_resign=True)
        
        # Embed signatures
        for tool_result in results["results"]:
            if tool_result["status"] == "signed":
                self._embed_tool_signature(tool_result)
        
        logger.info(f"Updated {len(self.updated_files)} files")

    def _embed_tool_signature(self, tool_result: dict[str, Any]) -> None:
        """Embed signature for a single tool."""
        file_path = tool_result["file_path"]
        tool_name = tool_result["tool_name"]
        
        logger.info(f"Embedding signature for {tool_name} in {file_path}")
        
        try:
            # Read the file
            with open(file_path, encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            # Find the function and its decorator
            updated_content = self._update_decorator_in_content(
                content, tool_name, tool_result
            )
            
            if updated_content != content:
                # Write back the updated content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(updated_content)
                
                self.updated_files.add(file_path)
                logger.info(f"Updated {tool_name} in {file_path}")
            else:
                logger.warning(f"No changes made to {tool_name} in {file_path}")
                
        except Exception as e:
            logger.exception(f"Failed to embed signature for {tool_name}")
            raise

    def _update_decorator_in_content(self, content: str, tool_name: str, 
                                   tool_result: dict[str, Any]) -> str:
        """Update the @signed_tool decorator in the content."""
        lines = content.split('\n')
        updated_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # Look for @signed_tool decorator
            if '@signed_tool' in line and not line.strip().startswith('#'):
                # Find the function this decorator belongs to
                func_line_idx = self._find_function_after_decorator(lines, i)
                if func_line_idx and tool_name in lines[func_line_idx]:
                    # Replace the decorator
                    new_decorator = self._generate_embedded_decorator(tool_result)
                    
                    # Handle multi-line decorators
                    decorator_end = self._find_decorator_end(lines, i)
                    
                    # Replace the decorator lines
                    updated_lines.extend(lines[:i])
                    updated_lines.extend(new_decorator.split('\n'))
                    i = decorator_end + 1
                    continue
            
            updated_lines.append(line)
            i += 1
        
        return '\n'.join(updated_lines)

    def _find_function_after_decorator(self, lines: list[str], decorator_idx: int) -> int | None:
        """Find the function definition after a decorator."""
        for i in range(decorator_idx + 1, min(decorator_idx + 10, len(lines))):
            line = lines[i].strip()
            if line.startswith('def ') or line.startswith('async def '):
                return i
        return None

    def _find_decorator_end(self, lines: list[str], start_idx: int) -> int:
        """Find the end of a decorator (handles multi-line decorators)."""
        i = start_idx
        paren_count = 0
        in_decorator = False
        
        while i < len(lines):
            line = lines[i]
            
            if '@signed_tool' in line:
                in_decorator = True
            
            if in_decorator:
                paren_count += line.count('(') - line.count(')')
                
                # If we've closed all parentheses, decorator is complete
                if paren_count == 0 and '(' in lines[start_idx]:
                    return i
                
                # If no parentheses, single line decorator
                if '(' not in lines[start_idx]:
                    return i
            
            i += 1
        
        return start_idx

    def _generate_embedded_decorator(self, tool_result: dict[str, Any]) -> str:
        """Generate the new @signed_tool decorator with embedded metadata."""
        signature = tool_result["signature"]
        schema_hash = tool_result["schema_hash"]
        domain = tool_result["domain"]
        
        # Generate timestamp if not present
        signed_at = tool_result.get("signed_at")
        if not signed_at:
            from datetime import datetime, timezone
            signed_at = datetime.now(timezone.utc).isoformat()
        
        decorator = f'''@signed_tool(
    domain="{domain}",
    signature="{signature}",
    schema_hash="{schema_hash}",
    public_key_url="{self.public_key_url}",
    signed_at="{signed_at}"
)'''
        
        return decorator


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Embed signature metadata into @signed_tool decorators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input signing_results.json
  %(prog)s --domain mockloop.com --public-key-url https://mockloop.com/.well-known/schemapin/public-key.pem
        """
    )

    parser.add_argument(
        "--input",
        help="JSON file with signing results from sign_all_schemas.py"
    )

    parser.add_argument(
        "--domain",
        help="Domain for signatures (used with environment variables)"
    )

    parser.add_argument(
        "--public-key-url",
        help="URL to public key for verification"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        if args.input:
            # Use results file
            if not Path(args.input).exists():
                logger.error(f"Results file not found: {args.input}")
                sys.exit(1)
            
            domain = args.domain
            if not domain:
                # Try to extract domain from results file
                with open(args.input, encoding='utf-8') as f:
                    results = json.load(f)
                    domain = results.get("domain")
            
            if not domain:
                logger.error("Domain must be specified via --domain or present in results file")
                sys.exit(1)
            
            embedder = SignatureEmbedder(domain, args.public_key_url)
            embedder.embed_from_results(args.input)
            
        elif args.domain:
            # Use environment variables
            embedder = SignatureEmbedder(args.domain, args.public_key_url)
            embedder.embed_from_environment()
            
        else:
            logger.error("Either --input or --domain must be specified")
            sys.exit(1)

        logger.info("Signature embedding completed successfully")

    except Exception:
        logger.exception("Signature embedding failed")
        sys.exit(1)


if __name__ == "__main__":
    main()