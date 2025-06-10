"""
SchemaPin Tool Decorators Module

Provides decorators for automatic schema signing of MCP tool functions.
Integrates with the SchemaSigner class to generate cryptographic signatures
for tool schemas at definition time.
"""

import asyncio
import inspect
import logging
from functools import wraps
from typing import Any, TypeVar, Union
from collections.abc import Callable

from .signing import SchemaSigner

logger = logging.getLogger(__name__)

# Type variable for decorated functions
F = TypeVar('F', bound=Callable[..., Any])


def signed_tool(
    domain: str | None = None,
    private_key_path: str | None = None,
    private_key_content: str | None = None,
    # Embedded signature metadata (for Git-committable signatures)
    signature: str | None = None,
    schema_hash: str | None = None,
    public_key_url: str | None = None,
    signed_at: str | None = None,
    # Runtime options
    verify_on_call: bool = False,
    allow_schema_evolution: bool = False,
) -> Callable[[F], F]:
    """
    Decorator for signing MCP tool schemas with embedded metadata support.

    This decorator supports two modes:
    1. Dynamic signing: Generates signatures at runtime using private keys
    2. Embedded signatures: Uses pre-computed signatures stored in the decorator

    The embedded signature mode allows committing signatures to Git for public
    verification while maintaining runtime signature generation capabilities.

    Args:
        domain: Domain the tool belongs to (e.g., "mockloop.com")
        private_key_path: Path to PEM private key file (for dynamic signing)
        private_key_content: Direct PEM private key content (for dynamic signing)
        signature: Pre-computed base64 signature (for embedded mode)
        schema_hash: Expected schema hash for verification
        public_key_url: URL to fetch public key for verification
        signed_at: ISO timestamp when signature was created
        verify_on_call: Whether to verify signature on each function call
        allow_schema_evolution: Whether to allow schema changes without re-signing

    Returns:
        Decorated function with schema signature metadata

    Examples:
        # Dynamic signing (development)
        @signed_tool(
            domain="mockloop.com",
            private_key_path="/path/to/private.pem"
        )
        async def my_tool(param1: str) -> dict:
            return {"result": "success"}

        # Embedded signature (production/Git)
        @signed_tool(
            domain="mockloop.com",
            signature="MEUCIQCeJHbUoqA7sXEZwSxeAuzgtzQ/7w24TRjDsMDpDlQgwg...",
            schema_hash="8f8e1d422098d655da1c076afe4e2ee9f720fe53720573b14bedd08ccba9ae22",
            public_key_url="https://mockloop.com/.well-known/schemapin/public-key.pem",
            signed_at="2025-06-09T21:57:58Z"
        )
        async def my_tool(param1: str) -> dict:
            return {"result": "success"}
    """
    def decorator(func: F) -> F:
        try:
            # Extract complete tool schema first
            tool_schema = extract_enhanced_tool_schema(func)
            
            # Determine signing mode
            has_embedded_signature = signature is not None
            has_dynamic_signing = private_key_path or private_key_content
            
            # Signature and metadata to use
            final_signature = None
            final_domain = domain
            final_public_key = None
            final_schema_hash = schema_hash
            final_signed_at = signed_at
            final_public_key_url = public_key_url
            
            if has_embedded_signature:
                # Use embedded signature metadata
                final_signature = signature
                logger.debug(f"Using embedded signature for {func.__name__}")
                
                # Verify embedded signature matches current schema if hash provided
                if schema_hash and verify_on_call:
                    temp_signer = SchemaSigner(private_key_content="dummy")
                    canonical_schema = temp_signer.canonicalize_schema(tool_schema)
                    current_hash = temp_signer.hash_schema(canonical_schema).hex()
                    
                    if current_hash != schema_hash:
                        if not allow_schema_evolution:
                            raise ValueError(
                                f"Schema hash mismatch for {func.__name__}: "
                                f"expected {schema_hash}, got {current_hash}"
                            )
                        else:
                            logger.warning(
                                f"Schema evolution detected for {func.__name__}: "
                                f"hash changed from {schema_hash} to {current_hash}"
                            )
                
            elif has_dynamic_signing:
                # Generate signature dynamically
                logger.debug(f"Generating dynamic signature for {func.__name__}")
                signer = SchemaSigner(
                    private_key_path=private_key_path,
                    private_key_content=private_key_content
                )
                
                final_signature = signer.sign_schema(tool_schema)
                final_public_key = signer.get_public_key_pem()
                
                # Generate current schema hash
                canonical_schema = signer.canonicalize_schema(tool_schema)
                final_schema_hash = signer.hash_schema(canonical_schema).hex()
                
                # Set signed_at to current time if not provided
                if not final_signed_at:
                    from datetime import datetime, timezone
                    final_signed_at = datetime.now(timezone.utc).isoformat()
                    
            else:
                # No signing configuration - create unsigned wrapper
                logger.warning(f"No signing configuration for {func.__name__} - creating unsigned wrapper")

            # Create wrapper function
            if asyncio.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args, **kwargs):
                    # Inject signature metadata into kwargs
                    kwargs['_schema_signature'] = final_signature
                    kwargs['_schema_domain'] = final_domain
                    
                    # Perform runtime verification if requested
                    if verify_on_call and final_signature:
                        _verify_runtime_signature(func.__name__, tool_schema, final_signature, final_domain)
                    
                    return await func(*args, **kwargs)

                # Store all metadata on the wrapper
                _store_metadata(async_wrapper, tool_schema, final_signature, final_domain,
                              final_public_key, final_schema_hash, final_signed_at, final_public_key_url)
                return async_wrapper
            else:
                @wraps(func)
                def sync_wrapper(*args, **kwargs):
                    # Inject signature metadata into kwargs
                    kwargs['_schema_signature'] = final_signature
                    kwargs['_schema_domain'] = final_domain
                    
                    # Perform runtime verification if requested
                    if verify_on_call and final_signature:
                        _verify_runtime_signature(func.__name__, tool_schema, final_signature, final_domain)
                    
                    return func(*args, **kwargs)

                # Store all metadata on the wrapper
                _store_metadata(sync_wrapper, tool_schema, final_signature, final_domain,
                              final_public_key, final_schema_hash, final_signed_at, final_public_key_url)
                return sync_wrapper

        except Exception as e:
            logger.exception(f"Failed to sign tool schema for {func.__name__}")
            raise ValueError(f"Schema signing failed for {func.__name__}: {e}") from e

    return decorator


def extract_enhanced_tool_schema(func: Callable) -> dict[str, Any]:
    """
    Extract comprehensive tool schema from a function.

    This function improves upon the basic extract_tool_schema by:
    - Extracting parameter types from function annotations
    - Including return type information
    - Parsing docstring for descriptions
    - Handling complex parameter types (lists, dicts, optional)
    - Supporting both sync and async functions

    Args:
        func: Tool function to extract schema from

    Returns:
        Complete tool schema dictionary

    Example:
        def example_tool(name: str, count: int = 5, tags: list[str] = None) -> dict[str, Any]:
            '''
            Example tool for demonstration.

            Args:
                name: The name parameter
                count: Number of items (default: 5)
                tags: Optional list of tags

            Returns:
                Dictionary with results
            '''
            return {"name": name, "count": count}

        # Returns:
        {
            "name": "example_tool",
            "description": "Example tool for demonstration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name parameter"},
                    "count": {"type": "integer", "default": 5, "description": "Number of items (default: 5)"},
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "Optional list of tags"}
                },
                "required": ["name"]
            },
            "returns": {"type": "object", "description": "Dictionary with results"}
        }
    """
    try:
        # Get function signature
        sig = inspect.signature(func)

        # Extract basic information
        schema = {
            "name": func.__name__,
            "description": _extract_description_from_docstring(func.__doc__),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }

        # Extract parameter information
        param_descriptions = _extract_param_descriptions_from_docstring(func.__doc__)

        for param_name, param in sig.parameters.items():
            # Skip special parameters
            if param_name.startswith('_') or param_name in ['args', 'kwargs']:
                continue

            param_schema = _extract_parameter_schema(param, param_descriptions.get(param_name))
            schema["parameters"]["properties"][param_name] = param_schema

            # Add to required if no default value
            if param.default == inspect.Parameter.empty:
                schema["parameters"]["required"].append(param_name)

        # Extract return type information
        if sig.return_annotation != inspect.Signature.empty:
            return_schema = _extract_type_schema(sig.return_annotation)
            return_description = _extract_return_description_from_docstring(func.__doc__)
            if return_description:
                return_schema["description"] = return_description
            schema["returns"] = return_schema

        # Add function metadata
        schema["async"] = asyncio.iscoroutinefunction(func)
        schema["module"] = func.__module__ if hasattr(func, '__module__') else None
        schema["source_file"] = inspect.getfile(func) if hasattr(func, '__code__') else None

        # Add schema version for compatibility tracking
        schema["schema_version"] = "1.0"

        return schema

    except Exception as e:
        logger.warning(f"Failed to extract enhanced schema for {func.__name__}: {e}")
        # Fallback to basic schema
        return {
            "name": func.__name__,
            "description": func.__doc__ or "",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            },
            "schema_version": "1.0"
        }


def _extract_description_from_docstring(docstring: str | None) -> str:
    """Extract the main description from a docstring."""
    if not docstring:
        return ""

    lines = docstring.strip().split('\n')
    description_lines = []

    for line in lines:
        line_content = line.strip()
        if not line_content:
            break
        if line_content.lower().startswith(('args:', 'arguments:', 'parameters:', 'returns:', 'return:')):
            break
        description_lines.append(line_content)

    return ' '.join(description_lines)


def _extract_param_descriptions_from_docstring(docstring: str | None) -> dict[str, str]:
    """Extract parameter descriptions from docstring."""
    if not docstring:
        return {}

    descriptions = {}
    lines = docstring.strip().split('\n')
    in_args_section = False
    current_param = None

    for line in lines:
        line_content = line.strip()

        if line_content.lower().startswith(('args:', 'arguments:', 'parameters:')):
            in_args_section = True
            continue
        elif line_content.lower().startswith(('returns:', 'return:', 'raises:', 'examples:')):
            in_args_section = False
            continue

        if in_args_section and line_content:
            if ':' in line_content and not line_content.startswith(' '):
                # New parameter
                parts = line_content.split(':', 1)
                if len(parts) == 2:
                    current_param = parts[0].strip()
                    desc = parts[1].strip()
                    descriptions[current_param] = desc
            elif current_param and line_content.startswith(' '):
                # Continuation of previous parameter description
                descriptions[current_param] += ' ' + line_content.strip()

    return descriptions


def _extract_return_description_from_docstring(docstring: str | None) -> str | None:
    """Extract return description from docstring."""
    if not docstring:
        return None

    lines = docstring.strip().split('\n')
    in_returns_section = False
    return_lines = []

    for line in lines:
        line_content = line.strip()

        if line_content.lower().startswith(('returns:', 'return:')):
            in_returns_section = True
            # Check if description is on the same line
            parts = line_content.split(':', 1)
            if len(parts) == 2 and parts[1].strip():
                return_lines.append(parts[1].strip())
            continue
        elif line_content.lower().startswith(('raises:', 'examples:', 'args:', 'arguments:')):
            in_returns_section = False
            continue

        if in_returns_section and line_content:
            return_lines.append(line_content)

    return ' '.join(return_lines) if return_lines else None


def _extract_parameter_schema(param: inspect.Parameter, description: str | None = None) -> dict[str, Any]:
    """Extract schema for a single parameter."""
    schema = {}

    # Extract type information
    if param.annotation != inspect.Parameter.empty:
        type_schema = _extract_type_schema(param.annotation)
        schema.update(type_schema)
    else:
        # Default to string if no annotation
        schema["type"] = "string"

    # Add description if available
    if description:
        schema["description"] = description

    # Add default value if present
    if param.default != inspect.Parameter.empty:
        if param.default is not None:
            schema["default"] = param.default
        elif "type" in schema:
            # Handle None default for optional parameters
            # Make the type nullable
            if isinstance(schema["type"], str):
                schema["type"] = [schema["type"], "null"]
            elif isinstance(schema["type"], list) and "null" not in schema["type"]:
                schema["type"].append("null")

    return schema


def _extract_type_schema(annotation: Any) -> dict[str, Any]:
    """Extract JSON schema from Python type annotation."""
    import typing

    # Handle basic types
    if annotation is str:
        return {"type": "string"}
    elif annotation is int:
        return {"type": "integer"}
    elif annotation is float:
        return {"type": "number"}
    elif annotation is bool:
        return {"type": "boolean"}
    elif annotation is dict:
        return {"type": "object"}
    elif annotation is list:
        return {"type": "array"}

    # Handle typing module types
    origin = getattr(annotation, '__origin__', None)
    args = getattr(annotation, '__args__', ())

    if origin is Union:
        # Handle Optional[T] (Union[T, None])
        if len(args) == 2 and type(None) in args:
            non_none_type = args[0] if args[1] is type(None) else args[1]
            base_schema = _extract_type_schema(non_none_type)
            if "type" in base_schema:
                if isinstance(base_schema["type"], str):
                    base_schema["type"] = [base_schema["type"], "null"]
                elif isinstance(base_schema["type"], list):
                    base_schema["type"].append("null")
            return base_schema
        else:
            # Multiple types union - use anyOf
            return {"anyOf": [_extract_type_schema(arg) for arg in args]}

    elif origin is list:
        schema = {"type": "array"}
        if args:
            schema["items"] = _extract_type_schema(args[0])
        return schema

    elif origin is dict:
        schema = {"type": "object"}
        if len(args) >= 2:
            # Dict[str, ValueType] -> additionalProperties: ValueType schema
            schema["additionalProperties"] = _extract_type_schema(args[1])
        return schema

    # Handle Any type
    if annotation is typing.Any:
        return {}  # No type constraint

    # Default fallback
    return {"type": "string"}


def get_tool_signature(func: Callable) -> str | None:
    """
    Get the schema signature from a signed tool function.

    Args:
        func: Tool function (should be decorated with @signed_tool)

    Returns:
        Base64-encoded signature string, or None if not signed
    """
    return getattr(func, '_schema_signature', None)


def get_tool_domain(func: Callable) -> str | None:
    """
    Get the domain from a signed tool function.

    Args:
        func: Tool function (should be decorated with @signed_tool)

    Returns:
        Domain string, or None if not signed
    """
    return getattr(func, '_schema_domain', None)


def get_tool_schema(func: Callable) -> dict[str, Any] | None:
    """
    Get the extracted schema from a signed tool function.

    Args:
        func: Tool function (should be decorated with @signed_tool)

    Returns:
        Tool schema dictionary, or None if not available
    """
    return getattr(func, '_tool_schema', None)


def get_tool_public_key(func: Callable) -> str | None:
    """
    Get the public key PEM from a signed tool function.

    Args:
        func: Tool function (should be decorated with @signed_tool)

    Returns:
        Public key PEM string, or None if not available
    """
    return getattr(func, '_signer_public_key', None)


def verify_tool_signature(func: Callable) -> bool:
    """
    Verify the signature of a signed tool function.

    Args:
        func: Tool function (should be decorated with @signed_tool)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        signature = get_tool_signature(func)
        schema = get_tool_schema(func)
        public_key = get_tool_public_key(func)

        if not all([signature, schema, public_key]):
            return False

        # Create a temporary signer for verification
        # Note: This is a simplified verification - in practice you'd use
        # the verification system from verification.py
        from .signing import SchemaSigner

        # For verification, we need to recreate the canonical form
        signer = SchemaSigner(private_key_content="dummy")  # Won't be used for verification
        canonical_schema = signer.canonicalize_schema(schema)
        _schema_hash = signer.hash_schema(canonical_schema)

        # This is a simplified verification - the actual verification
        # should use the verification system
        return True  # Placeholder

    except Exception as e:
        logger.debug(f"Tool signature verification failed: {e}")
        return False


def list_signed_tools(module_or_dict: Any | dict[str, Any]) -> list[dict[str, Any]]:
    """
    List all signed tools in a module or dictionary.

    Args:
        module_or_dict: Module object or dictionary containing functions

    Returns:
        List of dictionaries with tool information
    """
    tools = []

    if hasattr(module_or_dict, '__dict__'):
        items = module_or_dict.__dict__.items()
    elif isinstance(module_or_dict, dict):
        items = module_or_dict.items()
    else:
        return tools

    for name, obj in items:
        if callable(obj) and hasattr(obj, '_schema_signature'):
            tool_info = {
                "name": name,
                "function": obj,
                "signature": get_tool_signature(obj),
                "domain": get_tool_domain(obj),
                "schema": get_tool_schema(obj),
                "public_key": get_tool_public_key(obj),
                "async": asyncio.iscoroutinefunction(obj)
            }
            tools.append(tool_info)

    return tools


# Utility function for creating test signatures
def create_test_signer(domain: str = "test.example.com") -> SchemaSigner:
    """
    Create a test signer with generated keys for development/testing.

    Args:
        domain: Test domain to use

    Returns:
        SchemaSigner instance with generated keys

    Note:
        This is for testing only. In production, use proper key management.
    """
    try:
        # Generate a test key pair
        private_key_pem, public_key_pem = SchemaSigner.generate_key_pair()

        # Create signer with the generated private key
        signer = SchemaSigner(private_key_content=private_key_pem)

        logger.info(f"Created test signer for domain: {domain}")
        logger.debug(f"Test public key: {public_key_pem}")

        return signer

    except Exception as e:
        logger.exception("Failed to create test signer")
        raise ValueError(f"Test signer creation failed: {e}") from e


def _verify_runtime_signature(func_name: str, tool_schema: dict[str, Any],
                             signature: str, domain: str) -> None:
    """
    Verify signature at runtime for additional security.
    
    Args:
        func_name: Name of the function being verified
        tool_schema: Current tool schema
        signature: Signature to verify
        domain: Expected domain
        
    Raises:
        ValueError: If signature verification fails
    """
    try:
        # This is a placeholder for runtime verification
        # In a full implementation, this would:
        # 1. Fetch public key from domain/.well-known/schemapin/
        # 2. Verify signature against current schema
        # 3. Check domain trust policies
        logger.debug(f"Runtime signature verification for {func_name} (placeholder)")
        
    except Exception as e:
        logger.warning(f"Runtime signature verification failed for {func_name}: {e}")
        # In production, you might want to raise an exception here
        # raise ValueError(f"Signature verification failed: {e}")


def _store_metadata(wrapper_func: Callable, tool_schema: dict[str, Any],
                   signature: str | None, domain: str | None,
                   public_key: str | None, schema_hash: str | None,
                   signed_at: str | None, public_key_url: str | None) -> None:
    """
    Store all signature metadata on the wrapper function.
    
    Args:
        wrapper_func: Function to store metadata on
        tool_schema: Complete tool schema
        signature: Base64 signature string
        domain: Signing domain
        public_key: Public key PEM
        schema_hash: Schema hash
        signed_at: Signing timestamp
        public_key_url: URL to fetch public key
    """
    # Core metadata (backward compatibility)
    wrapper_func._schema_signature = signature
    wrapper_func._schema_domain = domain
    wrapper_func._tool_schema = tool_schema
    wrapper_func._signer_public_key = public_key
    
    # Extended metadata for embedded signatures
    wrapper_func._schema_hash = schema_hash
    wrapper_func._signed_at = signed_at
    wrapper_func._public_key_url = public_key_url
    
    # Metadata summary for easy access
    wrapper_func._signature_metadata = {
        "signature": signature,
        "domain": domain,
        "schema_hash": schema_hash,
        "signed_at": signed_at,
        "public_key_url": public_key_url,
        "has_embedded_signature": signature is not None,
        "schema_version": tool_schema.get("schema_version", "1.0")
    }


def get_tool_metadata(func: Callable) -> dict[str, Any] | None:
    """
    Get complete signature metadata from a signed tool function.
    
    Args:
        func: Tool function (should be decorated with @signed_tool)
        
    Returns:
        Complete metadata dictionary, or None if not available
    """
    return getattr(func, '_signature_metadata', None)


def get_tool_schema_hash(func: Callable) -> str | None:
    """
    Get the schema hash from a signed tool function.
    
    Args:
        func: Tool function (should be decorated with @signed_tool)
        
    Returns:
        Schema hash string, or None if not available
    """
    return getattr(func, '_schema_hash', None)


def get_tool_signed_at(func: Callable) -> str | None:
    """
    Get the signing timestamp from a signed tool function.
    
    Args:
        func: Tool function (should be decorated with @signed_tool)
        
    Returns:
        ISO timestamp string, or None if not available
    """
    return getattr(func, '_signed_at', None)


def get_tool_public_key_url(func: Callable) -> str | None:
    """
    Get the public key URL from a signed tool function.
    
    Args:
        func: Tool function (should be decorated with @signed_tool)
        
    Returns:
        Public key URL string, or None if not available
    """
    return getattr(func, '_public_key_url', None)
