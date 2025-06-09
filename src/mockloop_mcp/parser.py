# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

import json
import logging
from pathlib import Path
from typing import Any

import requests
import yaml

# Configure logger for this module
logger = logging.getLogger(__name__)


class APIParsingError(Exception):
    """Custom exception for API parsing errors."""

    pass


def load_api_specification(spec_source: str | Path) -> dict[str, Any]:
    """
    Loads an API specification from a URL or a local file path.
    Supports JSON and YAML formats.

    Args:
        spec_source: URL string or Path object pointing to the API specification.

    Returns:
        A dictionary representing the parsed API specification.

    Raises:
        APIParsingError: If the specification cannot be loaded or parsed.
        requests.exceptions.RequestException: If fetching from URL fails.
    """
    content: str = ""
    source_display_name = str(spec_source)

    try:
        if isinstance(spec_source, Path) or Path(spec_source).is_file():
            # Handle local file path
            source_path = Path(spec_source)
            source_display_name = str(source_path.resolve())
            if not source_path.exists():
                raise APIParsingError(
                    f"Local specification file not found: {source_display_name}"
                )
            content = source_path.read_text(encoding="utf-8")

        elif isinstance(spec_source, str) and (
            spec_source.startswith("http://") or spec_source.startswith("https://")
        ):
            # Handle URL
            response = requests.get(spec_source, timeout=10)  # 10 second timeout
            response.raise_for_status()  # Raises HTTPError for bad responses (4XX or 5XX)
            content = response.text
        else:
            # Check if it's a string that looks like a path but wasn't caught by Path(spec_source).is_file()
            # This can happen if the path is valid but the file doesn't exist yet, or it's not a file.
            # Try to treat as a local file path string
            source_path = Path(spec_source)
            if source_path.is_file():  # Double check if it became a file
                source_display_name = str(source_path.resolve())
                content = source_path.read_text(encoding="utf-8")
            else:
                raise APIParsingError(
                    f"Invalid specification source: '{source_display_name}'. "
                    "Must be a valid URL, an existing local file path, or a Path object."
                )

    except requests.exceptions.RequestException as e:
        raise APIParsingError(
            f"Failed to fetch API specification from URL '{source_display_name}': {e}"
        ) from e
    except OSError as e:
        raise APIParsingError(
            f"Failed to read local API specification file '{source_display_name}': {e}"
        ) from e
    except Exception as e:  # Catch any other unexpected error during loading
        raise APIParsingError(
            f"An unexpected error occurred while loading API specification from '{source_display_name}': {e}"
        ) from e

    if not content:
        raise APIParsingError(
            f"No content loaded from API specification source: {source_display_name}"
        )

    # Attempt to parse as YAML, then fall back to JSON
    parsed_spec: dict[str, Any] | None = None
    try:
        parsed_spec = yaml.safe_load(content)
        if not isinstance(parsed_spec, dict):  # Ensure it's a dictionary (root of spec)
            # If safe_load returns a non-dict (e.g. a string if content was just a string), try JSON
            parsed_spec = None
            raise yaml.YAMLError("Parsed YAML content is not a dictionary.")
    except yaml.YAMLError:
        # YAML parsing failed or resulted in non-dict, try JSON
        try:
            parsed_spec = json.loads(content)
            if not isinstance(parsed_spec, dict):
                raise APIParsingError(
                    f"Parsed JSON content from '{source_display_name}' is not a dictionary."
                )
        except json.JSONDecodeError as e:
            raise APIParsingError(
                f"Failed to parse API specification from '{source_display_name}'. "
                "Content is not valid YAML or JSON. "
                f"YAML Error (if any): Previous error. JSON Error: {e}"
            ) from e

    if parsed_spec is None:  # Should not happen if logic above is correct
        raise APIParsingError(
            f"Could not parse content from '{source_display_name}' as YAML or JSON."
        )

    # Basic validation: Check for OpenAPI version (can be extended)
    openapi_version = parsed_spec.get("openapi")
    swagger_version = parsed_spec.get("swagger")
    if not openapi_version and not swagger_version:
        # pass # Allow non-OpenAPI specs for now, generator will fail if it expects OpenAPI
        # Or raise error:
        # raise APIParsingError(
        #     f"Specification from '{source_display_name}' does not appear to be a valid OpenAPI/Swagger document "
        #     "(missing 'openapi' or 'swagger' version field at the root)."
        # )
        pass  # For now, let's be lenient and let the generator decide if it can handle it.

    return parsed_spec


if __name__ == "__main__":
    # Example Usage (for testing the parser directly)
    test_specs = [
        "https://petstore3.swagger.io/api/v3/openapi.json",  # URL JSON
    ]

    for spec_source in test_specs:
        try:
            spec_data = load_api_specification(spec_source)
            print(f"Successfully loaded spec from {spec_source}")
        except APIParsingError as e:
            logger.debug(f"API parsing error for {spec_source}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error for {spec_source}: {e}")
