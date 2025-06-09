#!/usr/bin/env python3
# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

import sys

# Add the current directory to path to find the modules
sys.path.append(".")

# Import the necessary functions directly
from src.mockloop_mcp.generator import generate_mock_api
from src.mockloop_mcp.parser import load_api_specification


def main():
    spec_url_or_path = "https://petstore3.swagger.io/api/v3/openapi.json"
    output_dir_name = "petstore_fixed_final_v3"

    # Load the API specification
    parsed_spec = load_api_specification(spec_url_or_path)

    # Generate the mock API
    generated_path = generate_mock_api(
        spec_data=parsed_spec,
        mock_server_name=output_dir_name,
        auth_enabled=True,
        webhooks_enabled=True,
        admin_ui_enabled=True,
        storage_enabled=True,
    )

    str(generated_path.resolve())


if __name__ == "__main__":
    main()
