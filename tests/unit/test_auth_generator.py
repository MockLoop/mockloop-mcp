# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

from src.mockloop_mcp.generator import generate_mock_api
from src.mockloop_mcp.parser import load_api_specification


def test_auth_mock_api_generation():
    spec_data = load_api_specification("tests/fixtures/test_spec.json")

    output_dir = generate_mock_api(
        spec_data=spec_data, mock_server_name="test_api_auth_mock", auth_enabled=True
    )

    for _item in output_dir.iterdir():
        pass


if __name__ == "__main__":
    test_auth_mock_api_generation()
