# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

from src.mockloop_mcp.generator import generate_mock_api
from src.mockloop_mcp.parser import load_api_specification


def test_mock_api_generation():
    spec_data = load_api_specification("tests/fixtures/test_spec.json")

    output_dir = generate_mock_api(
        spec_data=spec_data, mock_server_name="test_api_mock"
    )

    for _item in output_dir.iterdir():
        pass


def test_path_level_parameters_are_added_to_generated_routes(tmp_path):
    spec_data = {
        "openapi": "3.0.0",
        "info": {"title": "Path Params", "version": "1.0.0"},
        "paths": {
            "/items/{item_id}": {
                "parameters": [
                    {
                        "name": "item_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "get": {
                    "summary": "Get item",
                    "responses": {"200": {"description": "OK"}},
                },
            }
        },
    }

    output_dir = generate_mock_api(
        spec_data=spec_data,
        output_base_dir=tmp_path,
        mock_server_name="path_param_api",
        auth_enabled=False,
        webhooks_enabled=False,
        admin_ui_enabled=False,
        storage_enabled=False,
    )

    main_py_content = (output_dir / "main.py").read_text()

    assert "async def mock_get_items_item_id(" in main_py_content
    assert "item_id: int" in main_py_content


if __name__ == "__main__":
    test_mock_api_generation()
