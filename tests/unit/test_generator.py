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


def test_xquik_openapi31_mock_api_generation(tmp_path):
    spec_data = load_api_specification("tests/fixtures/xquik_openapi31.json")

    output_dir = generate_mock_api(
        spec_data=spec_data,
        output_base_dir=tmp_path,
        mock_server_name="xquik_api_mock",
        auth_enabled=False,
        webhooks_enabled=False,
        admin_ui_enabled=False,
        storage_enabled=False,
    )

    generated_main = (output_dir / "main.py").read_text(encoding="utf-8")
    assert '@app.get("/api/v1/x/tweets/search", summary="Search Tweets")' in generated_main
    assert "mock_get_api_v1_x_tweets_search" in generated_main
    assert "#/components/schemas/TweetSearchResponse" in generated_main


if __name__ == "__main__":
    test_mock_api_generation()
