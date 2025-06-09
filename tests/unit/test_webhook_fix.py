#!/usr/bin/env python3
# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Test script to verify webhook functionality in generated mock servers.
This script will generate a new mock server and test the webhook registration.
"""

import asyncio
from pathlib import Path
import sys
import time

# Add the src directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mockloop_mcp.generator import generate_mock_api
from mockloop_mcp.parser import load_api_specification


async def test_webhook_functionality():
    """Test webhook functionality by generating a mock server and testing webhook registration."""

    # Use the existing test API spec
    spec_path = "test_api_spec.json"

    try:
        # Load the API specification
        spec_data = load_api_specification(spec_path)

        # Generate a mock server with webhooks enabled
        mock_server_name = f"webhook_test_{int(time.time())}"
        generated_path = generate_mock_api(
            spec_data=spec_data,
            mock_server_name=mock_server_name,
            auth_enabled=True,
            webhooks_enabled=True,
            admin_ui_enabled=True,
            storage_enabled=True,
        )

        # Check that the webhook handler was created
        webhook_handler_path = generated_path / "webhook_handler.py"
        if webhook_handler_path.exists():
            pass
        else:
            return False

        # Check that the main.py contains webhook endpoints
        main_py_path = generated_path / "main.py"
        if main_py_path.exists():
            with open(main_py_path) as f:
                main_content = f.read()

            if "/admin/api/webhooks" in main_content:
                pass
            else:
                return False

            if "webhook_data: dict = Body(...)" in main_content:
                pass
            else:
                return False
        else:
            return False

        # Check that the admin UI template contains webhook JavaScript
        admin_template_path = generated_path / "templates" / "admin.html"
        if admin_template_path.exists():
            with open(admin_template_path) as f:
                admin_content = f.read()

            if "webhook-form" in admin_content:
                pass
            else:
                return False

            if "loadWebhooks" in admin_content:
                pass
            else:
                return False
        else:
            return False

        return True

    except Exception:
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_webhook_functionality())
    sys.exit(0 if success else 1)
