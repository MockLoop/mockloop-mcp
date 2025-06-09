# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""Integration test to verify the new test structure works correctly."""

from pathlib import Path

import pytest


def test_integration_can_access_fixtures():
    """Test that integration tests can access fixtures."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures"
    test_spec_path = fixtures_dir / "test_spec.json"
    assert test_spec_path.exists()


def test_integration_can_access_unit_tests():
    """Test that integration tests can reference unit test directory."""
    unit_dir = Path(__file__).parent.parent / "unit"
    assert unit_dir.exists()
    assert (unit_dir / "__init__.py").exists()


@pytest.mark.integration
def test_integration_marker():
    """Test that integration marker works."""
    assert True


@pytest.mark.slow
def test_slow_marker():
    """Test that slow marker works."""
    assert True


if __name__ == "__main__":
    # Simple test runner for verification
    test_integration_can_access_fixtures()
    test_integration_can_access_unit_tests()
    test_integration_marker()
    test_slow_marker()
