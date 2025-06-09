# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
Release preparation script for mockloop-mcp.

This script provides an interactive guide for preparing releases,
validating the project state, and ensuring all requirements are met
before creating a release.

Usage:
    python scripts/prepare_release.py
    python scripts/prepare_release.py --version 1.0.0
    python scripts/prepare_release.py --check-only
"""

import argparse
from pathlib import Path
import re
import subprocess
import sys


class ReleasePreparation:
    """Handles release preparation and validation."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.pyproject_path = project_root / "pyproject.toml"
        self.init_path = project_root / "src" / "mockloop_mcp" / "__init__.py"
        self.changelog_path = project_root / "CHANGELOG.md"
        self.checks_passed = []
        self.checks_failed = []

    def print_header(self, title: str) -> None:
        """Print a formatted header."""

    def print_check(self, name: str, passed: bool, details: str = "") -> None:
        """Print a check result."""
        if details:
            pass

        if passed:
            self.checks_passed.append(name)
        else:
            self.checks_failed.append(name)

    def get_current_version(self) -> str:
        """Get the current version from pyproject.toml."""
        if not self.pyproject_path.exists():
            raise FileNotFoundError(
                f"pyproject.toml not found at {self.pyproject_path}"
            )

        content = self.pyproject_path.read_text()
        match = re.search(r'version\s*=\s*"([^"]+)"', content)
        if not match:
            raise ValueError("Version not found in pyproject.toml")

        return match.group(1)

    def check_git_status(self) -> bool:
        """Check if git working directory is clean."""
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=True,
            )
            is_clean = len(result.stdout.strip()) == 0

            if not is_clean:
                details = "Working directory has uncommitted changes"
            else:
                details = "Working directory is clean"

            self.print_check("Git working directory clean", is_clean, details)
            return is_clean

        except (subprocess.CalledProcessError, FileNotFoundError):
            self.print_check(
                "Git working directory clean",
                False,
                "Git not available or not a git repository",
            )
            return False

    def check_version_consistency(self) -> bool:
        """Check if versions are consistent across files."""
        try:
            pyproject_version = self.get_current_version()

            # Check __init__.py
            if self.init_path.exists():
                init_content = self.init_path.read_text()
                init_match = re.search(r'__version__\s*=\s*"([^"]+)"', init_content)
                if init_match:
                    init_version = init_match.group(1)
                    is_consistent = pyproject_version == init_version
                    details = f"pyproject.toml: {pyproject_version}, __init__.py: {init_version}"
                else:
                    is_consistent = False
                    details = "__version__ not found in __init__.py"
            else:
                is_consistent = False
                details = "__init__.py not found"

            self.print_check("Version consistency", is_consistent, details)
            return is_consistent

        except Exception as e:
            self.print_check("Version consistency", False, str(e))
            return False

    def check_changelog_updated(self) -> bool:
        """Check if changelog has been updated for the current version."""
        try:
            if not self.changelog_path.exists():
                self.print_check("Changelog updated", False, "CHANGELOG.md not found")
                return False

            content = self.changelog_path.read_text()
            current_version = self.get_current_version()

            # Check if current version is in changelog
            version_pattern = rf"\[{re.escape(current_version)}\]"
            has_version = bool(re.search(version_pattern, content))

            # Check if there's content in Unreleased section
            unreleased_match = re.search(
                r"## \[Unreleased\](.*?)(?=## \[|\Z)", content, re.DOTALL
            )
            has_unreleased_content = False
            if unreleased_match:
                unreleased_content = unreleased_match.group(1).strip()
                # Remove section headers and check if there's actual content
                content_lines = [
                    line.strip()
                    for line in unreleased_content.split("\n")
                    if line.strip() and not line.strip().startswith("###")
                ]
                has_unreleased_content = len(content_lines) > 0

            if has_version:
                details = f"Version {current_version} found in changelog"
                result = True
            elif has_unreleased_content:
                details = "Unreleased section has content ready for release"
                result = True
            else:
                details = "No version entry or unreleased content found"
                result = False

            self.print_check("Changelog updated", result, details)
            return result

        except Exception as e:
            self.print_check("Changelog updated", False, str(e))
            return False

    def check_tests_pass(self) -> bool:
        """Check if all tests pass."""
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", "tests/", "-v", "--tb=short"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                check=False,
            )

            tests_pass = result.returncode == 0
            if tests_pass:
                # Count tests from output
                output_lines = result.stdout.split("\n")
                test_summary = [
                    line
                    for line in output_lines
                    if "passed" in line
                    and ("failed" in line or "error" in line or "skipped" in line)
                ]
                details = test_summary[-1] if test_summary else "All tests passed"
            else:
                details = "Some tests failed - check output above"

            self.print_check("All tests pass", tests_pass, details)
            return tests_pass

        except FileNotFoundError:
            self.print_check(
                "All tests pass", False, "pytest not found - install dev dependencies"
            )
            return False
        except Exception as e:
            self.print_check("All tests pass", False, str(e))
            return False

    def check_security_scans(self) -> bool:
        """Run basic security checks."""
        try:
            # Run bandit
            bandit_result = subprocess.run(
                ["bandit", "-r", "src/", "-f", "txt"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                check=False,
            )

            # Bandit returns 1 if issues found, 0 if clean
            bandit_clean = bandit_result.returncode == 0

            if bandit_clean:
                details = "No security issues found"
            else:
                # Count issues
                issues = bandit_result.stdout.count(">> Issue:")
                details = f"{issues} potential security issues found"

            self.print_check("Security scan (Bandit)", bandit_clean, details)
            return bandit_clean

        except FileNotFoundError:
            self.print_check(
                "Security scan (Bandit)",
                False,
                "bandit not found - install dev dependencies",
            )
            return False
        except Exception as e:
            self.print_check("Security scan (Bandit)", False, str(e))
            return False

    def check_dependencies_secure(self) -> bool:
        """Check for known vulnerabilities in dependencies."""
        try:
            # Run safety check
            safety_result = subprocess.run(
                ["safety", "check"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                check=False,
            )

            safety_clean = safety_result.returncode == 0

            if safety_clean:
                details = "No known vulnerabilities found"
            else:
                details = "Known vulnerabilities detected in dependencies"

            self.print_check("Dependency security (Safety)", safety_clean, details)
            return safety_clean

        except FileNotFoundError:
            self.print_check(
                "Dependency security (Safety)",
                False,
                "safety not found - install dev dependencies",
            )
            return False
        except Exception as e:
            self.print_check("Dependency security (Safety)", False, str(e))
            return False

    def check_build_works(self) -> bool:
        """Check if the package builds successfully."""
        try:
            # Clean any existing build artifacts
            build_dir = self.project_root / "build"
            dist_dir = self.project_root / "dist"

            if build_dir.exists():
                subprocess.run(["rm", "-rf", str(build_dir)], check=True)
            if dist_dir.exists():
                subprocess.run(["rm", "-rf", str(dist_dir)], check=True)

            # Build the package
            result = subprocess.run(
                ["python", "-m", "build"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                check=False,
            )

            build_success = result.returncode == 0

            if build_success:
                # Check if files were created
                dist_files = list(dist_dir.glob("*")) if dist_dir.exists() else []
                details = f"Built {len(dist_files)} distribution files"
            else:
                details = "Build failed - check build dependencies"

            self.print_check("Package builds successfully", build_success, details)
            return build_success

        except FileNotFoundError:
            self.print_check(
                "Package builds successfully",
                False,
                "build module not found - install build dependencies",
            )
            return False
        except Exception as e:
            self.print_check("Package builds successfully", False, str(e))
            return False

    def generate_release_notes(self, version: str) -> str:
        """Generate release notes from changelog."""
        if not self.changelog_path.exists():
            return f"Release notes for version {version}"

        content = self.changelog_path.read_text()

        # Try to find the version section
        version_pattern = (
            rf"## \[{re.escape(version)}\].*?\n(.*?)(?=\n## \[|\n\[.*?\]:|\Z)"
        )
        match = re.search(version_pattern, content, re.DOTALL)

        if match:
            notes = match.group(1).strip()
            # Remove any trailing links section
            notes = re.sub(r"\n\[.*?\]:.*$", "", notes, flags=re.MULTILINE)
            return notes

        # If version not found, try unreleased section
        unreleased_match = re.search(
            r"## \[Unreleased\](.*?)(?=## \[|\Z)", content, re.DOTALL
        )
        if unreleased_match:
            notes = unreleased_match.group(1).strip()
            return notes

        return f"Release notes for version {version}"

    def run_all_checks(self) -> bool:
        """Run all release preparation checks."""
        self.print_header("Release Preparation Checks")

        # Reset check counters
        self.checks_passed = []
        self.checks_failed = []

        # Run all checks
        checks = [
            self.check_git_status,
            self.check_version_consistency,
            self.check_changelog_updated,
            self.check_tests_pass,
            self.check_security_scans,
            self.check_dependencies_secure,
            self.check_build_works,
        ]

        for check in checks:
            check()

        # Summary

        if self.checks_failed:
            for _check in self.checks_failed:
                pass

        if self.checks_passed:
            for _check in self.checks_passed:
                pass

        return len(self.checks_failed) == 0

    def interactive_release_preparation(
        self, target_version: str | None = None
    ) -> None:
        """Interactive release preparation workflow."""
        self.print_header("MockLoop MCP Release Preparation")

        self.get_current_version()

        if target_version:
            pass
        else:
            pass

        # Run checks
        all_passed = self.run_all_checks()

        if not all_passed:
            return

        # Show next steps
        self.print_header("Next Steps")

        # Show release notes preview
        if target_version:
            notes = self.generate_release_notes(target_version)
            if notes:
                self.print_header("Release Notes Preview")


def main():
    """Main entry point for the release preparation script."""
    parser = argparse.ArgumentParser(description="Prepare release for mockloop-mcp")
    parser.add_argument("--version", help="Target version for release")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only run checks, don't show interactive guide",
    )

    args = parser.parse_args()

    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent

    prep = ReleasePreparation(project_root)

    try:
        if args.check_only:
            # Just run checks and exit
            all_passed = prep.run_all_checks()
            sys.exit(0 if all_passed else 1)
        else:
            # Interactive mode
            prep.interactive_release_preparation(args.version)

    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
