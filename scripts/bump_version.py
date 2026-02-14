#!/usr/bin/env python3
# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Version bumping script for mockloop-mcp.

This script automates the process of bumping version numbers across the project,
updating the changelog, and creating git commits and tags.

Usage:
    python scripts/bump_version.py patch
    python scripts/bump_version.py minor
    python scripts/bump_version.py major
    python scripts/bump_version.py --version 1.2.3
    python scripts/bump_version.py --pre-release alpha
"""

import argparse
from datetime import datetime
from pathlib import Path
import re
import subprocess
import sys


class VersionBumper:
    """Handles version bumping operations for the project."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.pyproject_path = project_root / "pyproject.toml"
        self.init_path = project_root / "src" / "mockloop_mcp" / "__init__.py"
        self.changelog_path = project_root / "CHANGELOG.md"

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

    def validate_version_consistency(self) -> bool:
        """Validate that versions are consistent across files."""
        pyproject_version = self.get_current_version()

        # Check __init__.py
        if self.init_path.exists():
            init_content = self.init_path.read_text()
            init_match = re.search(r'__version__\s*=\s*"([^"]+)"', init_content)
            if init_match and init_match.group(1) != pyproject_version:
                return False

        return True

    def parse_version(self, version: str) -> tuple[int, int, int, str | None]:
        """Parse a semantic version string."""
        # Handle pre-release versions like 1.0.0-alpha.1
        if "-" in version:
            base_version, pre_release = version.split("-", 1)
        else:
            base_version, pre_release = version, None

        parts = base_version.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid version format: {version}")

        try:
            major, minor, patch = map(int, parts)
        except ValueError as err:
            raise ValueError(f"Invalid version format: {version}") from err

        return major, minor, patch, pre_release

    def bump_version(self, bump_type: str, pre_release: str | None = None) -> str:
        """Bump version based on type (major, minor, patch)."""
        current = self.get_current_version()
        major, minor, patch, current_pre = self.parse_version(current)

        if bump_type == "major":
            major += 1
            minor = 0
            patch = 0
        elif bump_type == "minor":
            minor += 1
            patch = 0
        elif bump_type == "patch":
            patch += 1
        else:
            raise ValueError(f"Invalid bump type: {bump_type}")

        new_version = f"{major}.{minor}.{patch}"
        if pre_release:
            new_version += f"-{pre_release}"

        return new_version

    def set_version(self, new_version: str) -> None:
        """Set version in all relevant files."""
        # Validate version format
        self.parse_version(new_version)

        # Update pyproject.toml
        content = self.pyproject_path.read_text()
        content = re.sub(
            r'version\s*=\s*"[^"]+"', f'version = "{new_version}"', content
        )
        self.pyproject_path.write_text(content)

        # Update __init__.py
        if self.init_path.exists():
            content = self.init_path.read_text()
            content = re.sub(
                r'__version__\s*=\s*"[^"]+"', f'__version__ = "{new_version}"', content
            )
            self.init_path.write_text(content)

    def update_changelog(self, new_version: str) -> None:
        """Update CHANGELOG.md with new version and date."""
        if not self.changelog_path.exists():
            return

        content = self.changelog_path.read_text()
        today = datetime.now().strftime("%Y-%m-%d")

        # Replace [Unreleased] with the new version
        content = re.sub(
            r"\[Unreleased\]", f"[{new_version}] - {today}", content, count=1
        )

        # Add new [Unreleased] section at the top
        unreleased_section = """## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

"""

        # Find the first version section and insert before it
        version_pattern = r"(## \[\d+\.\d+\.\d+.*?\])"
        match = re.search(version_pattern, content)
        if match:
            content = content.replace(
                match.group(1), unreleased_section + match.group(1)
            )
        else:
            # If no version sections found, add after the header
            header_end = content.find("\n\n") + 2
            content = content[:header_end] + unreleased_section + content[header_end:]

        # Update comparison links at the bottom
        if f"[{new_version}]:" not in content:
            # Add new version link
            unreleased_link = (
                "[Unreleased]: https://github.com/mockloop/mockloop-mcp/compare/"
            )
            if unreleased_link in content:
                content = content.replace(
                    unreleased_link,
                    f"{unreleased_link}v{new_version}...HEAD\n[{new_version}]: https://github.com/mockloop/mockloop-mcp/releases/tag/v{new_version}\n",
                )

        self.changelog_path.write_text(content)

    def create_git_commit_and_tag(self, version: str) -> None:
        """Create git commit and tag for the release."""
        try:
            # Check if we're in a git repository
            subprocess.run(["git", "status"], check=True, capture_output=True)

            # Add changed files
            subprocess.run(["git", "add", "pyproject.toml"], check=True)
            if self.init_path.exists():
                subprocess.run(["git", "add", str(self.init_path)], check=True)
            if self.changelog_path.exists():
                subprocess.run(["git", "add", str(self.changelog_path)], check=True)

            # Create commit
            commit_message = f"chore: bump version to {version}"
            subprocess.run(["git", "commit", "-m", commit_message], check=True)

            # Create tag
            tag_name = f"v{version}"
            tag_message = f"Release version {version}"
            subprocess.run(
                ["git", "tag", "-a", tag_name, "-m", tag_message], check=True
            )

        except (subprocess.CalledProcessError, FileNotFoundError):
            pass  # Git operations are optional - silently skip if not in a git repo


def main():
    """Main entry point for the version bumping script."""
    parser = argparse.ArgumentParser(description="Bump version for mockloop-mcp")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "bump_type",
        nargs="?",
        choices=["major", "minor", "patch"],
        help="Type of version bump",
    )
    group.add_argument("--version", help="Set specific version")

    parser.add_argument(
        "--pre-release", help="Pre-release identifier (alpha, beta, rc)"
    )
    parser.add_argument("--no-git", action="store_true", help="Skip git operations")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )

    args = parser.parse_args()

    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent

    bumper = VersionBumper(project_root)

    try:
        # Validate current state
        if not bumper.validate_version_consistency():
            sys.exit(1)

        bumper.get_current_version()

        # Determine new version
        if args.version:
            new_version = args.version
        else:
            new_version = bumper.bump_version(args.bump_type, args.pre_release)

        if args.dry_run:
            return

        # Make changes
        bumper.set_version(new_version)
        bumper.update_changelog(new_version)

        if not args.no_git:
            bumper.create_git_commit_and_tag(new_version)

    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
