# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
PyPI Readiness Validation Script

This script performs comprehensive validation to ensure MockLoop MCP
is ready for PyPI distribution. It checks package structure, metadata,
dependencies, documentation, and more.
"""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import subprocess  # nosec B404 - needed for validation commands
import sys
from urllib.parse import urlparse


@dataclass
class ValidationResult:
    """Result of a validation check."""

    name: str
    passed: bool
    message: str
    details: str | None = None
    severity: str = "error"  # error, warning, info


@dataclass
class ValidationSummary:
    """Summary of all validation results."""

    total_checks: int
    passed_checks: int
    failed_checks: int
    warnings: int
    errors: int
    results: list[ValidationResult]
    overall_status: str
    recommendations: list[str]


class PyPIValidator:
    """Comprehensive PyPI readiness validator."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.results: list[ValidationResult] = []
        self.recommendations: list[str] = []

    def add_result(
        self,
        name: str,
        passed: bool,
        message: str,
        details: str | None = None,
        severity: str = "error",
    ) -> None:
        """Add a validation result."""
        self.results.append(
            ValidationResult(
                name=name,
                passed=passed,
                message=message,
                details=details,
                severity=severity,
            )
        )

    def add_recommendation(self, recommendation: str) -> None:
        """Add a recommendation."""
        self.recommendations.append(recommendation)

    def _check_for_valid_badges(self, content: str) -> bool:
        """Check for valid PyPI badges using proper URL parsing."""
        # Find all URLs in markdown format [text](url) and HTML format src="url"
        url_patterns = [
            r"\[.*?\]\((https?://[^\)]+)\)",  # Markdown links
            r'src=["\']([^"\']+)["\']',  # HTML src attributes
            r'href=["\']([^"\']+)["\']',  # HTML href attributes
        ]

        valid_badge_hosts = {"pypi.org", "img.shields.io"}

        for pattern in url_patterns:
            matches = re.findall(pattern, content)
            for url in matches:
                try:
                    parsed_url = urlparse(url)
                    # Check if the hostname exactly matches our allowed hosts
                    if parsed_url.hostname in valid_badge_hosts:
                        return True
                except (ValueError, TypeError) as e:
                    # Log specific URL parsing errors for debugging
                    print(f"Warning: Failed to parse URL '{url}': {e}")
                    continue

        return False

    def run_command(
        self, command: list[str], cwd: Path | None = None
    ) -> tuple[bool, str, str]:
        """Run a command and return success, stdout, stderr."""
        try:
            result = subprocess.run(  # nosec B603 - command list is controlled, no shell injection risk
                command,
                cwd=cwd or self.project_root,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

    def validate_project_structure(self) -> None:
        """Validate basic project structure."""
        required_files = [
            "pyproject.toml",
            "README.md",
            "LICENSE",
            "CHANGELOG.md",
            "src/mockloop_mcp/__init__.py",
            "src/mockloop_mcp/main.py",
        ]

        for file_path in required_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                self.add_result(
                    f"file_{file_path.replace('/', '_')}",
                    True,
                    f"Required file exists: {file_path}",
                )
            else:
                self.add_result(
                    f"file_{file_path.replace('/', '_')}",
                    False,
                    f"Missing required file: {file_path}",
                )
                self.add_recommendation(f"Create missing file: {file_path}")

        # Check for common optional files
        optional_files = [
            "MANIFEST.in",
            ".gitignore",
            "requirements.txt",
            "docs/",
            "tests/",
        ]

        for file_path in optional_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                self.add_result(
                    f"optional_{file_path.replace('/', '_')}",
                    True,
                    f"Optional file/directory exists: {file_path}",
                    severity="info",
                )
            else:
                self.add_result(
                    f"optional_{file_path.replace('/', '_')}",
                    False,
                    f"Optional file/directory missing: {file_path}",
                    severity="warning",
                )

    def validate_pyproject_toml(self) -> None:
        """Validate pyproject.toml configuration."""
        pyproject_path = self.project_root / "pyproject.toml"

        if not pyproject_path.exists():
            self.add_result("pyproject_exists", False, "pyproject.toml file is missing")
            return

        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                self.add_result(
                    "pyproject_parse",
                    False,
                    "Cannot parse pyproject.toml - tomllib/tomli not available",
                )
                return

        try:
            with open(pyproject_path, "rb") as f:
                config = tomllib.load(f)
        except Exception as e:
            self.add_result(
                "pyproject_parse", False, f"Failed to parse pyproject.toml: {e}"
            )
            return

        self.add_result("pyproject_parse", True, "pyproject.toml parsed successfully")

        # Check required sections
        required_sections = ["build-system", "project"]
        for section in required_sections:
            if section in config:
                self.add_result(
                    f"pyproject_{section}",
                    True,
                    f"pyproject.toml has required section: {section}",
                )
            else:
                self.add_result(
                    f"pyproject_{section}",
                    False,
                    f"pyproject.toml missing required section: {section}",
                )

        # Check project metadata
        if "project" in config:
            project = config["project"]
            required_fields = ["name", "version", "description", "authors"]

            for field in required_fields:
                if field in project:
                    self.add_result(
                        f"project_{field}", True, f"Project has required field: {field}"
                    )
                else:
                    self.add_result(
                        f"project_{field}",
                        False,
                        f"Project missing required field: {field}",
                    )

            # Check version format
            if "version" in project:
                version = project["version"]
                if re.match(r"^\d+\.\d+\.\d+", version):
                    self.add_result(
                        "version_format", True, f"Version format is valid: {version}"
                    )
                else:
                    self.add_result(
                        "version_format", False, f"Version format is invalid: {version}"
                    )

            # Check Python version requirements
            if "requires-python" in project:
                python_req = project["requires-python"]
                self.add_result(
                    "python_requirement",
                    True,
                    f"Python requirement specified: {python_req}",
                )
            else:
                self.add_result(
                    "python_requirement", False, "Python requirement not specified"
                )
                self.add_recommendation(
                    "Add requires-python field to specify supported Python versions"
                )

    def validate_package_imports(self) -> None:
        """Validate that the package can be imported."""
        src_path = self.project_root / "src"
        if not src_path.exists():
            self.add_result("src_directory", False, "src/ directory not found")
            return

        # Add src to Python path temporarily
        sys.path.insert(0, str(src_path))

        try:
            import mockloop_mcp

            self.add_result("package_import", True, "Package imports successfully")

            # Check for main module
            if hasattr(mockloop_mcp, "main"):
                self.add_result("main_module", True, "Main module is accessible")
            else:
                self.add_result(
                    "main_module", False, "Main module not found in package"
                )

            # Check version attribute
            if hasattr(mockloop_mcp, "__version__"):
                version = mockloop_mcp.__version__
                self.add_result(
                    "package_version", True, f"Package version available: {version}"
                )
            else:
                self.add_result(
                    "package_version", False, "Package version not available"
                )
                self.add_recommendation(
                    "Add __version__ attribute to package __init__.py"
                )

        except ImportError as e:
            self.add_result("package_import", False, f"Package import failed: {e}")
        finally:
            sys.path.remove(str(src_path))

    def validate_dependencies(self) -> None:
        """Validate package dependencies."""
        # Check if requirements.txt exists and is reasonable
        req_file = self.project_root / "requirements.txt"
        if req_file.exists():
            try:
                with open(req_file) as f:
                    requirements = f.read().strip().split("\n")

                # Filter out empty lines and comments
                deps = [
                    req.strip()
                    for req in requirements
                    if req.strip() and not req.strip().startswith("#")
                ]

                self.add_result(
                    "requirements_file",
                    True,
                    f"requirements.txt found with {len(deps)} dependencies",
                )

                # Check for common problematic patterns
                for dep in deps:
                    if "==" in dep and not re.search(r"==\d+\.\d+", dep):
                        self.add_result(
                            f"dep_pinning_{dep}",
                            False,
                            f"Dependency has problematic pinning: {dep}",
                            severity="warning",
                        )

            except Exception as e:
                self.add_result(
                    "requirements_file", False, f"Failed to read requirements.txt: {e}"
                )

        # Test dependency installation
        success, stdout, stderr = self.run_command(
            [sys.executable, "-m", "pip", "check"]
        )

        if success:
            self.add_result("dependency_check", True, "All dependencies are compatible")
        else:
            self.add_result(
                "dependency_check", False, f"Dependency conflicts detected: {stderr}"
            )

    def validate_documentation(self) -> None:
        """Validate documentation completeness."""
        readme_path = self.project_root / "README.md"

        if readme_path.exists():
            with open(readme_path, encoding="utf-8") as f:
                readme_content = f.read()

            # Check README length
            if len(readme_content) > 500:
                self.add_result(
                    "readme_length",
                    True,
                    f"README.md has adequate length ({len(readme_content)} chars)",
                )
            else:
                self.add_result(
                    "readme_length",
                    False,
                    f"README.md is too short ({len(readme_content)} chars)",
                )
                self.add_recommendation(
                    "Expand README.md with more detailed information"
                )

            # Check for required sections
            required_sections = ["installation", "usage", "example", "getting started"]

            for section in required_sections:
                if section.lower() in readme_content.lower():
                    self.add_result(
                        f"readme_{section}",
                        True,
                        f"README contains {section} information",
                    )
                else:
                    self.add_result(
                        f"readme_{section}",
                        False,
                        f"README missing {section} information",
                        severity="warning",
                    )

            # Check for PyPI badges using proper URL parsing
            has_pypi_badges = self._check_for_valid_badges(readme_content)
            if has_pypi_badges:
                self.add_result(
                    "readme_badges", True, "README contains valid PyPI badges"
                )
            else:
                self.add_result(
                    "readme_badges",
                    False,
                    "README missing PyPI badges",
                    severity="warning",
                )
                self.add_recommendation(
                    "Add PyPI badges to README for better visibility"
                )

    def validate_tests(self) -> None:
        """Validate test suite."""
        tests_dir = self.project_root / "tests"

        if tests_dir.exists():
            test_files = list(tests_dir.rglob("test_*.py"))

            if test_files:
                self.add_result(
                    "test_files", True, f"Found {len(test_files)} test files"
                )

                # Try to run tests
                success, stdout, stderr = self.run_command(
                    [sys.executable, "-m", "pytest", "--collect-only", "-q"]
                )

                if success:
                    self.add_result(
                        "test_collection", True, "Tests can be collected successfully"
                    )
                else:
                    self.add_result(
                        "test_collection",
                        False,
                        f"Test collection failed: {stderr}",
                        severity="warning",
                    )
            else:
                self.add_result(
                    "test_files",
                    False,
                    "No test files found in tests/ directory",
                    severity="warning",
                )
        else:
            self.add_result(
                "tests_directory",
                False,
                "tests/ directory not found",
                severity="warning",
            )
            self.add_recommendation("Add comprehensive test suite")

    def validate_build_system(self) -> None:
        """Validate that the package can be built."""
        # Test package building
        success, stdout, stderr = self.run_command(
            [sys.executable, "-m", "build", "--wheel", "--no-isolation"]
        )

        if success:
            self.add_result("package_build", True, "Package builds successfully")

            # Check if wheel was created
            dist_dir = self.project_root / "dist"
            if dist_dir.exists():
                wheels = list(dist_dir.glob("*.whl"))
                if wheels:
                    self.add_result(
                        "wheel_creation", True, f"Wheel file created: {wheels[0].name}"
                    )
                else:
                    self.add_result(
                        "wheel_creation", False, "No wheel file found after build"
                    )
        else:
            self.add_result("package_build", False, f"Package build failed: {stderr}")
            self.add_recommendation("Fix package build issues before PyPI upload")

    def validate_security(self) -> None:
        """Validate security aspects."""
        # Check for common security files
        security_files = [".secrets.baseline", "SECURITY.md"]

        for file_path in security_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                self.add_result(
                    f"security_{file_path.replace('.', '_')}",
                    True,
                    f"Security file exists: {file_path}",
                    severity="info",
                )
            else:
                self.add_result(
                    f"security_{file_path.replace('.', '_')}",
                    False,
                    f"Security file missing: {file_path}",
                    severity="warning",
                )

        # Check for hardcoded secrets (basic check)
        python_files = list(self.project_root.rglob("*.py"))
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ]

        secrets_found = False
        for py_file in python_files:
            try:
                with open(py_file, encoding="utf-8") as f:
                    content = f.read()

                for pattern in secret_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        secrets_found = True
                        self.add_result(
                            f"hardcoded_secret_{py_file.name}",
                            False,
                            f"Potential hardcoded secret in {py_file}",
                            severity="warning",
                        )
                        break
            except Exception as e:
                # Log the exception for debugging purposes
                print(f"Warning: Failed to check secret pattern: {e}")
                continue

        if not secrets_found:
            self.add_result(
                "hardcoded_secrets", True, "No obvious hardcoded secrets found"
            )

    def validate_all(self) -> ValidationSummary:
        """Run all validation checks."""

        validation_methods = [
            ("Project Structure", self.validate_project_structure),
            ("pyproject.toml", self.validate_pyproject_toml),
            ("Package Imports", self.validate_package_imports),
            ("Dependencies", self.validate_dependencies),
            ("Documentation", self.validate_documentation),
            ("Tests", self.validate_tests),
            ("Build System", self.validate_build_system),
            ("Security", self.validate_security),
        ]

        for name, method in validation_methods:
            try:
                method()
            except Exception as e:
                self.add_result(
                    f"validation_{name.lower().replace(' ', '_')}",
                    False,
                    f"Validation failed for {name}: {e}",
                )

        # Calculate summary
        total_checks = len(self.results)
        passed_checks = sum(1 for r in self.results if r.passed)
        failed_checks = total_checks - passed_checks
        warnings = sum(1 for r in self.results if r.severity == "warning")
        errors = sum(1 for r in self.results if r.severity == "error" and not r.passed)

        # Determine overall status
        if errors > 0:
            overall_status = "FAILED"
        elif warnings > 5:
            overall_status = "NEEDS_ATTENTION"
        elif passed_checks / total_checks >= 0.8:
            overall_status = "READY"
        else:
            overall_status = "NEEDS_IMPROVEMENT"

        return ValidationSummary(
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            warnings=warnings,
            errors=errors,
            results=self.results,
            overall_status=overall_status,
            recommendations=self.recommendations,
        )


def print_summary(summary: ValidationSummary) -> None:
    """Print validation summary."""

    # Print failed checks
    failed_results = [
        r for r in summary.results if not r.passed and r.severity == "error"
    ]
    if failed_results:
        for result in failed_results:
            if result.details:
                pass

    # Print warnings
    warning_results = [
        r for r in summary.results if not r.passed and r.severity == "warning"
    ]
    if warning_results:
        for _result in warning_results[:5]:  # Show first 5 warnings
            pass
        if len(warning_results) > 5:
            pass

    # Print recommendations
    if summary.recommendations:
        for _rec in summary.recommendations[:10]:  # Show first 10 recommendations
            pass
        if len(summary.recommendations) > 10:
            pass


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Validate PyPI readiness for MockLoop MCP"
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Project root directory (default: current directory)",
    )
    parser.add_argument(
        "--output", type=Path, help="Output file for detailed results (JSON format)"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "both"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on-warnings",
        action="store_true",
        help="Exit with error code if warnings are found",
    )

    args = parser.parse_args()

    validator = PyPIValidator(args.project_root)
    summary = validator.validate_all()

    if args.format in ["text", "both"]:
        print_summary(summary)

    if args.format in ["json", "both"] or args.output:
        output_data = asdict(summary)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2, default=str)

        if args.format == "json":
            pass

    # Exit with appropriate code
    if summary.overall_status == "FAILED" or (
        summary.overall_status in ["NEEDS_ATTENTION", "NEEDS_IMPROVEMENT"]
        and args.fail_on_warnings
    ):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
