# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

#!/usr/bin/env python3
"""
MockLoop MCP Package Monitoring Script

This script monitors PyPI statistics and package health for mockloop-mcp.
It tracks download statistics, version information, and package availability.
"""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime
import json
from pathlib import Path
import sys
import time
from typing import Any

import requests


@dataclass
class PackageStats:
    """Package statistics data structure."""

    package_name: str
    current_version: str
    latest_version: str
    total_downloads: int
    recent_downloads: int
    last_updated: str
    health_status: str
    check_timestamp: str
    versions: list[str]
    dependencies: list[str]
    maintainers: list[str]
    description: str
    homepage: str
    repository: str
    license: str
    python_versions: list[str]
    classifiers: list[str]


class PyPIMonitor:
    """Monitor PyPI package statistics and health."""

    def __init__(self, package_name: str = "mockloop-mcp"):
        self.package_name = package_name
        self.base_url = "https://pypi.org/pypi"
        self.stats_url = "https://pypistats.org/api"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "MockLoop-MCP-Monitor/1.0"})

    def get_package_info(self) -> dict[str, Any] | None:
        """Get package information from PyPI."""
        try:
            response = self.session.get(f"{self.base_url}/{self.package_name}/json")
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return None

    def get_download_stats(self, period: str = "month") -> dict[str, Any] | None:
        """Get download statistics from pypistats.org."""
        try:
            response = self.session.get(
                f"{self.stats_url}/packages/{self.package_name}/recent",
                params={"period": period},
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return None

    def get_version_downloads(self) -> dict[str, Any] | None:
        """Get download statistics by version."""
        try:
            response = self.session.get(
                f"{self.stats_url}/packages/{self.package_name}/major"
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return None

    def check_package_health(self) -> str:
        """Check overall package health status."""
        package_info = self.get_package_info()
        if not package_info:
            return "UNAVAILABLE"

        info = package_info.get("info", {})

        # Check if package is actively maintained
        last_release = info.get("upload_time_iso_8601", "")
        if last_release:
            try:
                release_date = datetime.fromisoformat(
                    last_release.replace("Z", "+00:00")
                )
                days_since_release = (datetime.now().astimezone() - release_date).days

                if days_since_release > 365:
                    return "STALE"
                elif days_since_release > 180:
                    return "AGING"
                else:
                    return "HEALTHY"
            except ValueError:
                return "UNKNOWN"

        return "UNKNOWN"

    def collect_stats(self) -> PackageStats | None:
        """Collect comprehensive package statistics."""
        package_info = self.get_package_info()
        if not package_info:
            return None

        info = package_info.get("info", {})
        releases = package_info.get("releases", {})

        # Get download statistics
        download_stats = self.get_download_stats()
        total_downloads = 0
        recent_downloads = 0

        if download_stats and download_stats.get("data"):
            recent_downloads = download_stats["data"].get("last_month", 0)
            # Note: Total downloads require different API endpoint

        # Extract version information
        versions = list(releases.keys())
        versions.sort(
            key=lambda x: [int(i) for i in x.split(".") if i.isdigit()], reverse=True
        )

        current_version = info.get("version", "")
        latest_version = versions[0] if versions else ""

        # Extract maintainer information
        maintainers = []
        if info.get("maintainer"):
            maintainers.append(info["maintainer"])
        if info.get("author") and info["author"] not in maintainers:
            maintainers.append(info["author"])

        # Extract Python version support
        python_versions = []
        classifiers = info.get("classifiers", [])
        for classifier in classifiers:
            if classifier.startswith("Programming Language :: Python ::"):
                version = classifier.split("::")[-1].strip()
                if version and version not in ["Implementation", "Only"]:
                    python_versions.append(version)

        # Extract dependencies
        dependencies = []
        requires_dist = info.get("requires_dist", [])
        if requires_dist:
            for req in requires_dist:
                # Extract package name (before any version specifiers)
                dep_name = req.split()[0].split(">=")[0].split("==")[0].split("~=")[0]
                if dep_name not in dependencies:
                    dependencies.append(dep_name)

        return PackageStats(
            package_name=self.package_name,
            current_version=current_version,
            latest_version=latest_version,
            total_downloads=total_downloads,
            recent_downloads=recent_downloads,
            last_updated=info.get("upload_time_iso_8601", ""),
            health_status=self.check_package_health(),
            check_timestamp=datetime.now().isoformat(),
            versions=versions[:10],  # Last 10 versions
            dependencies=dependencies,
            maintainers=maintainers,
            description=info.get("summary", ""),
            homepage=info.get("home_page", ""),
            repository=info.get("project_url", ""),
            license=info.get("license", ""),
            python_versions=python_versions,
            classifiers=classifiers,
        )

    def save_stats(self, stats: PackageStats, output_file: Path | None = None) -> None:
        """Save statistics to JSON file."""
        if output_file is None:
            output_file = Path("package_stats.json")

        # Load existing stats if file exists
        existing_stats = []
        if output_file.exists():
            try:
                with open(output_file) as f:
                    existing_stats = json.load(f)
            except (OSError, json.JSONDecodeError):
                existing_stats = []

        # Add new stats
        existing_stats.append(asdict(stats))

        # Keep only last 100 entries
        if len(existing_stats) > 100:
            existing_stats = existing_stats[-100:]

        # Save updated stats
        with open(output_file, "w") as f:
            json.dump(existing_stats, f, indent=2, default=str)

    def print_stats(self, stats: PackageStats) -> None:
        """Print statistics in a readable format."""

        for _version in stats.python_versions:
            pass

        for _dep in stats.dependencies[:10]:  # Show first 10
            pass
        if len(stats.dependencies) > 10:
            pass

        for _version in stats.versions[:5]:  # Show last 5 versions
            pass

        for _maintainer in stats.maintainers:
            pass

    def generate_health_report(self, stats: PackageStats) -> dict[str, Any]:
        """Generate a health report with recommendations."""
        report = {
            "overall_health": stats.health_status,
            "timestamp": stats.check_timestamp,
            "issues": [],
            "recommendations": [],
            "metrics": {
                "version_freshness": "good"
                if stats.health_status == "HEALTHY"
                else "needs_attention",
                "download_trend": "unknown",  # Would need historical data
                "dependency_count": len(stats.dependencies),
                "python_version_support": len(stats.python_versions),
            },
        }

        # Check for issues
        if stats.health_status == "STALE":
            report["issues"].append("Package hasn't been updated in over a year")
            report["recommendations"].append("Consider releasing a maintenance update")

        if stats.health_status == "AGING":
            report["issues"].append("Package hasn't been updated in over 6 months")
            report["recommendations"].append(
                "Review for potential updates or bug fixes"
            )

        if stats.recent_downloads < 100:
            report["issues"].append("Low download count in recent period")
            report["recommendations"].append(
                "Consider improving documentation or marketing"
            )

        if len(stats.python_versions) < 3:
            report["issues"].append("Limited Python version support")
            report["recommendations"].append("Consider supporting more Python versions")

        if not stats.description:
            report["issues"].append("Missing package description")
            report["recommendations"].append("Add a comprehensive package description")

        return report


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description="Monitor MockLoop MCP package statistics"
    )
    parser.add_argument(
        "--package",
        default="mockloop-mcp",
        help="Package name to monitor (default: mockloop-mcp)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for statistics (default: package_stats.json)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--health-report",
        action="store_true",
        help="Generate health report with recommendations",
    )
    parser.add_argument(
        "--continuous",
        type=int,
        metavar="MINUTES",
        help="Run continuously, checking every N minutes",
    )

    args = parser.parse_args()

    monitor = PyPIMonitor(args.package)

    def run_check():
        """Run a single monitoring check."""

        stats = monitor.collect_stats()
        if not stats:
            return False

        if args.format in ["text", "both"]:
            monitor.print_stats(stats)

        if args.format in ["json", "both"]:
            monitor.save_stats(stats, args.output)

        if args.health_report:
            report = monitor.generate_health_report(stats)

            if report["issues"]:
                for _issue in report["issues"]:
                    pass

            if report["recommendations"]:
                for _rec in report["recommendations"]:
                    pass

            for _key, _value in report["metrics"].items():
                pass

        return True

    if args.continuous:
        try:
            while True:
                success = run_check()
                if success:
                    pass
                else:
                    pass

                time.sleep(args.continuous * 60)
        except KeyboardInterrupt:
            pass
    else:
        success = run_check()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
