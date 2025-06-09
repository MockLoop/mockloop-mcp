# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Mock server management utilities for discovering and managing MockLoop servers.
"""

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

# Handle imports for different execution contexts
try:
    from .utils.http_client import (
        MockServerClient,
        discover_running_servers,
        check_server_connectivity,
    )
except ImportError:
    from utils.http_client import (
        MockServerClient,
        discover_running_servers,
    )


class MockServerManager:
    """Manager for MockLoop generated mock servers."""

    def __init__(self, generated_mocks_dir: str | Path | None = None):
        """
        Initialize the mock server manager.

        Args:
            generated_mocks_dir: Path to the generated mocks directory
        """
        if generated_mocks_dir is None:
            # Default to generated_mocks in the project root
            project_root = Path(__file__).parent.parent.parent
            self.generated_mocks_dir = project_root / "generated_mocks"
        else:
            self.generated_mocks_dir = Path(generated_mocks_dir)

    def discover_generated_mocks(self) -> list[dict[str, Any]]:
        """
        Discover all generated mock servers in the generated_mocks directory.

        Returns:
            List of mock server information
        """
        mock_servers = []

        if not self.generated_mocks_dir.exists():
            return mock_servers

        for mock_dir in self.generated_mocks_dir.iterdir():
            if mock_dir.is_dir():
                mock_info = self._analyze_mock_directory(mock_dir)
                if mock_info:
                    mock_servers.append(mock_info)

        return mock_servers

    def _analyze_mock_directory(self, mock_dir: Path) -> dict[str, Any] | None:
        """
        Analyze a mock directory to extract server information.

        Args:
            mock_dir: Path to the mock directory

        Returns:
            Dict containing mock server information or None if invalid
        """
        main_py = mock_dir / "main.py"
        docker_compose = mock_dir / "docker-compose.yml"

        if not main_py.exists():
            return None

        mock_info = {
            "name": mock_dir.name,
            "path": str(mock_dir.absolute()),
            "has_main_py": True,
            "has_docker_compose": docker_compose.exists(),
            "created_at": datetime.fromtimestamp(mock_dir.stat().st_ctime).isoformat(),
            "modified_at": datetime.fromtimestamp(mock_dir.stat().st_mtime).isoformat(),
        }

        # Try to extract port from docker-compose.yml
        if docker_compose.exists():
            try:
                with open(docker_compose) as f:
                    compose_data = yaml.safe_load(f)
                    services = compose_data.get("services", {})
                    for service_config in services.values():
                        ports = service_config.get("ports", [])
                        if ports:
                            # Extract host port from port mapping like "8000:8000"
                            port_mapping = ports[0]
                            if isinstance(port_mapping, str) and ":" in port_mapping:
                                host_port = port_mapping.split(":")[0]
                                mock_info["default_port"] = int(host_port)
                            elif isinstance(port_mapping, int):
                                mock_info["default_port"] = port_mapping
                        break
            except Exception as e:
                mock_info["docker_compose_error"] = str(e)

        # Try to extract API info from main.py
        try:
            with open(main_py) as f:
                main_content = f.read()
                # Look for FastAPI app title and version
                if "FastAPI(" in main_content:
                    # Simple regex-like extraction (could be improved)
                    lines = main_content.split("\n")
                    for line in lines:
                        if "title=" in line and "FastAPI(" in line:
                            # Extract title
                            title_start = line.find('title="') + 7
                            title_end = line.find('"', title_start)
                            if title_start > 6 and title_end > title_start:
                                mock_info["api_title"] = line[title_start:title_end]
                        if "version=" in line and "FastAPI(" in line:
                            # Extract version
                            version_start = line.find('version="') + 9
                            version_end = line.find('"', version_start)
                            if version_start > 8 and version_end > version_start:
                                mock_info["api_version"] = line[
                                    version_start:version_end
                                ]
        except Exception as e:
            mock_info["main_py_analysis_error"] = str(e)

        # Check for additional files
        mock_info["has_auth"] = (mock_dir / "auth_middleware.py").exists()
        mock_info["has_webhooks"] = (mock_dir / "webhook_handler.py").exists()
        mock_info["has_storage"] = (mock_dir / "storage.py").exists()
        mock_info["has_admin_ui"] = (mock_dir / "templates" / "admin.html").exists()

        # Check for database and logs
        db_dir = mock_dir / "db"
        logs_dir = mock_dir / "logs"
        mock_info["has_database"] = db_dir.exists()
        mock_info["has_logs"] = logs_dir.exists()

        if db_dir.exists():
            db_file = db_dir / "request_logs.db"
            mock_info["database_exists"] = db_file.exists()
            if db_file.exists():
                mock_info["database_size"] = db_file.stat().st_size

        return mock_info

    async def discover_running_servers(
        self, ports: list[int] | None = None, check_health: bool = True
    ) -> list[dict[str, Any]]:
        """
        Discover running mock servers.

        Args:
            ports: List of ports to scan
            check_health: Whether to perform health checks

        Returns:
            List of running server information
        """
        return await discover_running_servers(ports, check_health)

    async def get_server_status(
        self, server_url: str, admin_port: int | None = None
    ) -> dict[str, Any]:
        """
        Get the status of a specific mock server.

        Args:
            server_url: URL of the mock server
            admin_port: Admin port for dual-port architecture (optional)

        Returns:
            Dict containing server status information
        """
        client = MockServerClient(server_url, admin_port=admin_port)

        # Get health status
        health_result = await client.health_check()

        # Get additional info if server is healthy
        if health_result.get("status") == "healthy":
            stats_result = await client.get_stats()
            debug_result = await client.get_debug_info()

            server_status = {
                "url": server_url,
                "health": health_result,
                "stats": stats_result.get("stats", {}),
                "debug_info": debug_result.get("debug_info", {}),
                "is_mockloop_server": True,
            }

            # Add architecture information
            if admin_port is not None:
                server_status["architecture"] = "dual-port"
                server_status["admin_port"] = admin_port
            else:
                server_status["architecture"] = "single-port"

            return server_status
        else:
            return {
                "url": server_url,
                "health": health_result,
                "is_mockloop_server": False,
            }

    async def query_server_logs(
        self, server_url: str, admin_port: int | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Query logs from a specific mock server.

        Args:
            server_url: URL of the mock server
            admin_port: Admin port for dual-port architecture (optional)
            **kwargs: Additional query parameters

        Returns:
            Dict containing log query results
        """
        client = MockServerClient(server_url, admin_port=admin_port)
        return await client.query_logs(**kwargs)

    def get_mock_by_name(self, name: str) -> dict[str, Any] | None:
        """
        Get mock server information by name.

        Args:
            name: Name of the mock server

        Returns:
            Mock server information or None if not found
        """
        mock_dir = self.generated_mocks_dir / name
        if mock_dir.exists():
            return self._analyze_mock_directory(mock_dir)
        return None

    def list_available_mocks(self) -> list[str]:
        """
        List names of all available generated mocks.

        Returns:
            List of mock server names
        """
        if not self.generated_mocks_dir.exists():
            return []

        return [
            d.name
            for d in self.generated_mocks_dir.iterdir()
            if d.is_dir() and (d / "main.py").exists()
        ]

    async def comprehensive_discovery(self) -> dict[str, Any]:
        """
        Perform comprehensive discovery of both generated and running mock servers.

        Returns:
            Dict containing complete discovery results
        """
        # Discover generated mocks
        generated_mocks = self.discover_generated_mocks()

        # Discover running servers
        running_servers = await self.discover_running_servers()

        # Try to match running servers with generated mocks
        matched_servers = []
        unmatched_running = []

        for running in running_servers:
            matched = False
            for generated in generated_mocks:
                # Try to match by port
                if generated.get("default_port") == running.get("port") and running.get(
                    "is_mockloop_server", False
                ):
                    matched_servers.append(
                        {
                            "generated_mock": generated,
                            "running_server": running,
                            "status": "running",
                        }
                    )
                    matched = True
                    break

            if not matched:
                unmatched_running.append(running)

        # Find generated mocks that are not running
        not_running = []
        for generated in generated_mocks:
            is_running = any(
                generated.get("default_port") == match["running_server"].get("port")
                for match in matched_servers
            )
            if not is_running:
                not_running.append(
                    {"generated_mock": generated, "status": "not_running"}
                )

        return {
            "discovery_timestamp": datetime.now().isoformat(),
            "total_generated": len(generated_mocks),
            "total_running": len(running_servers),
            "matched_servers": matched_servers,
            "not_running_mocks": not_running,
            "unmatched_running_servers": unmatched_running,
            "generated_mocks_directory": str(self.generated_mocks_dir),
        }


# Convenience functions for direct use
async def quick_discovery() -> dict[str, Any]:
    """
    Quick discovery of mock servers using default settings.

    Returns:
        Dict containing discovery results
    """
    manager = MockServerManager()
    return await manager.comprehensive_discovery()


async def find_server_by_name(name: str) -> dict[str, Any] | None:
    """
    Find a running server by mock name.
    Supports both single-port and dual-port architectures.

    Args:
        name: Name of the mock server

    Returns:
        Server information if found and running, None otherwise
    """
    manager = MockServerManager()
    mock_info = manager.get_mock_by_name(name)

    if mock_info and mock_info.get("default_port"):
        business_port = mock_info["default_port"]
        server_url = f"http://localhost:{business_port}"

        # Try dual-port architecture first (admin_port = business_port + 1)
        admin_port = business_port + 1
        status = await manager.get_server_status(server_url, admin_port=admin_port)

        if status.get("health", {}).get("status") == "healthy":
            return {"mock_info": mock_info, "server_status": status}

        # Fallback to single-port architecture
        status = await manager.get_server_status(server_url)
        if status.get("health", {}).get("status") == "healthy":
            return {"mock_info": mock_info, "server_status": status}

    return None
