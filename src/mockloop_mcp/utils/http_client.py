# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
HTTP client utilities for communicating with mock servers.
"""

import logging
import socket
from typing import Any
from urllib.parse import urlparse

import aiohttp

# Configure logger for this module
logger = logging.getLogger(__name__)


class MockServerClient:
    """Client for communicating with MockLoop generated mock servers."""

    def __init__(self, base_url: str, timeout: int = 30, admin_port: int | None = None):
        """
        Initialize the mock server client.

        Args:
            base_url: Base URL of the mock server (e.g., "http://localhost:8000")
            timeout: Request timeout in seconds
            admin_port: Port for admin API (for dual-port architecture). If None, uses legacy /admin paths
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.admin_port = admin_port

        # Determine admin base URL
        if admin_port is not None:
            # Dual-port architecture: admin runs on separate port
            from urllib.parse import urlparse

            parsed = urlparse(self.base_url)
            self.admin_base_url = f"{parsed.scheme}://{parsed.hostname}:{admin_port}"
        else:
            # Legacy single-port architecture: admin uses /admin paths
            self.admin_base_url = self.base_url

    async def health_check(self) -> dict[str, Any]:
        """
        Check if the mock server is healthy and responsive.

        Returns:
            Dict containing health status and server info
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.base_url}/health") as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "status": "healthy",
                            "server_info": data,
                            "response_time_ms": response.headers.get(
                                "X-Process-Time", "unknown"
                            ),
                        }
                    else:
                        return {
                            "status": "unhealthy",
                            "status_code": response.status,
                            "error": f"Health check returned {response.status}",
                        }
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}

    async def query_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        method: str | None = None,
        path: str | None = None,
        include_admin: bool = False,
        log_id: int | None = None,
    ) -> dict[str, Any]:
        """
        Query request logs from the mock server.

        Args:
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            method: Filter by HTTP method
            path: Filter by path pattern
            include_admin: Include admin requests in results
            log_id: Get specific log by ID

        Returns:
            Dict containing logs and metadata
        """
        try:
            params = {"limit": limit, "offset": offset, "include_admin": include_admin}

            if method:
                params["method"] = method
            if path:
                params["path"] = path
            if log_id:
                params["id"] = log_id

            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/requests"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = f"{self.admin_base_url}/admin/api/requests"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(admin_url, params=params) as response:
                    if response.status == 200:
                        logs = await response.json()
                        return {
                            "status": "success",
                            "logs": logs if isinstance(logs, list) else [logs],
                            "total_count": len(logs) if isinstance(logs, list) else 1,
                            "filters_applied": {
                                "method": method,
                                "path": path,
                                "include_admin": include_admin,
                                "log_id": log_id,
                            },
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Request failed with status {response.status}: {error_text}",
                            "logs": [],
                        }
        except Exception as e:
            return {"status": "error", "error": str(e), "logs": []}

    async def get_stats(self) -> dict[str, Any]:
        """
        Get request statistics from the mock server.

        Returns:
            Dict containing request statistics
        """
        try:
            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/requests/stats"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = f"{self.admin_base_url}/admin/api/requests/stats"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(admin_url) as response:
                    if response.status == 200:
                        stats = await response.json()
                        return {"status": "success", "stats": stats}
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Stats request failed with status {response.status}: {error_text}",
                        }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def get_debug_info(self) -> dict[str, Any]:
        """
        Get debug information from the mock server.

        Returns:
            Dict containing debug information
        """
        try:
            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/debug"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = f"{self.admin_base_url}/admin/api/debug"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(admin_url) as response:
                    if response.status == 200:
                        debug_info = await response.json()
                        return {"status": "success", "debug_info": debug_info}
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Debug request failed with status {response.status}: {error_text}",
                        }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def update_response(
        self, endpoint_path: str, response_data: dict[str, Any], method: str = "GET"
    ) -> dict[str, Any]:
        """
        Update response data for a specific endpoint.

        Args:
            endpoint_path: Path of the endpoint to update
            response_data: New response data
            method: HTTP method for the endpoint

        Returns:
            Dict containing update operation result
        """
        try:
            payload = {
                "endpoint_path": endpoint_path,
                "method": method,
                "response_data": response_data,
            }

            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/responses/update"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = f"{self.admin_base_url}/admin/api/responses/update"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(admin_url, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        return {
                            "status": "success",
                            "result": result,
                            "endpoint_path": endpoint_path,
                            "method": method,
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Update failed with status {response.status}: {error_text}",
                            "endpoint_path": endpoint_path,
                        }
        except Exception as e:
            return {"status": "error", "error": str(e), "endpoint_path": endpoint_path}

    async def create_scenario(
        self, scenario_name: str, scenario_config: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a new test scenario.

        Args:
            scenario_name: Name of the scenario
            scenario_config: Complete scenario configuration

        Returns:
            Dict containing scenario creation result
        """
        try:
            payload = {
                "name": scenario_name,
                "description": f"Mock scenario for {scenario_name}",
                "config": scenario_config,
            }

            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/mock-data/scenarios"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = f"{self.admin_base_url}/admin/api/mock-data/scenarios"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(admin_url, json=payload) as response:
                    if response.status == 200:  # Changed from 201 to 200
                        result = await response.json()
                        return {
                            "status": "success",
                            "result": result,
                            "scenario_name": scenario_name,
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Scenario creation failed with status {response.status}: {error_text}",
                            "scenario_name": scenario_name,
                        }
        except Exception as e:
            return {"status": "error", "error": str(e), "scenario_name": scenario_name}

    async def switch_scenario(self, scenario_name: str) -> dict[str, Any]:
        """
        Switch to a different test scenario.

        Args:
            scenario_name: Name of the scenario to switch to

        Returns:
            Dict containing scenario switch result
        """
        try:
            # First, get all scenarios to find the ID by name
            scenarios_result = await self.list_scenarios()
            if scenarios_result.get("status") != "success":
                return {
                    "status": "error",
                    "error": f"Failed to list scenarios: {scenarios_result.get('error')}",
                    "scenario_name": scenario_name,
                }

            scenarios = scenarios_result.get("scenarios", [])
            scenario_id = None
            for scenario in scenarios:
                if scenario.get("name") == scenario_name:
                    scenario_id = scenario.get("id")
                    break

            if scenario_id is None:
                return {
                    "status": "error",
                    "error": f"Scenario '{scenario_name}' not found",
                    "scenario_name": scenario_name,
                }

            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/mock-data/scenarios/{scenario_id}/activate"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = f"{self.admin_base_url}/admin/api/mock-data/scenarios/{scenario_id}/activate"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(admin_url) as response:
                    if response.status == 200:
                        result = await response.json()
                        return {
                            "status": "success",
                            "result": result,
                            "scenario_name": scenario_name,
                            "previous_scenario": result.get("previous_scenario"),
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Scenario switch failed with status {response.status}: {error_text}",
                            "scenario_name": scenario_name,
                        }
        except Exception as e:
            return {"status": "error", "error": str(e), "scenario_name": scenario_name}

    async def list_scenarios(self) -> dict[str, Any]:
        """
        List all available test scenarios.

        Returns:
            Dict containing list of scenarios
        """
        try:
            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/mock-data/scenarios"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = f"{self.admin_base_url}/admin/api/mock-data/scenarios"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(admin_url) as response:
                    if response.status == 200:
                        scenarios = await response.json()
                        return {
                            "status": "success",
                            "scenarios": scenarios,
                            "total_count": len(scenarios)
                            if isinstance(scenarios, list)
                            else 0,
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Scenario list failed with status {response.status}: {error_text}",
                            "scenarios": [],
                        }
        except Exception as e:
            return {"status": "error", "error": str(e), "scenarios": []}

    async def get_current_scenario(self) -> dict[str, Any]:
        """
        Get information about the currently active scenario.

        Returns:
            Dict containing current scenario information
        """
        try:
            # Use appropriate admin endpoint based on architecture
            if self.admin_port is not None:
                # Dual-port: admin API on separate port with /api/* paths
                admin_url = f"{self.admin_base_url}/api/mock-data/scenarios/active"
            else:
                # Legacy: admin API on same port with /admin/api/* paths
                admin_url = (
                    f"{self.admin_base_url}/admin/api/mock-data/scenarios/active"
                )

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(admin_url) as response:
                    if response.status == 200:
                        current_scenario = await response.json()
                        return {
                            "status": "success",
                            "current_scenario": current_scenario,
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "status": "error",
                            "error": f"Current scenario request failed with status {response.status}: {error_text}",
                        }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def get_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        method: str | None = None,
        path: str | None = None,
        include_admin: bool = False,
        log_id: int | None = None,
    ) -> dict[str, Any]:
        """
        Alias for query_logs method for backward compatibility.

        Args:
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            method: Filter by HTTP method
            path: Filter by path pattern
            include_admin: Include admin requests in results
            log_id: Get specific log by ID

        Returns:
            Dict containing logs and metadata
        """
        return await self.query_logs(limit, offset, method, path, include_admin, log_id)


async def discover_running_servers(
    ports: list[int] | None = None, check_health: bool = True
) -> list[dict[str, Any]]:
    """
    Discover running MockLoop servers by scanning common ports.
    Supports both single-port (legacy) and dual-port (new) architectures.

    Args:
        ports: List of ports to scan. If None, scans common ports.
        check_health: Whether to perform health checks on discovered servers

    Returns:
        List of discovered server information
    """
    if ports is None:
        # Extended port range to include common dual-port setups
        ports = [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 3000, 3001, 5000, 5001]

    discovered_servers = []
    potential_admin_ports = set()

    for port in ports:
        try:
            # Quick port check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("localhost", port))
            sock.close()

            if result == 0:  # Port is open
                server_url = f"http://localhost:{port}"
                server_info = {"url": server_url, "port": port, "status": "discovered"}

                if check_health:
                    # First try as mocked API server (legacy single-port or dual-port mocked API)
                    client = MockServerClient(server_url, timeout=5)
                    health_result = await client.health_check()
                    server_info.update(health_result)

                    # Try to get additional server info if it's a MockLoop server
                    if health_result.get("status") == "healthy":
                        debug_result = await client.get_debug_info()
                        if debug_result.get("status") == "success":
                            server_info["is_mockloop_server"] = True
                            server_info["debug_info"] = debug_result.get(
                                "debug_info", {}
                            )
                            server_info["server_type"] = "business"

                            # Check if this might be part of a dual-port setup
                            # Look for admin port (typically business_port + 1)
                            potential_admin_port = port + 1
                            if potential_admin_port in ports:
                                potential_admin_ports.add(potential_admin_port)
                        else:
                            # Try as admin server (dual-port admin)
                            admin_client = MockServerClient(
                                server_url, timeout=5, admin_port=port
                            )
                            admin_debug_result = await admin_client.get_debug_info()
                            if admin_debug_result.get("status") == "success":
                                server_info["is_mockloop_server"] = True
                                server_info["debug_info"] = admin_debug_result.get(
                                    "debug_info", {}
                                )
                                server_info["server_type"] = "admin"
                            else:
                                server_info["is_mockloop_server"] = False
                                server_info["server_type"] = "unknown"

                discovered_servers.append(server_info)

        except Exception as e:
            logger.debug(f"Port scan failed for port {port}: {e}")
            # Port scan failed, continue to next port
            continue

    # Post-process to identify dual-port setups
    for server in discovered_servers:
        if (
            server.get("is_mockloop_server")
            and server.get("server_type") == "business"
            and server["port"] + 1 in potential_admin_ports
        ):
            # Check if the next port is actually the admin port for this mocked API server
            admin_port = server["port"] + 1
            admin_servers = [s for s in discovered_servers if s["port"] == admin_port]
            if admin_servers:
                admin_server = admin_servers[0]
                if admin_server.get("server_type") == "admin":
                    server["admin_port"] = admin_port
                    server["architecture"] = "dual-port"
                    admin_server["business_port"] = server["port"]
                    admin_server["architecture"] = "dual-port"
                else:
                    server["architecture"] = "single-port"
            else:
                server["architecture"] = "single-port"
        elif server.get("is_mockloop_server") and not server.get("architecture"):
            server["architecture"] = "single-port"

    return discovered_servers


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid and properly formatted.

    Args:
        url: URL to validate

    Returns:
        True if URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


async def check_server_connectivity(url: str, timeout: int = 10) -> dict[str, Any]:
    """
    Test connectivity to a server URL.

    Args:
        url: Server URL to test
        timeout: Connection timeout in seconds

    Returns:
        Dict containing connectivity test results
    """
    if not is_valid_url(url):
        return {"status": "error", "error": "Invalid URL format"}

    client = MockServerClient(url, timeout=timeout)
    return await client.health_check()
