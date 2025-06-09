# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Proxy Handler

Handles API proxy requests, routing them between mock and production endpoints
based on configuration and testing scenarios.
"""

from typing import Any, Optional, Union
import logging
import asyncio
from enum import Enum

logger = logging.getLogger(__name__)


class ProxyMode(Enum):
    """Proxy operation modes."""

    MOCK = "mock"
    PROXY = "proxy"
    HYBRID = "hybrid"


class ProxyHandler:
    """
    Handles API proxy requests for seamless switching between mock and production APIs.

    This class manages request routing, response transformation, and mode switching
    for testing scenarios that require both mock and real API interactions.
    """

    def __init__(self, mode: ProxyMode = ProxyMode.MOCK):
        """
        Initialize the proxy handler.

        Args:
            mode: Initial proxy mode (mock, proxy, or hybrid)
        """
        self.mode = mode
        self.mock_endpoints: dict[str, Any] = {}
        self.proxy_endpoints: dict[str, Any] = {}
        self.route_rules: dict[str, Any] = {}

    async def handle_request(self, request_data: dict[str, Any]) -> dict[str, Any]:
        """
        Handle an incoming API request.

        Args:
            request_data: Request information including method, path, headers, body

        Returns:
            Response data from either mock or proxied endpoint
        """
        method = request_data.get("method", "GET")
        path = request_data.get("path", "/")

        logger.info(f"Handling {method} {path} in {self.mode.value} mode")

        if self.mode == ProxyMode.MOCK:
            return await self._handle_mock_request(request_data)
        elif self.mode == ProxyMode.PROXY:
            return await self._handle_proxy_request(request_data)
        else:  # HYBRID
            return await self._handle_hybrid_request(request_data)

    async def _handle_mock_request(
        self, _request_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle request using mock endpoints."""
        # TODO: Implement mock request handling
        return {"status": 200, "data": {"message": "Mock response"}}

    async def _handle_proxy_request(
        self, _request_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle request by proxying to real API."""
        # TODO: Implement proxy request handling
        return {"status": 200, "data": {"message": "Proxied response"}}

    async def _handle_hybrid_request(
        self, _request_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle request using hybrid mock/proxy logic."""
        # TODO: Implement hybrid request handling based on rules
        return {"status": 200, "data": {"message": "Hybrid response"}}

    def switch_mode(self, new_mode: ProxyMode) -> bool:
        """
        Switch the proxy mode.

        Args:
            new_mode: New proxy mode to switch to

        Returns:
            True if mode switch was successful
        """
        old_mode = self.mode
        self.mode = new_mode
        logger.info(f"Switched proxy mode from {old_mode.value} to {new_mode.value}")
        return True

    def add_route_rule(self, pattern: str, rule: dict[str, Any]) -> None:
        """
        Add a routing rule for hybrid mode.

        Args:
            pattern: URL pattern to match
            rule: Routing rule configuration
        """
        self.route_rules[pattern] = rule
        logger.info(f"Added route rule for pattern: {pattern}")

    def get_status(self) -> dict[str, Any]:
        """
        Get current proxy handler status.

        Returns:
            Status information including mode, endpoints, and rules
        """
        return {
            "mode": self.mode.value,
            "mock_endpoints": len(self.mock_endpoints),
            "proxy_endpoints": len(self.proxy_endpoints),
            "route_rules": len(self.route_rules),
        }
