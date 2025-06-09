# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Authentication Handler

Manages authentication and authorization for proxy requests,
supporting various authentication schemes and credential management.
"""

from typing import Any, Optional
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class AuthType(Enum):
    """Supported authentication types."""

    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer" + "_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"


class AuthHandler:
    """
    Handles authentication and authorization for API proxy requests.

    This class manages different authentication schemes, credential storage,
    and request authentication for both mock and proxy modes.
    """

    def __init__(self):
        """Initialize the authentication handler."""
        self.credentials: dict[str, dict[str, Any]] = {}
        self.auth_schemes: dict[str, AuthType] = {}
        self.default_auth: AuthType | None = None

    def add_credentials(
        self, api_name: str, auth_type: AuthType, credentials: dict[str, Any]
    ) -> bool:
        """
        Add authentication credentials for an API.

        Args:
            api_name: Name of the API
            auth_type: Type of authentication
            credentials: Authentication credentials

        Returns:
            True if credentials were added successfully
        """
        self.credentials[api_name] = {
            "auth_type": auth_type,
            "credentials": credentials,
        }
        self.auth_schemes[api_name] = auth_type
        logger.info(f"Added {auth_type.value} credentials for {api_name}")
        return True

    def authenticate_request(
        self, api_name: str, request_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Authenticate a request for the specified API.

        Args:
            api_name: Name of the API
            request_data: Request data to authenticate

        Returns:
            Authenticated request data with proper headers/parameters
        """
        if api_name not in self.credentials:
            logger.warning(f"No credentials found for API: {api_name}")
            return request_data

        auth_info = self.credentials[api_name]
        auth_type = auth_info["auth_type"]
        credentials = auth_info["credentials"]

        if auth_type == AuthType.API_KEY:
            return self._add_api_key_auth(request_data, credentials)
        elif auth_type == AuthType.BEARER_TOKEN:
            return self._add_bearer_token_auth(request_data, credentials)
        elif auth_type == AuthType.BASIC_AUTH:
            return self._add_basic_auth(request_data, credentials)
        elif auth_type == AuthType.OAUTH2:
            return self._add_oauth2_auth(request_data, credentials)
        else:
            logger.info(f"No authentication applied for {auth_type.value}")
            return request_data

    def _add_api_key_auth(
        self, request_data: dict[str, Any], credentials: dict[str, Any]
    ) -> dict[str, Any]:
        """Add API key authentication to request."""
        api_key = credentials.get("api_key")
        key_location = credentials.get("location", "header")  # header, query, or cookie
        key_name = credentials.get("name", "X-API-Key")

        if not api_key:
            logger.error("API key not found in credentials")
            return request_data

        if key_location == "header":
            headers = request_data.get("headers", {})
            headers[key_name] = api_key
            request_data["headers"] = headers
        elif key_location == "query":
            params = request_data.get("params", {})
            params[key_name] = api_key
            request_data["params"] = params

        return request_data

    def _add_bearer_token_auth(
        self, request_data: dict[str, Any], credentials: dict[str, Any]
    ) -> dict[str, Any]:
        """Add Bearer token authentication to request."""
        token = credentials.get("token")
        if not token:
            logger.error("Bearer token not found in credentials")
            return request_data

        headers = request_data.get("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        request_data["headers"] = headers
        return request_data

    def _add_basic_auth(
        self, request_data: dict[str, Any], credentials: dict[str, Any]
    ) -> dict[str, Any]:
        """Add Basic authentication to request."""
        username = credentials.get("username")
        password = credentials.get("password")

        if not username or not password:
            logger.error("Username or password not found in credentials")
            return request_data

        import base64

        auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()

        headers = request_data.get("headers", {})
        headers["Authorization"] = f"Basic {auth_string}"
        request_data["headers"] = headers
        return request_data

    def _add_oauth2_auth(
        self, request_data: dict[str, Any], credentials: dict[str, Any]
    ) -> dict[str, Any]:
        """Add OAuth2 authentication to request."""
        access_token = credentials.get("access_token")
        if not access_token:
            logger.error("OAuth2 access token not found in credentials")
            return request_data

        headers = request_data.get("headers", {})
        headers["Authorization"] = f"Bearer {access_token}"
        request_data["headers"] = headers
        return request_data

    def remove_credentials(self, api_name: str) -> bool:
        """
        Remove credentials for an API.

        Args:
            api_name: Name of the API

        Returns:
            True if credentials were removed successfully
        """
        if api_name in self.credentials:
            del self.credentials[api_name]
            del self.auth_schemes[api_name]
            logger.info(f"Removed credentials for {api_name}")
            return True
        return False

    def list_apis(self) -> list[dict[str, Any]]:
        """
        List all APIs with their authentication schemes.

        Returns:
            List of API information with authentication details
        """
        apis = []
        for api_name, auth_type in self.auth_schemes.items():
            apis.append(
                {
                    "api_name": api_name,
                    "auth_type": auth_type.value,
                    "has_credentials": api_name in self.credentials,
                }
            )
        return apis

    def get_auth_status(self, api_name: str) -> dict[str, Any]:
        """
        Get authentication status for an API.

        Args:
            api_name: Name of the API

        Returns:
            Authentication status information
        """
        if api_name not in self.credentials:
            return {"authenticated": False, "auth_type": "none"}

        auth_info = self.credentials[api_name]
        return {
            "authenticated": True,
            "auth_type": auth_info["auth_type"].value,
            "api_name": api_name,
        }
