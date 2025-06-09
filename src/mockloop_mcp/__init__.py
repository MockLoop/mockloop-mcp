# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

# This file makes Python treat the `mockloop_mcp` directory as a package.

__version__ = "2.2.9"

# Import proxy module components
from .proxy import PluginManager, ProxyHandler, AuthHandler, ProxyConfig

__all__ = [
    "AuthHandler",
    "PluginManager",
    "ProxyConfig",
    "ProxyHandler",
]
