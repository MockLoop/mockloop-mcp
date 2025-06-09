# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

from generator import generate_routes
from parser import load_spec
import uvicorn


def build_and_run(spec_path):
    spec = load_spec(spec_path)
    generate_routes(spec, "mocks/my_mock_server.py")
    uvicorn.run("mocks.my_mock_server:app", reload=True)


if __name__ == "__main__":
    import sys

    build_and_run(sys.argv[1])
