# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml"])
)


def generate_routes(spec: dict, output_path: str):
    template = env.get_template("route_template.j2")
    paths = spec.get("paths", {})

    routes_code = ""
    for path, methods in paths.items():
        for method, details in methods.items():
            route = template.render(
                method=method,
                path=path.replace("{", "{"),
                summary=details.get("summary", ""),
                response_body={"message": "mock response"},
            )
            routes_code += route + "\n"

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        f"from fastapi import FastAPI\n\napp = FastAPI()\n\n{routes_code}"
    )
