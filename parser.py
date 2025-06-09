# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

import json
from pathlib import Path

import requests
import yaml


def load_spec(path_or_url):
    if path_or_url.startswith("http"):
        content = requests.get(path_or_url, timeout=30).text
    else:
        content = Path(path_or_url).read_text()

    try:
        return yaml.safe_load(content)
    except yaml.YAMLError:
        return json.loads(content)
