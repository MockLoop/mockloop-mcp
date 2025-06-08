import contextlib
import json
from pathlib import Path
import secrets
import string
import time
from typing import Any

from jinja2 import Environment, FileSystemLoader


class APIGenerationError(Exception):
    """Custom exception for API generation errors."""

    pass


TEMPLATE_DIR = Path(__file__).parent / "templates"
if not TEMPLATE_DIR.is_dir():
    TEMPLATE_DIR = Path("src/mockloop_mcp/templates")
    if not TEMPLATE_DIR.is_dir():
        raise APIGenerationError("Template directory not found at expected locations.")

# Note: autoescape=False is intentional here as we're generating Python code, not HTML
# This is safe because we control all template inputs and don't render user-provided content
jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=False)  # noqa: S701 # nosec B701

# Add base64 encode filter for admin UI template
import base64


def b64encode_filter(s):
    """Base64 encode filter for Jinja2 templates"""
    if isinstance(s, str):
        s = s.encode("utf-8")
    return base64.b64encode(s).decode("ascii")


jinja_env.filters["b64encode"] = b64encode_filter


# Add Python boolean conversion filter
def python_bool_filter(value):
    """Convert JavaScript-style boolean values to Python boolean values"""
    if isinstance(value, str):
        js_to_python = {"true": True, "false": False, "null": None}
        return js_to_python.get(value, value)
    return value


def convert_js_to_python(obj):
    """Recursively convert JavaScript-style boolean values to Python values"""
    if isinstance(obj, dict):
        return {k: convert_js_to_python(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_js_to_python(item) for item in obj]
    elif isinstance(obj, str):
        js_to_python = {"true": True, "false": False, "null": None}
        return js_to_python.get(obj, obj)
    return obj


jinja_env.filters["python_bool"] = python_bool_filter
jinja_env.filters["convert_js_to_python"] = convert_js_to_python


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1", "on")
    if isinstance(value, int):
        return value != 0
    return bool(value)


def _generate_mock_data_from_schema(schema: dict[str, Any]) -> Any:
    if not schema:
        return None
    schema_type = schema.get("type")
    if schema_type == "string":
        format_type = schema.get("format", "")
        if format_type == "date-time":
            return "2023-01-01T00:00:00Z"
        if format_type == "date":
            return "2023-01-01"
        if format_type == "email":
            return "user@example.com"
        if format_type == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        length = schema.get("minLength", 5)
        if schema.get("maxLength") and schema.get("maxLength") < length:
            length = schema.get("maxLength")
        return "".join(secrets.choice(string.ascii_letters) for _ in range(length))
    if schema_type in {"number", "integer"}:
        minimum = schema.get("minimum", 0)
        maximum = schema.get("maximum", 100)
        return (
            secrets.randbelow(maximum - minimum + 1) + minimum
            if schema_type == "integer"
            else round(
                secrets.randbelow(int((maximum - minimum) * 100)) / 100 + minimum, 2
            )
        )
    if schema_type == "boolean":
        return secrets.choice([True, False])
    if schema_type == "array":
        items_schema = schema.get("items", {})
        min_items = schema.get("minItems", 1)
        max_items = schema.get("maxItems", 3)
        num_items = secrets.randbelow(max_items - min_items + 1) + min_items
        return [_generate_mock_data_from_schema(items_schema) for _ in range(num_items)]
    if schema_type == "object":
        result = {}
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for prop_name, prop_schema in properties.items():
            if prop_name in required or secrets.randbelow(10) > 2:
                result[prop_name] = _generate_mock_data_from_schema(prop_schema)
        return result
    if "$ref" in schema:
        return {"$ref_placeholder": schema["$ref"]}
    for key in ["oneOf", "anyOf"]:
        if key in schema and isinstance(schema[key], list) and len(schema[key]) > 0:
            return _generate_mock_data_from_schema(secrets.choice(schema[key]))
    if (
        "allOf" in schema
        and isinstance(schema["allOf"], list)
        and len(schema["allOf"]) > 0
    ):
        merged_schema = {}
        for sub_schema in schema["allOf"]:
            if isinstance(sub_schema, dict):
                merged_schema.update(sub_schema)
        return _generate_mock_data_from_schema(merged_schema)
    return "mock_data"


def generate_mock_api(
    spec_data: dict[str, Any],
    output_base_dir: str | Path | None = None,
    mock_server_name: str | None = None,
    auth_enabled: Any = True,
    webhooks_enabled: Any = True,
    admin_ui_enabled: Any = True,
    storage_enabled: Any = True,
    business_port: int = 8000,
    admin_port: int | None = None,
) -> Path:
    auth_enabled_bool = _to_bool(auth_enabled)
    webhooks_enabled_bool = _to_bool(webhooks_enabled)
    admin_ui_enabled_bool = _to_bool(admin_ui_enabled)
    storage_enabled_bool = _to_bool(storage_enabled)

    # Set admin port to business_port + 1 if not specified
    if admin_port is None:
        admin_port = business_port + 1

    try:
        api_title = (
            spec_data.get("info", {})
            .get("title", "mock_api")
            .lower()
            .replace(" ", "_")
            .replace("-", "_")
        )
        api_version = (
            spec_data.get("info", {}).get("version", "v1").lower().replace(".", "_")
        )

        _mock_server_name = mock_server_name
        if not _mock_server_name:
            _mock_server_name = f"{api_title}_{api_version}_{int(time.time())}"

        _mock_server_name = "".join(
            c if c.isalnum() or c in ["_", "-"] else "_" for c in _mock_server_name
        )

        _output_base_dir = output_base_dir
        if _output_base_dir is None:
            project_root = Path(__file__).parent.parent.parent
            _output_base_dir = project_root / "generated_mocks"

        mock_server_dir = Path(_output_base_dir) / _mock_server_name
        mock_server_dir.mkdir(parents=True, exist_ok=True)

        requirements_content = "fastapi\nuvicorn[standard]\npsutil\n"

        with open(
            mock_server_dir / "requirements_mock.txt", "w", encoding="utf-8"
        ) as f:
            f.write(requirements_content)

        if auth_enabled_bool:
            auth_middleware_template = jinja_env.get_template(
                "auth_middleware_template.j2"
            )
            random_suffix = "".join(
                secrets.choice(string.ascii_letters + string.digits) for _ in range(8)
            )
            auth_middleware_code = auth_middleware_template.render(
                random_suffix=random_suffix
            )
            with open(
                mock_server_dir / "auth_middleware.py", "w", encoding="utf-8"
            ) as f:
                f.write(auth_middleware_code)
            with open(
                mock_server_dir / "requirements_mock.txt", "a", encoding="utf-8"
            ) as f:
                f.write("pyjwt\n")
                f.write("python-multipart\n")  # Add python-multipart here

        if webhooks_enabled_bool:
            webhook_template = jinja_env.get_template("webhook_template.j2")
            webhook_code = webhook_template.render()
            with open(
                mock_server_dir / "webhook_handler.py", "w", encoding="utf-8"
            ) as f:
                f.write(webhook_code)
            with open(
                mock_server_dir / "requirements_mock.txt", "a", encoding="utf-8"
            ) as f:
                f.write("httpx\n")

        if storage_enabled_bool:
            storage_template = jinja_env.get_template("storage_template.j2")
            storage_code = storage_template.render()
            with open(mock_server_dir / "storage.py", "w", encoding="utf-8") as f:
                f.write(storage_code)
            (mock_server_dir / "mock_data").mkdir(exist_ok=True)

        if admin_ui_enabled_bool:
            # Load analytics charts and functions templates
            analytics_charts_template = jinja_env.get_template(
                "analytics_charts_template.j2"
            )
            analytics_charts_code = analytics_charts_template.render()

            analytics_functions_template = jinja_env.get_template(
                "analytics_functions_template.j2"
            )
            analytics_functions_code = analytics_functions_template.render()

            admin_ui_template = jinja_env.get_template("admin_ui_template.j2")
            admin_ui_code = admin_ui_template.render(
                api_title=spec_data.get("info", {}).get("title", "Mock API"),
                api_version=spec_data.get("info", {}).get("version", "1.0.0"),
                auth_enabled=auth_enabled_bool,
                webhooks_enabled=webhooks_enabled_bool,
                storage_enabled=storage_enabled_bool,
                analytics_charts_js=analytics_charts_code,
                analytics_functions_js=analytics_functions_code,
            )
            (mock_server_dir / "templates").mkdir(exist_ok=True)
            with open(
                mock_server_dir / "templates" / "admin.html", "w", encoding="utf-8"
            ) as f:
                f.write(admin_ui_code)
            with open(
                mock_server_dir / "requirements_mock.txt", "a", encoding="utf-8"
            ) as f:
                f.write("jinja2\n")

            # Generate log analyzer module for admin UI analytics
            log_analyzer_template = jinja_env.get_template("log_analyzer_template.j2")
            log_analyzer_code = log_analyzer_template.render()
            with open(mock_server_dir / "log_analyzer.py", "w", encoding="utf-8") as f:
                f.write(log_analyzer_code)

            # Copy favicon.ico to prevent 404s in admin UI
            import shutil

            favicon_source_paths = [
                Path(__file__).parent.parent.parent / "favicon.ico",  # Project root
                Path(__file__).parent / "favicon.ico",  # Template directory
                Path("favicon.ico"),  # Current directory
            ]

            for favicon_source in favicon_source_paths:
                if favicon_source.exists():
                    try:
                        shutil.copy2(favicon_source, mock_server_dir / "favicon.ico")
                        break
                    except Exception as e:
                        # Log the error and continue to next path if copy fails
                        print(f"Failed to copy favicon from {favicon_source}: {e}")
                        continue

        routes_code_parts: list[str] = []
        paths = spec_data.get("paths", {})
        for path_url, methods in paths.items():
            for method, details in methods.items():
                valid_methods = [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                    "head",
                    "trace",
                ]
                if method.lower() not in valid_methods:
                    continue
                path_params = ""
                parameters = details.get("parameters", [])
                path_param_list = []
                for param in parameters:
                    if param.get("in") == "path":
                        param_name = param.get("name")
                        param_type = param.get("schema", {}).get("type", "string")
                        python_type = "str"
                        if param_type == "integer":
                            python_type = "int"
                        elif param_type == "number":
                            python_type = "float"
                        elif param_type == "boolean":
                            python_type = "bool"
                        path_param_list.append(f"{param_name}: {python_type}")
                if path_param_list:
                    path_params = ", ".join(path_param_list)
                example_response = None
                responses = details.get("responses", {})
                for status_code, response_info in responses.items():
                    if status_code.startswith("2"):
                        content = response_info.get("content", {})
                        for content_type, content_schema in content.items():
                            if "application/json" in content_type:
                                if "example" in content_schema:
                                    converted_example = convert_js_to_python(
                                        content_schema["example"]
                                    )
                                    example_response = repr(converted_example)
                                    break
                                schema = content_schema.get("schema", {})
                                if "example" in schema:
                                    converted_example = convert_js_to_python(
                                        schema["example"]
                                    )
                                    example_response = repr(converted_example)
                                    break
                                examples = content_schema.get("examples", {})
                                if examples:
                                    first_example = next(iter(examples.values()), {})
                                    if "value" in first_example:
                                        converted_example = convert_js_to_python(
                                            first_example["value"]
                                        )
                                        example_response = repr(converted_example)
                                        break
                        if example_response:
                            break
                if not example_response:
                    for status_code, response_info in responses.items():
                        if status_code.startswith("2"):
                            content = response_info.get("content", {})
                            for content_type, content_schema in content.items():
                                if "application/json" in content_type:
                                    schema = content_schema.get("schema", {})
                                    mock_data = _generate_mock_data_from_schema(schema)
                                    if mock_data:
                                        # Convert JavaScript-style values to Python values before repr()
                                        converted_data = convert_js_to_python(mock_data)
                                        # Use repr() to ensure Python boolean values are properly formatted
                                        example_response = repr(converted_data)
                                        break
                            if example_response:
                                break
                route_template = jinja_env.get_template("route_template.j2")
                route_code = route_template.render(
                    method=method.lower(),
                    path=path_url,
                    summary=details.get("summary", f"{method.upper()} {path_url}"),
                    path_params=path_params,
                    example_response=example_response,
                    webhooks_enabled=webhooks_enabled_bool,
                )
                routes_code_parts.append(route_code)

        # Add favicon route when admin UI is enabled to prevent 404s
        if admin_ui_enabled_bool:
            favicon_route = '''@app.get("/favicon.ico", summary="Favicon", tags=["_system"])
async def favicon():
    """Serve favicon to prevent 404 errors in admin UI"""
    from fastapi.responses import FileResponse
    import os

    # Try to find favicon.ico in common locations
    favicon_paths = [
        "favicon.ico",
        "../favicon.ico",
        "../../favicon.ico",
        os.path.join(os.path.dirname(__file__), "favicon.ico"),
        os.path.join(os.path.dirname(__file__), "..", "favicon.ico"),
        os.path.join(os.path.dirname(__file__), "..", "..", "favicon.ico")
    ]

    for favicon_path in favicon_paths:
        if os.path.exists(favicon_path):
            return FileResponse(favicon_path, media_type="image/x-icon")

    # If no favicon found, return a simple 1x1 transparent PNG as fallback
    from fastapi.responses import Response
    # 1x1 transparent PNG in base64
    transparent_png = b'\\x89PNG\\r\\n\\x1a\\n\\x00\\x00\\x00\\rIHDR\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x08\\x06\\x00\\x00\\x00\\x1f\\x15\\xc4\\x89\\x00\\x00\\x00\\rIDATx\\x9cc\\xf8\\x0f\\x00\\x00\\x01\\x00\\x01\\x00\\x18\\xdd\\x8d\\xb4\\x00\\x00\\x00\\x00IEND\\xaeB`\\x82'
    return Response(content=transparent_png, media_type="image/png")'''
            routes_code_parts.append(favicon_route)

        all_routes_code = "\n\n".join(routes_code_parts)
        middleware_template = jinja_env.get_template("middleware_log_template.j2")
        logging_middleware_code = middleware_template.render()
        with open(
            mock_server_dir / "logging_middleware.py", "w", encoding="utf-8"
        ) as f:
            f.write(logging_middleware_code)

        # Generate separate admin logging middleware if admin UI is enabled
        if admin_ui_enabled_bool:
            admin_middleware_template = jinja_env.get_template(
                "admin_middleware_log_template.j2"
            )
            admin_logging_middleware_code = admin_middleware_template.render()
            with open(
                mock_server_dir / "admin_logging_middleware.py", "w", encoding="utf-8"
            ) as f:
                f.write(admin_logging_middleware_code)

        common_imports = "from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, Body, Query, Path, BackgroundTasks\nfrom fastapi.responses import HTMLResponse, JSONResponse\nfrom fastapi.templating import Jinja2Templates\nfrom fastapi.staticfiles import StaticFiles\nfrom fastapi.middleware.cors import CORSMiddleware\nfrom typing import List, Dict, Any, Optional\nimport json\nimport os\nimport time\nimport sqlite3\nimport logging\nfrom datetime import datetime\nfrom pathlib import Path\nfrom logging_middleware import LoggingMiddleware\n"
        auth_imports = (
            "from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer\nfrom auth_middleware import verify_api_key, verify_jwt_token, generate_token_response\n"
            if auth_enabled_bool
            else ""
        )
        webhook_imports = (
            'from webhook_handler import register_webhook, get_webhooks, delete_webhook, get_webhook_history, trigger_webhooks, test_webhook\n\n# Configure logging for webhook functionality\nlogger = logging.getLogger("webhook_handler")\n'
            if webhooks_enabled_bool
            else ""
        )
        storage_imports = (
            "from storage import StorageManager, get_storage_stats, get_collections\n"
            if storage_enabled_bool
            else ""
        )
        imports_section = (
            common_imports + auth_imports + webhook_imports + storage_imports
        )
        app_setup = 'app = FastAPI(title="{{ api_title }}", version="{{ api_version }}")\ntemplates = Jinja2Templates(directory="templates")\napp.add_middleware(LoggingMiddleware)\napp.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])\n\n# Setup database path for logs (same as in middleware)\ndb_dir = Path("db")\ndb_dir.mkdir(exist_ok=True)\nDB_PATH = db_dir / "request_logs.db"\n\n# Global variable for active scenario\nactive_scenario = None\n\n# Initialize active scenario from database on startup\ndef load_active_scenario():\n    global active_scenario\n    try:\n        conn = sqlite3.connect(str(DB_PATH))\n        conn.row_factory = sqlite3.Row\n        cursor = conn.cursor()\n        cursor.execute("SELECT id, name, config FROM mock_scenarios WHERE is_active = 1")\n        row = cursor.fetchone()\n        if row:\n            active_scenario = {\n                "id": row[0],\n                "name": row[1],\n                "config": json.loads(row[2]) if row[2] else {}\n            }\n        conn.close()\n    except Exception as e:\n        print(f"Error loading active scenario: {e}")\n        active_scenario = None\n\n# Load active scenario on startup\nload_active_scenario()\n'
        auth_endpoints_str = (
            '@app.post("/token", summary="Get access token", tags=["authentication"])\nasync def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):\n    return generate_token_response(form_data.username, form_data.password)\n'
            if auth_enabled_bool
            else ""
        )

        admin_api_endpoints_str = ""
        if admin_ui_enabled_bool:
            admin_api_endpoints_str = """    # --- Admin API Endpoints ---
    @admin_app.get("/api/export", tags=["_admin"])
    async def export_data():
        import io
        import zipfile
        from fastapi.responses import StreamingResponse

        try:
            # Create in-memory zip file
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Export request logs
                conn = sqlite3.connect(str(DB_PATH))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Get all request logs
                cursor.execute('''
                    SELECT * FROM request_logs ORDER BY created_at DESC
                ''')
                logs = cursor.fetchall()

                # Convert to JSON
                logs_data = []
                for row in logs:
                    log_entry = dict(row)
                    if log_entry.get('headers'):
                        try:
                            log_entry['headers'] = json.loads(log_entry['headers'])
                        except:
                            pass
                    logs_data.append(log_entry)

                # Add logs to zip
                zip_file.writestr("request_logs.json", json.dumps(logs_data, indent=2))

                # Export performance metrics if available
                try:
                    cursor.execute('SELECT * FROM performance_metrics ORDER BY recorded_at DESC')
                    metrics = [dict(row) for row in cursor.fetchall()]
                    zip_file.writestr("performance_metrics.json", json.dumps(metrics, indent=2))
                except:
                    pass

                # Export test sessions if available
                try:
                    cursor.execute('SELECT * FROM test_sessions ORDER BY created_at DESC')
                    sessions = [dict(row) for row in cursor.fetchall()]
                    zip_file.writestr("test_sessions.json", json.dumps(sessions, indent=2))
                except:
                    pass

                conn.close()

                # Add metadata
                metadata = {
                    "export_timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z', time.gmtime()),
                    "total_logs": len(logs_data),
                    "database_path": str(DB_PATH),
                    "server_info": {
                        "business_port": """ + str(business_port) + """,
                        "admin_port": """ + str(admin_port) + """,
                        "active_scenario": active_scenario
                    }
                }
                zip_file.writestr("metadata.json", json.dumps(metadata, indent=2))

            zip_buffer.seek(0)

            # Return as streaming response
            def iter_zip():
                yield zip_buffer.getvalue()

            timestamp = time.strftime('%Y%m%d_%H%M%S', time.gmtime())
            filename = f"mockloop_export_{timestamp}.zip"

            print(f"DEBUG ADMIN: Exported {len(logs_data)} logs to {filename}")

            return StreamingResponse(
                iter_zip(),
                media_type="application/zip",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )

        except Exception as e:
            print(f"DEBUG ADMIN: Error exporting data: {e}")
            return {"error": str(e)}

    @admin_app.get("/api/requests", tags=["_admin"])
    async def get_request_logs(limit: int = 100, offset: int = 0):
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get total count
            cursor.execute("SELECT COUNT(*) FROM request_logs")
            total_count = cursor.fetchone()[0]

            # Get paginated logs with all available columns
            cursor.execute('''
                SELECT id, timestamp, type, method, path, status_code, process_time_ms,
                       client_host, client_port, headers, query_params, request_body,
                       response_body, session_id, test_scenario, correlation_id,
                       user_agent, response_size, is_admin, created_at
                FROM request_logs
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))

            logs = []
            for row in cursor.fetchall():
                log_entry = {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "type": row["type"],
                    "method": row["method"],
                    "path": row["path"],
                    "status_code": row["status_code"],
                    "process_time_ms": row["process_time_ms"],
                    "client_host": row["client_host"],
                    "client_port": row["client_port"],
                    "headers": json.loads(row["headers"]) if row["headers"] else {},
                    "query_params": row["query_params"],
                    "request_body": row["request_body"],
                    "response_body": row["response_body"],
                    "session_id": row["session_id"],
                    "test_scenario": row["test_scenario"],
                    "correlation_id": row["correlation_id"],
                    "user_agent": row["user_agent"],
                    "response_size": row["response_size"],
                    "is_admin": bool(row["is_admin"]),
                    "created_at": row["created_at"]
                }
                logs.append(log_entry)

            conn.close()
            print(f"DEBUG ADMIN: Retrieved {len(logs)} logs from database (total: {total_count})")
            return {"logs": logs, "count": total_count}

        except Exception as e:
            print(f"DEBUG ADMIN: Error querying database: {e}")
            return {"logs": [], "count": 0, "error": str(e)}

    @admin_app.get("/api/debug", tags=["_admin"])
    async def get_debug_info():
        try:
            # Get database info
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.cursor()

            # Check database tables and counts
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            table_info = {}
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                table_info[table] = count

            # Get recent logs count
            cursor.execute("SELECT COUNT(*) FROM request_logs WHERE created_at > datetime('now', '-1 hour')")
            recent_logs = cursor.fetchone()[0]

            # Get schema version
            cursor.execute("SELECT MAX(version) FROM schema_version")
            schema_version = cursor.fetchone()[0] or 0

            conn.close()

            debug_info = {
                "status": "ok",
                "database": {
                    "path": str(DB_PATH),
                    "tables": table_info,
                    "schema_version": schema_version,
                    "recent_logs_1h": recent_logs
                },
                "server": {
                    "business_port": """ + str(business_port) + """,
                    "admin_port": """ + str(admin_port) + """,
                    "active_scenario": active_scenario
                },
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z', time.gmtime())
            }

            print(f"DEBUG ADMIN: Debug info retrieved successfully")
            return debug_info

        except Exception as e:
            print(f"DEBUG ADMIN: Error getting debug info: {e}")
            return {"status": "error", "error": str(e)}"""  # noqa: S608
        webhook_api_endpoints_str = ""
        if webhooks_enabled_bool and admin_ui_enabled_bool:
            _webhook_api_endpoints_raw = """
    @admin_app.get("/api/webhooks", tags=["_admin"])
    async def admin_get_webhooks():
        return get_webhooks()

    @admin_app.post("/api/webhooks", tags=["_admin"])
    async def admin_register_webhook(webhook_data: dict = Body(...)):
        event_type = webhook_data.get("event_type")
        url = webhook_data.get("url")
        description = webhook_data.get("description")
        if not event_type or not url:
            raise HTTPException(status_code=400, detail="event_type and url are required")
        return register_webhook(event_type, url, description)

    @admin_app.delete("/api/webhooks/{webhook_id}", tags=["_admin"])
    async def admin_delete_webhook(webhook_id: str):
        return delete_webhook(webhook_id)

    @admin_app.post("/api/webhooks/{webhook_id}/test", tags=["_admin"])
    async def admin_test_webhook(webhook_id: str):
        return await test_webhook(webhook_id)

    @admin_app.get("/api/webhooks/history", tags=["_admin"])
    async def admin_get_webhook_history():
        return get_webhook_history()"""
            webhook_api_endpoints_str = _webhook_api_endpoints_raw.strip()
        storage_api_endpoints_str = ""
        if storage_enabled_bool and admin_ui_enabled_bool:
            _storage_api_endpoints_raw = """
    @admin_app.get("/api/storage/stats", tags=["_admin"])
    async def admin_get_storage_stats():
        return get_storage_stats()

    @admin_app.get("/api/storage/collections", tags=["_admin"])
    async def admin_get_collections():
        return get_collections()
"""
            storage_api_endpoints_str = _storage_api_endpoints_raw.strip()

        if admin_ui_enabled_bool:
            admin_ui_endpoint_str = f'''    @admin_app.get("/", response_class=HTMLResponse, summary="Admin UI", tags=["_system"])
    async def read_admin_ui(request: Request):
        return templates.TemplateResponse("admin.html", {{
            "request": request,
            "api_title": "{api_title}",
            "api_version": "{api_version}",
            "auth_enabled": {auth_enabled_bool},
            "webhooks_enabled": {webhooks_enabled_bool},
            "storage_enabled": {storage_enabled_bool}
        }})'''
        else:
            admin_ui_endpoint_str = "    @app.get(\"/\")\n    async def no_admin(): return {'message': 'Admin UI not enabled'}"

        health_endpoint_str = '@app.get("/health", summary="Health check endpoint", tags=["_system"])\nasync def health_check(): return {"status": "healthy"}\n'

        # Create separate main sections for mocked API and admin servers
        business_main_section_str = f'''if __name__ == "__main__":
    import uvicorn
    import threading
    import time

    def run_business_server():
        uvicorn.run(app, host="0.0.0.0", port={business_port})

    # Create admin app at module level
    admin_app = FastAPI(title="{api_title} Admin", version="{api_version}")
    admin_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

    # Add admin-specific middleware for separate logging
    from admin_logging_middleware import AdminLoggingMiddleware
    admin_app.add_middleware(AdminLoggingMiddleware)

    def run_admin_server():
        # Run the admin server
        uvicorn.run(admin_app, host="0.0.0.0", port={admin_port})

    # Admin endpoints
    {admin_api_endpoints_str if admin_ui_enabled_bool else ""}
    {webhook_api_endpoints_str if webhooks_enabled_bool and admin_ui_enabled_bool else ""}
    {storage_api_endpoints_str if storage_enabled_bool and admin_ui_enabled_bool else ""}
    {admin_ui_endpoint_str if admin_ui_enabled_bool else ""}

    # Add health check for admin server
    @admin_app.get("/health", summary="Admin health check", tags=["_system"])
    async def admin_health_check():
        return {{"status": "healthy", "server": "admin"}}

    # Start both servers
    if {admin_ui_enabled_bool}:
        # Start admin server in separate thread
        admin_thread = threading.Thread(target=run_admin_server, daemon=True)
        admin_thread.start()
        time.sleep(1)  # Give admin server time to start

        print(f"Mocked API server starting on port {business_port}")
        print(f"Admin UI server running on port {admin_port}")
    else:
        print(f"Mocked API server starting on port {business_port}")

    # Start mocked API server (main thread)
    run_business_server()
'''

        main_app_template_str = (
            imports_section
            + app_setup
            + auth_endpoints_str
            + "\n# --- Generated Routes ---\n{{ routes_code }}\n# --- End Generated Routes ---\n"
            + health_endpoint_str
            + business_main_section_str
        )
        main_app_jinja_template = jinja_env.from_string(main_app_template_str)
        main_py_content = main_app_jinja_template.render(
            api_title=api_title,
            api_version=api_version,
            routes_code=all_routes_code,
            default_port=business_port,
        )
        with open(mock_server_dir / "main.py", "w", encoding="utf-8") as f:
            f.write(main_py_content)

        dockerfile_template = jinja_env.get_template("dockerfile_template.j2")
        dockerfile_content = dockerfile_template.render(
            python_version="3.9-slim",
            port=business_port,
            auth_enabled=auth_enabled_bool,
            webhooks_enabled=webhooks_enabled_bool,
            storage_enabled=storage_enabled_bool,
            admin_ui_enabled=admin_ui_enabled_bool,
        )
        with open(mock_server_dir / "Dockerfile", "w", encoding="utf-8") as f:
            f.write(dockerfile_content)

        compose_template = jinja_env.get_template("docker_compose_template.j2")
        timestamp_for_id = str(int(time.time()))[-6:]
        raw_api_title = spec_data.get("info", {}).get("title", "mock_api")
        clean_service_name = "".join(
            c if c.isalnum() else "-" for c in raw_api_title.lower()
        )
        while "--" in clean_service_name:
            clean_service_name = clean_service_name.replace("--", "-")
        clean_service_name = clean_service_name.strip("-")
        if not clean_service_name:
            clean_service_name = "mock-api"
        final_service_name = f"{clean_service_name}-mock"
        compose_content = compose_template.render(
            service_name=final_service_name,
            business_port=business_port,
            admin_port=admin_port,
            admin_ui_enabled=admin_ui_enabled_bool,
            timestamp_id=timestamp_for_id,
        )
        with open(mock_server_dir / "docker-compose.yml", "w", encoding="utf-8") as f:
            f.write(compose_content)

        return mock_server_dir

    except Exception as e:
        raise APIGenerationError(f"Failed to generate mock API: {e}") from e


if __name__ == "__main__":
    dummy_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.1"},
        "paths": {"/items": {"get": {"summary": "Get all items"}}},
    }
    with contextlib.suppress(APIGenerationError):
        generated_path = generate_mock_api(
            dummy_spec, mock_server_name="my_test_api_main"
        )
