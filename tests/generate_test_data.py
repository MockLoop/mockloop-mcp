#!/usr/bin/env python3
# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
MockLoop Test Data Generator

This script generates realistic test data for MockLoop mock servers including:
- Configurable number of API request logs with realistic patterns
- Performance metrics for each request
- Demo scenarios for testing
- Test sessions based on the generated logs

Usage:
    python generate_test_data.py [--db-path PATH] [--num-logs N] [--scenarios N]

Examples:
    # Generate default 500 logs in current directory
    python generate_test_data.py

    # Generate 1000 logs in specific database
    python generate_test_data.py --db-path /path/to/db/request_logs.db --num-logs 1000

    # Generate with custom scenarios
    python generate_test_data.py --scenarios 3
"""
# ruff: noqa: S311

import argparse
import json
import random
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# Default database path (can be overridden via command line)
DEFAULT_DB_PATH = Path("db/request_logs.db")

# Sample endpoints from the Petstore API
ENDPOINTS = [
    ("/pet/findByStatus", "GET"),
    ("/pet/findByTags", "GET"),
    ("/pet/{petId}", "GET"),
    ("/pet/{petId}", "POST"),
    ("/pet/{petId}", "DELETE"),
    ("/pet", "POST"),
    ("/pet", "PUT"),
    ("/store/inventory", "GET"),
    ("/store/order", "POST"),
    ("/store/order/{orderId}", "GET"),
    ("/store/order/{orderId}", "DELETE"),
    ("/user", "POST"),
    ("/user/login", "GET"),
    ("/user/logout", "GET"),
    ("/user/{username}", "GET"),
    ("/user/{username}", "PUT"),
    ("/user/{username}", "DELETE"),
]

# Sample user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "PostmanRuntime/7.32.3",
    "curl/7.68.0",
    "Python/3.9 requests/2.28.1",
    "Go-http-client/1.1",
    "Apache-HttpClient/4.5.13",
]

# Sample client IPs
CLIENT_IPS = [
    "192.168.1.100",
    "192.168.1.101",
    "192.168.1.102",
    "10.0.0.50",
    "10.0.0.51",
    "10.0.0.52",
    "172.16.0.10",
    "172.16.0.11",
    "172.16.0.12",
    "203.0.113.1",
    "203.0.113.2",
    "203.0.113.3",
]


def generate_sample_headers(user_agent, client_ip):
    """Generate realistic HTTP headers."""
    return {
        "host": "localhost:8000",
        "user-agent": user_agent,
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate",
        "connection": "keep-alive",
        "x-forwarded-for": client_ip,
        "content-type": "application/json"
        if random.choice([True, False])
        else "text/plain",
    }


def generate_sample_response_body(path, method):
    """Generate realistic response body based on endpoint."""
    if "/pet" in path and method == "GET":
        if "findByStatus" in path:
            return json.dumps(
                [
                    {
                        "id": random.randint(1, 1000),
                        "name": random.choice(
                            ["Fluffy", "Buddy", "Max", "Bella", "Charlie", "Luna"]
                        ),
                        "status": random.choice(["available", "pending", "sold"]),
                        "category": {
                            "id": random.randint(1, 10),
                            "name": random.choice(["Dogs", "Cats", "Birds"]),
                        },
                        "tags": [
                            {
                                "id": random.randint(1, 20),
                                "name": f"tag{random.randint(1, 5)}",
                            }
                        ],
                    }
                ]
            )
        elif "/user" in path:
            return json.dumps(
                {
                    "id": random.randint(1, 1000),
                    "username": f"user{random.randint(1, 100)}",
                    "firstName": random.choice(
                        ["John", "Jane", "Bob", "Alice", "Charlie"]
                    ),
                    "lastName": random.choice(
                        ["Doe", "Smith", "Johnson", "Brown", "Davis"]
                    ),
                    "email": f"user{random.randint(1, 100)}@example.com",
                    "phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
                    "userStatus": random.randint(0, 2),
                }
            )
        else:
            return json.dumps(
                {
                    "id": random.randint(1, 1000),
                    "name": random.choice(
                        ["Fluffy", "Buddy", "Max", "Bella", "Charlie", "Luna"]
                    ),
                    "status": random.choice(["available", "pending", "sold"]),
                    "category": {
                        "id": random.randint(1, 10),
                        "name": random.choice(["Dogs", "Cats", "Birds"]),
                    },
                    "photoUrls": [
                        f"https://example.com/photo{random.randint(1, 10)}.jpg"
                    ],
                    "tags": [
                        {
                            "id": random.randint(1, 20),
                            "name": f"tag{random.randint(1, 5)}",
                        }
                    ],
                }
            )
    elif "/store/inventory" in path:
        return json.dumps(
            {
                "available": random.randint(10, 100),
                "pending": random.randint(5, 50),
                "sold": random.randint(20, 200),
            }
        )
    elif "/user" in path and method == "GET":
        return json.dumps(
            {
                "id": random.randint(1, 1000),
                "username": f"user{random.randint(1, 100)}",
                "firstName": random.choice(["John", "Jane", "Bob", "Alice", "Charlie"]),
                "lastName": random.choice(
                    ["Doe", "Smith", "Johnson", "Brown", "Davis"]
                ),
                "email": f"user{random.randint(1, 100)}@example.com",
                "phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
                "userStatus": random.randint(0, 2),
            }
        )
    else:
        return json.dumps(
            {"message": "success", "data": {"id": random.randint(1, 1000)}}
        )


def generate_sample_request_body(path, method):
    """Generate realistic request body for POST/PUT requests."""
    if method in ["POST", "PUT"]:
        if "/pet" in path:
            return json.dumps(
                {
                    "id": random.randint(1, 1000),
                    "name": random.choice(
                        ["Fluffy", "Buddy", "Max", "Bella", "Charlie", "Luna"]
                    ),
                    "status": random.choice(["available", "pending", "sold"]),
                    "category": {
                        "id": random.randint(1, 10),
                        "name": random.choice(["Dogs", "Cats", "Birds"]),
                    },
                    "photoUrls": [
                        f"https://example.com/photo{random.randint(1, 10)}.jpg"
                    ],
                    "tags": [
                        {
                            "id": random.randint(1, 20),
                            "name": f"tag{random.randint(1, 5)}",
                        }
                    ],
                }
            )
        elif "/store/inventory" in path:
            return json.dumps(
                {
                    "available": random.randint(10, 100),
                    "pending": random.randint(5, 50),
                    "sold": random.randint(20, 200),
                }
            )
        elif "/user" in path and method == "GET":
            return json.dumps(
                {
                    "id": random.randint(1, 1000),
                    "username": f"user{random.randint(1, 100)}",
                    "firstName": random.choice(
                        ["John", "Jane", "Bob", "Alice", "Charlie"]
                    ),
                    "lastName": random.choice(
                        ["Doe", "Smith", "Johnson", "Brown", "Davis"]
                    ),
                    "email": f"user{random.randint(1, 100)}@example.com",
                    "phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
                    "userStatus": random.randint(0, 2),
                }
            )
    return None


def generate_test_logs(conn, num_logs=500):
    """Generate realistic test logs with performance metrics."""
    cursor = conn.cursor()

    print(f"Generating {num_logs} test logs...")

    # Time range: past week
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)

    for i in range(num_logs):
        # Random timestamp within the past week
        random_time = start_time + timedelta(
            seconds=random.randint(0, int((end_time - start_time).total_seconds()))
        )

        # Random endpoint
        path, method = random.choice(ENDPOINTS)

        # Replace path parameters with actual values
        if "{petId}" in path:
            path = path.replace("{petId}", str(random.randint(1, 100)))
        if "{orderId}" in path:
            path = path.replace("{orderId}", str(random.randint(1, 1000)))
        if "{username}" in path:
            path = path.replace("{username}", f"user{random.randint(1, 50)}")

        # Random response characteristics
        status_code = random.choices(
            [200, 201, 400, 404, 500],
            weights=[70, 15, 8, 5, 2],  # Mostly successful responses
        )[0]

        process_time_ms = random.randint(1, 500)  # 1-500ms response time

        # Random client info
        client_ip = random.choice(CLIENT_IPS)
        user_agent = random.choice(USER_AGENTS)

        # Generate request/response data
        headers = generate_sample_headers(user_agent, client_ip)
        request_body = generate_sample_request_body(path, method)
        response_body = generate_sample_response_body(path, method)

        # Random session info (some requests have sessions)
        session_id = (
            f"session_{random.randint(1, 20)}" if random.random() < 0.3 else None
        )
        test_scenario = random.choice(
            ["load_test", "stress_test", None, None, None]
        )  # 40% have scenarios
        correlation_id = (
            f"corr_{random.randint(1000, 9999)}" if random.random() < 0.2 else None
        )

        # Insert request log
        request_id = f"req_{int(time.time() * 1000)}_{i}"
        cursor.execute(
            """
            INSERT INTO request_logs (
                id, timestamp, method, path, status_code, process_time_ms,
                client_ip, client_port, headers, query_params, request_body,
                response_body, session_id, correlation_id, test_scenario
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                request_id,
                random_time.strftime("%Y-%m-%dT%H:%M:%S"),
                method,
                path,
                status_code,
                process_time_ms,
                client_ip,
                str(random.randint(40000, 65000)),  # Random client port
                json.dumps(headers),
                "status=available" if "findByStatus" in path else "",
                request_body,
                response_body,
                session_id,
                correlation_id,
                test_scenario,
            ),
        )

        # Insert performance metrics
        cursor.execute(
            """
            INSERT INTO performance_metrics (
                request_id, response_time_ms, memory_usage_mb, cpu_usage_percent,
                db_queries, cache_hits, cache_misses, request_size_bytes,
                response_size_bytes, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                request_id,
                process_time_ms,
                random.uniform(45.0, 55.0),  # Memory usage 45-55MB
                random.uniform(0.5, 5.0),  # CPU usage 0.5-5%
                random.randint(0, 3),  # DB queries
                random.randint(0, 5),  # Cache hits
                random.randint(0, 2),  # Cache misses
                len(request_body) if request_body else 0,
                len(response_body) if response_body else 0,
                random_time.strftime("%Y-%m-%dT%H:%M:%S"),
            ),
        )

        if (i + 1) % 100 == 0:
            print(f"Generated {i + 1} logs...")

    conn.commit()
    print(f"Successfully generated {num_logs} test logs!")


def create_demo_scenarios(conn, num_scenarios=2):
    """Create demo scenarios."""
    cursor = conn.cursor()

    print(f"Creating {num_scenarios} demo scenarios...")

    scenarios = [
        {
            "name": "High Traffic Load Test",
            "description": "Simulates high traffic conditions with optimized responses for load testing",
            "config": {
                "/pet/findByStatus": {
                    "status": 200,
                    "data": [
                        {
                            "id": 1,
                            "name": "Fluffy",
                            "status": "available",
                            "category": {"id": 1, "name": "Dogs"},
                            "photoUrls": ["https://example.com/fluffy.jpg"],
                            "tags": [{"id": 1, "name": "friendly"}],
                        },
                        {
                            "id": 2,
                            "name": "Buddy",
                            "status": "available",
                            "category": {"id": 1, "name": "Dogs"},
                            "photoUrls": ["https://example.com/buddy.jpg"],
                            "tags": [{"id": 2, "name": "playful"}],
                        },
                    ],
                }
            },
        },
        {
            "name": "Error Simulation",
            "description": "Simulates various error conditions for testing error handling and resilience",
            "config": {
                "/pet/{petId}": {
                    "status": 404,
                    "data": {"code": 404, "type": "error", "message": "Pet not found"},
                },
                "/store/inventory": {
                    "status": 500,
                    "data": {
                        "code": 500,
                        "type": "error",
                        "message": "Internal server error",
                    },
                },
            },
        },
        {
            "name": "Performance Testing",
            "description": "Optimized responses for performance and load testing scenarios",
            "config": {
                "/pet/findByStatus": {
                    "status": 200,
                    "data": [],  # Empty response for faster processing
                },
                "/store/inventory": {
                    "status": 200,
                    "data": {"available": 100, "pending": 0, "sold": 0},
                },
            },
        },
    ]

    for scenario in scenarios[:num_scenarios]:
        cursor.execute(
            """
            INSERT INTO mock_scenarios (name, description, config, is_active)
            VALUES (?, ?, ?, ?)
        """,
            (
                scenario["name"],
                scenario["description"],
                json.dumps(scenario["config"]),
                0,
            ),
        )

    conn.commit()
    print(f"Successfully created {num_scenarios} demo scenarios!")


def update_test_sessions(conn):
    """Create some test sessions based on the generated logs."""
    cursor = conn.cursor()

    print("Creating test sessions...")

    # Get unique session IDs from logs
    cursor.execute(
        "SELECT DISTINCT session_id FROM request_logs WHERE session_id IS NOT NULL"
    )
    session_ids = [row[0] for row in cursor.fetchall()]

    for session_id in session_ids:
        # Get session stats
        cursor.execute(
            """
            SELECT COUNT(*), AVG(process_time_ms), MIN(timestamp), MAX(timestamp)
            FROM request_logs
            WHERE session_id = ?
        """,
            (session_id,),
        )

        stats = cursor.fetchone()
        if stats:
            total_requests, avg_response_time, start_time, end_time = stats

            # Determine scenario name
            cursor.execute(
                """
                SELECT test_scenario FROM request_logs
                WHERE session_id = ? AND test_scenario IS NOT NULL
                LIMIT 1
            """,
                (session_id,),
            )

            scenario_result = cursor.fetchone()
            scenario_name = scenario_result[0] if scenario_result else "general_testing"

            # Insert test session
            cursor.execute(
                """
                INSERT INTO test_sessions (
                    session_id, start_time, end_time, total_requests,
                    avg_response_time_ms, scenario_name, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    start_time,
                    end_time,
                    total_requests,
                    avg_response_time,
                    scenario_name,
                    json.dumps(
                        {
                            "client_info": "Generated test session",
                            "test_type": scenario_name,
                            "duration_minutes": random.randint(5, 60),
                        }
                    ),
                ),
            )

    conn.commit()
    print(f"Successfully created {len(session_ids)} test sessions!")


def init_database(conn):
    """Initialize database tables if they don't exist."""
    cursor = conn.cursor()

    print("Initializing database tables...")

    # Create the base table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS request_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        process_time_ms REAL NOT NULL,
        client_ip TEXT,
        client_port TEXT,
        headers TEXT,
        query_params TEXT,
        request_body TEXT,
        response_body TEXT,
        session_id TEXT,
        correlation_id TEXT,
        test_scenario TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create performance metrics table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS performance_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT NOT NULL,
        response_time_ms REAL NOT NULL,
        memory_usage_mb REAL,
        cpu_usage_percent REAL,
        db_queries INTEGER DEFAULT 0,
        cache_hits INTEGER DEFAULT 0,
        cache_misses INTEGER DEFAULT 0,
        request_size_bytes INTEGER DEFAULT 0,
        response_size_bytes INTEGER DEFAULT 0,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (request_id) REFERENCES request_logs (id)
    )
    """)

    # Create test sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS test_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        total_requests INTEGER NOT NULL,
        avg_response_time_ms REAL NOT NULL,
        scenario_name TEXT,
        metadata TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create mock scenarios table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mock_scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        config TEXT NOT NULL,
        is_active INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    print("Database tables initialized successfully!")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate test data for MockLoop mock servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Generate 500 logs with default settings
  %(prog)s --num-logs 1000                    # Generate 1000 logs
  %(prog)s --db-path /custom/path/db.sqlite   # Use custom database path
  %(prog)s --scenarios 3                      # Create 3 demo scenarios
        """,
    )

    parser.add_argument(
        "--db-path",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database file (default: {DEFAULT_DB_PATH})",
    )

    parser.add_argument(
        "--num-logs",
        type=int,
        default=500,
        help="Number of test logs to generate (default: 500)",
    )

    parser.add_argument(
        "--scenarios",
        type=int,
        default=2,
        help="Number of demo scenarios to create (default: 2, max: 3)",
    )

    return parser.parse_args()


def main():
    """Main function."""
    args = parse_args()

    print("MockLoop Test Data Generator")
    print("=" * 40)
    print(f"Database: {args.db_path}")
    print(f"Logs to generate: {args.num_logs}")
    print(f"Scenarios to create: {args.scenarios}")
    print("=" * 40)

    # Ensure database directory exists
    args.db_path.parent.mkdir(parents=True, exist_ok=True)

    # Connect to database
    conn = sqlite3.connect(str(args.db_path))

    try:
        # Initialize database tables
        init_database(conn)

        # Generate test logs and performance metrics
        generate_test_logs(conn, args.num_logs)

        # Create demo scenarios
        create_demo_scenarios(conn, min(args.scenarios, 3))

        # Create test sessions
        update_test_sessions(conn)

        print("\n" + "=" * 40)
        print("✅ Test data generation completed successfully!")
        print(f"📊 Generated {args.num_logs} request logs")
        print(f"📈 Created {args.num_logs} performance metrics")
        print(f"🎭 Created {min(args.scenarios, 3)} demo scenarios")
        print(f"📝 Database saved to: {args.db_path}")
        print("\n🌐 You can now view the rich performance data in the admin UI at:")
        print("   http://localhost:8000/admin")

    except Exception as e:
        print(f"❌ Error generating test data: {e}")
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
