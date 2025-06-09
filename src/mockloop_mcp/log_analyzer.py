# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
Log analysis utilities for MockLoop servers.
"""

from collections import Counter, defaultdict
from datetime import datetime
import logging
import re
import statistics
from typing import Any

# Configure logger for this module
logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Analyzer for MockLoop server request logs."""

    def __init__(self):
        """Initialize the log analyzer."""
        pass

    def analyze_logs(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Perform comprehensive analysis of request logs.

        Args:
            logs: List of log entries

        Returns:
            Dict containing analysis results
        """
        if not logs:
            return {
                "total_requests": 0,
                "analysis_timestamp": datetime.now().isoformat(),
                "error": "No logs provided for analysis",
            }

        analysis = {
            "total_requests": len(logs),
            "analysis_timestamp": datetime.now().isoformat(),
            "time_range": self._analyze_time_range(logs),
            "methods": self._analyze_methods(logs),
            "status_codes": self._analyze_status_codes(logs),
            "endpoints": self._analyze_endpoints(logs),
            "performance": self._analyze_performance(logs),
            "errors": self._analyze_errors(logs),
            "patterns": self._detect_patterns(logs),
            "insights": [],
        }

        # Generate insights based on analysis
        analysis["insights"] = self._generate_insights(analysis)

        return analysis

    def _analyze_time_range(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze the time range of logs."""
        timestamps = []
        for log in logs:
            if log.get("timestamp"):
                try:
                    # Handle different timestamp formats
                    timestamp_str = log["timestamp"]
                    if "T" in timestamp_str:
                        # ISO format
                        timestamp = datetime.fromisoformat(
                            timestamp_str.replace("Z", "+00:00")
                        )
                    else:
                        # Try parsing as standard format
                        timestamp = datetime.strptime(
                            timestamp_str, "%Y-%m-%d %H:%M:%S"
                        )
                    timestamps.append(timestamp)
                except Exception as e:
                    logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
                    continue

        if not timestamps:
            return {"error": "No valid timestamps found"}

        timestamps.sort()
        duration = timestamps[-1] - timestamps[0]

        return {
            "earliest": timestamps[0].isoformat(),
            "latest": timestamps[-1].isoformat(),
            "duration_seconds": duration.total_seconds(),
            "duration_human": str(duration),
            "total_entries": len(timestamps),
        }

    def _analyze_methods(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze HTTP methods distribution."""
        methods = Counter(log.get("method", "UNKNOWN") for log in logs)
        total = sum(methods.values())

        return {
            "distribution": dict(methods),
            "percentages": {
                method: round((count / total) * 100, 2)
                for method, count in methods.items()
            },
            "most_common": methods.most_common(1)[0] if methods else None,
        }

    def _analyze_status_codes(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze HTTP status codes distribution."""
        status_codes = Counter(log.get("status_code", 0) for log in logs)
        total = sum(status_codes.values())

        # Categorize status codes
        success_codes = sum(
            count for code, count in status_codes.items() if 200 <= code < 300
        )
        client_errors = sum(
            count for code, count in status_codes.items() if 400 <= code < 500
        )
        server_errors = sum(
            count for code, count in status_codes.items() if 500 <= code < 600
        )

        return {
            "distribution": dict(status_codes),
            "percentages": {
                str(code): round((count / total) * 100, 2)
                for code, count in status_codes.items()
            },
            "categories": {
                "success_2xx": success_codes,
                "client_error_4xx": client_errors,
                "server_error_5xx": server_errors,
            },
            "success_rate": round((success_codes / total) * 100, 2) if total > 0 else 0,
            "error_rate": round(((client_errors + server_errors) / total) * 100, 2)
            if total > 0
            else 0,
        }

    def _analyze_endpoints(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze endpoint usage patterns."""
        endpoints = Counter(log.get("path", "unknown") for log in logs)
        total = sum(endpoints.values())

        # Group by endpoint patterns (remove IDs, etc.)
        endpoint_patterns = defaultdict(int)
        for path, count in endpoints.items():
            # Simple pattern detection - replace numbers with {id}
            pattern = re.sub(r"/\d+", "/{id}", path)
            pattern = re.sub(r"/[a-f0-9-]{36}", "/{uuid}", pattern)  # UUIDs
            endpoint_patterns[pattern] += count

        return {
            "total_unique_endpoints": len(endpoints),
            "distribution": dict(endpoints.most_common(10)),  # Top 10
            "patterns": dict(endpoint_patterns),
            "most_accessed": endpoints.most_common(1)[0] if endpoints else None,
            "percentages": {
                path: round((count / total) * 100, 2)
                for path, count in endpoints.most_common(10)
            },
        }

    def _analyze_performance(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze performance metrics."""
        response_times = []
        for log in logs:
            if log.get("process_time_ms") is not None:
                try:
                    response_times.append(float(log["process_time_ms"]))
                except (ValueError, TypeError):
                    continue

        if not response_times:
            return {"error": "No response time data available"}

        # Calculate statistics
        avg_time = statistics.mean(response_times)
        median_time = statistics.median(response_times)
        min_time = min(response_times)
        max_time = max(response_times)

        # Calculate percentiles
        response_times.sort()
        p95 = response_times[int(0.95 * len(response_times))]
        p99 = response_times[int(0.99 * len(response_times))]

        # Performance categorization
        fast_requests = sum(1 for t in response_times if t < 100)
        medium_requests = sum(1 for t in response_times if 100 <= t < 500)
        slow_requests = sum(1 for t in response_times if t >= 500)

        return {
            "average_ms": round(avg_time, 2),
            "median_ms": round(median_time, 2),
            "min_ms": round(min_time, 2),
            "max_ms": round(max_time, 2),
            "p95_ms": round(p95, 2),
            "p99_ms": round(p99, 2),
            "performance_distribution": {
                "fast_under_100ms": fast_requests,
                "medium_100_500ms": medium_requests,
                "slow_over_500ms": slow_requests,
            },
            "total_measured": len(response_times),
        }

    def _analyze_errors(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze error patterns and frequencies."""
        error_logs = [log for log in logs if log.get("status_code", 0) >= 400]

        if not error_logs:
            return {"total_errors": 0, "message": "No errors found"}

        # Analyze error types
        error_codes = Counter(log.get("status_code") for log in error_logs)
        error_endpoints = Counter(log.get("path") for log in error_logs)
        error_methods = Counter(log.get("method") for log in error_logs)

        # Time-based error analysis
        error_times = []
        for log in error_logs:
            if log.get("timestamp"):
                try:
                    timestamp_str = log["timestamp"]
                    if "T" in timestamp_str:
                        timestamp = datetime.fromisoformat(
                            timestamp_str.replace("Z", "+00:00")
                        )
                    else:
                        timestamp = datetime.strptime(
                            timestamp_str, "%Y-%m-%d %H:%M:%S"
                        )
                    error_times.append(timestamp)
                except Exception as e:
                    logger.debug(
                        f"Failed to parse error timestamp '{timestamp_str}': {e}"
                    )
                    continue

        return {
            "total_errors": len(error_logs),
            "error_rate": round((len(error_logs) / len(logs)) * 100, 2),
            "by_status_code": dict(error_codes),
            "by_endpoint": dict(error_endpoints.most_common(5)),
            "by_method": dict(error_methods),
            "time_distribution": self._analyze_error_time_distribution(error_times)
            if error_times
            else {},
        }

    def _analyze_error_time_distribution(
        self, error_times: list[datetime]
    ) -> dict[str, Any]:
        """Analyze when errors occur over time."""
        if not error_times:
            return {}

        error_times.sort()

        # Group by hour
        hourly_errors = defaultdict(int)
        for timestamp in error_times:
            hour_key = timestamp.strftime("%Y-%m-%d %H:00")
            hourly_errors[hour_key] += 1

        return {
            "first_error": error_times[0].isoformat(),
            "last_error": error_times[-1].isoformat(),
            "hourly_distribution": dict(hourly_errors),
            "peak_error_hour": max(hourly_errors.items(), key=lambda x: x[1])
            if hourly_errors
            else None,
        }

    def _detect_patterns(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Detect interesting patterns in the logs."""
        patterns = {}

        # Detect potential bot traffic
        user_agents = [
            log.get("headers", {}).get("user-agent", "")
            for log in logs
            if log.get("headers")
        ]
        bot_indicators = ["bot", "crawler", "spider", "scraper"]
        potential_bot_requests = sum(
            1
            for ua in user_agents
            if any(indicator.lower() in ua.lower() for indicator in bot_indicators)
        )

        if potential_bot_requests > 0:
            patterns["potential_bot_traffic"] = {
                "count": potential_bot_requests,
                "percentage": round((potential_bot_requests / len(logs)) * 100, 2),
            }

        # Detect repeated requests from same client
        client_ips = Counter(log.get("client_host", "unknown") for log in logs)
        high_volume_clients = {
            ip: count for ip, count in client_ips.items() if count > len(logs) * 0.1
        }

        if high_volume_clients:
            patterns["high_volume_clients"] = high_volume_clients

        # Detect admin endpoint usage
        admin_requests = [
            log for log in logs if log.get("path", "").startswith("/admin")
        ]
        if admin_requests:
            patterns["admin_usage"] = {
                "count": len(admin_requests),
                "percentage": round((len(admin_requests) / len(logs)) * 100, 2),
                "unique_admin_endpoints": len(
                    {log.get("path") for log in admin_requests}
                ),
            }

        return patterns

    def _generate_insights(self, analysis: dict[str, Any]) -> list[str]:
        """Generate human-readable insights from the analysis."""
        insights = []

        # Performance insights
        perf = analysis.get("performance", {})
        if perf.get("average_ms", 0) > 1000:
            insights.append(f"⚠️ High average response time: {perf['average_ms']}ms")
        elif perf.get("average_ms", 0) < 50:
            insights.append(
                f"✅ Excellent performance: {perf['average_ms']}ms average response time"
            )

        # Error rate insights
        status = analysis.get("status_codes", {})
        error_rate = status.get("error_rate", 0)
        if error_rate > 10:
            insights.append(f"🚨 High error rate: {error_rate}% of requests failed")
        elif error_rate < 1:
            insights.append(f"✅ Low error rate: {error_rate}% - system is stable")

        # Traffic patterns
        methods = analysis.get("methods", {})
        if methods.get("most_common"):
            method, count = methods["most_common"]
            percentage = methods.get("percentages", {}).get(method, 0)
            insights.append(
                f"📊 Most common method: {method} ({percentage}% of requests)"
            )

        # Endpoint usage
        endpoints = analysis.get("endpoints", {})
        if endpoints.get("most_accessed"):
            path, count = endpoints["most_accessed"]
            insights.append(f"🎯 Most accessed endpoint: {path} ({count} requests)")

        # Pattern insights
        patterns = analysis.get("patterns", {})
        if patterns.get("potential_bot_traffic"):
            bot_percentage = patterns["potential_bot_traffic"]["percentage"]
            insights.append(
                f"🤖 Potential bot traffic detected: {bot_percentage}% of requests"
            )

        if patterns.get("high_volume_clients"):
            client_count = len(patterns["high_volume_clients"])
            insights.append(f"📈 {client_count} high-volume clients detected")

        # Time range insights
        time_range = analysis.get("time_range", {})
        if time_range.get("duration_seconds", 0) > 0:
            duration = time_range["duration_seconds"]
            rps = analysis["total_requests"] / duration
            insights.append(f"⏱️ Average request rate: {rps:.2f} requests/second")

        return insights

    def filter_logs(
        self,
        logs: list[dict[str, Any]],
        method: str | None = None,
        status_code: int | None = None,
        path_pattern: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        include_admin: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Filter logs based on various criteria.

        Args:
            logs: List of log entries
            method: HTTP method filter
            status_code: Status code filter
            path_pattern: Regex pattern for path filtering
            time_from: Start time filter (ISO format)
            time_to: End time filter (ISO format)
            include_admin: Whether to include admin requests

        Returns:
            Filtered list of logs
        """
        filtered_logs = logs.copy()

        # Filter by method
        if method:
            filtered_logs = [
                log for log in filtered_logs if log.get("method") == method.upper()
            ]

        # Filter by status code
        if status_code:
            filtered_logs = [
                log for log in filtered_logs if log.get("status_code") == status_code
            ]

        # Filter by path pattern
        if path_pattern:
            try:
                pattern = re.compile(path_pattern)
                filtered_logs = [
                    log for log in filtered_logs if pattern.search(log.get("path", ""))
                ]
            except re.error:
                # Invalid regex, skip pattern filtering
                pass

        # Filter by time range
        if time_from or time_to:
            time_filtered = []
            for log in filtered_logs:
                if not log.get("timestamp"):
                    continue

                try:
                    timestamp_str = log["timestamp"]
                    if "T" in timestamp_str:
                        log_time = datetime.fromisoformat(
                            timestamp_str.replace("Z", "+00:00")
                        )
                    else:
                        log_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                    if time_from:
                        from_time = datetime.fromisoformat(
                            time_from.replace("Z", "+00:00")
                        )
                        if log_time < from_time:
                            continue

                    if time_to:
                        to_time = datetime.fromisoformat(time_to.replace("Z", "+00:00"))
                        if log_time > to_time:
                            continue

                    time_filtered.append(log)
                except Exception as e:
                    logger.debug(f"Failed to parse log timestamp for filtering: {e}")
                    continue

            filtered_logs = time_filtered

        # Filter admin requests
        if not include_admin:
            filtered_logs = [
                log
                for log in filtered_logs
                if not log.get("path", "").startswith("/admin")
            ]

        return filtered_logs


# Convenience functions
def quick_analyze(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Quick analysis of logs using default analyzer.

    Args:
        logs: List of log entries

    Returns:
        Analysis results
    """
    analyzer = LogAnalyzer()
    return analyzer.analyze_logs(logs)


def filter_and_analyze(logs: list[dict[str, Any]], **filter_kwargs) -> dict[str, Any]:
    """
    Filter logs and perform analysis.

    Args:
        logs: List of log entries
        **filter_kwargs: Filter parameters

    Returns:
        Analysis results for filtered logs
    """
    analyzer = LogAnalyzer()
    filtered_logs = analyzer.filter_logs(logs, **filter_kwargs)
    return analyzer.analyze_logs(filtered_logs)
