# Copyright (c) 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: MIT
#
# This file is part of the MockLoop project. (https://mockloop.com)
# You may obtain a copy of the license at https://opensource.org/licenses/MIT

"""
MCP Context Management System for MockLoop

This module provides comprehensive context management for stateful testing workflows,
cross-session orchestration, and agent-specific state management.

Features:
- Multiple context types for different workflow scenarios
- Context persistence and storage using SQLite
- Context inheritance and hierarchical relationships
- Context snapshots for rollback capabilities
- Cross-session data sharing via GlobalContext
- Agent-specific state management via AgentContext
- Thread-safe operations for multi-agent scenarios
- Comprehensive audit logging integration
"""

import asyncio
import json
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union
import logging

# Configure logger for this module
logger = logging.getLogger(__name__)


class ContextType(Enum):
    """Enumeration of available context types."""

    TEST_SESSION = "test_session"
    WORKFLOW = "workflow"
    SCENARIO = "scenario"
    PERFORMANCE = "performance"
    GLOBAL = "global"
    AGENT = "agent"


class ContextStatus(Enum):
    """Enumeration of context status values."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    EXPIRED = "expired"
    ERROR = "error"


class ContextError(Exception):
    """Base exception for context management errors."""

    pass


class ContextNotFoundError(ContextError):
    """Raised when a requested context is not found."""

    pass


class ContextValidationError(ContextError):
    """Raised when context validation fails."""

    pass


class ContextPersistenceError(ContextError):
    """Raised when context persistence operations fail."""

    pass


class ContextSnapshot:
    """Represents a snapshot of context state for rollback capabilities."""

    def __init__(
        self,
        context_id: str,
        snapshot_data: dict[str, Any],
        timestamp: datetime | None = None,
    ):
        self.context_id = context_id
        self.snapshot_data = snapshot_data
        self.timestamp = timestamp or datetime.utcnow()
        self.snapshot_id = str(uuid.uuid4())

    def to_dict(self) -> dict[str, Any]:
        """Convert snapshot to dictionary representation."""
        return {
            "snapshot_id": self.snapshot_id,
            "context_id": self.context_id,
            "snapshot_data": self.snapshot_data,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ContextSnapshot":
        """Create snapshot from dictionary representation."""
        return cls(
            context_id=data["context_id"],
            snapshot_data=data["snapshot_data"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


class BaseContext:
    """Base class for all context types."""

    def __init__(
        self,
        context_id: str,
        context_type: ContextType,
        data: dict[str, Any] | None = None,
        parent_context_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.context_id = context_id
        self.context_type = context_type
        self.data = data or {}
        self.parent_context_id = parent_context_id
        self.metadata = metadata or {}
        self.created_at = datetime.utcnow()
        self.updated_at = self.created_at
        self.status = ContextStatus.ACTIVE
        self.expiry_time: datetime | None = None
        self.tags: set[str] = set()
        self._lock = threading.RLock()
        self._snapshots: list[ContextSnapshot] = []

    def update_data(self, updates: dict[str, Any], merge: bool = True) -> None:
        """Update context data with change tracking."""
        with self._lock:
            if merge:
                self.data.update(updates)
            else:
                self.data = updates.copy()
            self.updated_at = datetime.utcnow()

    def get_data(self, key: str | None = None, default: Any = None) -> Any:
        """Get context data with optional key filtering."""
        with self._lock:
            if key is None:
                return self.data.copy()
            return self.data.get(key, default)

    def add_tag(self, tag: str) -> None:
        """Add a tag to the context."""
        with self._lock:
            self.tags.add(tag)
            self.updated_at = datetime.utcnow()

    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the context."""
        with self._lock:
            self.tags.discard(tag)
            self.updated_at = datetime.utcnow()

    def has_tag(self, tag: str) -> bool:
        """Check if context has a specific tag."""
        with self._lock:
            return tag in self.tags

    def set_expiry(self, expiry_time: datetime) -> None:
        """Set context expiry time."""
        with self._lock:
            self.expiry_time = expiry_time
            self.updated_at = datetime.utcnow()

    def is_expired(self) -> bool:
        """Check if context has expired."""
        with self._lock:
            if self.expiry_time is None:
                return False
            return datetime.utcnow() > self.expiry_time

    def create_snapshot(self, description: str | None = None) -> ContextSnapshot:
        """Create a snapshot of current context state."""
        with self._lock:
            snapshot_data = {
                "data": self.data.copy(),
                "metadata": self.metadata.copy(),
                "status": self.status.value,
                "tags": list(self.tags),
                "description": description,
            }
            snapshot = ContextSnapshot(self.context_id, snapshot_data)
            self._snapshots.append(snapshot)
            return snapshot

    def restore_from_snapshot(self, snapshot_id: str) -> bool:
        """Restore context state from a snapshot."""
        with self._lock:
            for snapshot in self._snapshots:
                if snapshot.snapshot_id == snapshot_id:
                    snapshot_data = snapshot.snapshot_data
                    self.data = snapshot_data.get("data", {}).copy()
                    self.metadata = snapshot_data.get("metadata", {}).copy()
                    self.status = ContextStatus(snapshot_data.get("status", "active"))
                    self.tags = set(snapshot_data.get("tags", []))
                    self.updated_at = datetime.utcnow()
                    return True
            return False

    def list_snapshots(self) -> list[dict[str, Any]]:
        """List all snapshots for this context."""
        with self._lock:
            return [snapshot.to_dict() for snapshot in self._snapshots]

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary representation."""
        with self._lock:
            return {
                "context_id": self.context_id,
                "context_type": self.context_type.value,
                "data": self.data.copy(),
                "parent_context_id": self.parent_context_id,
                "metadata": self.metadata.copy(),
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat(),
                "status": self.status.value,
                "expiry_time": self.expiry_time.isoformat()
                if self.expiry_time
                else None,
                "tags": list(self.tags),
                "snapshots": [snapshot.to_dict() for snapshot in self._snapshots],
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaseContext":
        """Create context from dictionary representation."""
        context = cls(
            context_id=data["context_id"],
            context_type=ContextType(data["context_type"]),
            data=data.get("data", {}),
            parent_context_id=data.get("parent_context_id"),
            metadata=data.get("metadata", {}),
        )
        context.created_at = datetime.fromisoformat(data["created_at"])
        context.updated_at = datetime.fromisoformat(data["updated_at"])
        context.status = ContextStatus(data["status"])
        if data.get("expiry_time"):
            context.expiry_time = datetime.fromisoformat(data["expiry_time"])
        context.tags = set(data.get("tags", []))

        # Restore snapshots
        for snapshot_data in data.get("snapshots", []):
            snapshot = ContextSnapshot.from_dict(snapshot_data)
            context._snapshots.append(snapshot)

        return context


class TestSessionContext(BaseContext):
    """Context for managing test session state and metadata."""

    def __init__(
        self,
        context_id: str,
        session_name: str,
        test_plan: dict[str, Any],
        session_config: dict[str, Any] | None = None,
    ):
        super().__init__(context_id, ContextType.TEST_SESSION)
        self.session_name = session_name
        self.test_plan = test_plan
        self.session_config = session_config or {}
        self.test_results: list[dict[str, Any]] = []
        self.current_test_index = 0

        # Initialize session-specific data
        self.data.update(
            {
                "session_name": session_name,
                "test_plan": test_plan,
                "session_config": self.session_config,
                "test_results": self.test_results,
                "current_test_index": self.current_test_index,
                "session_metrics": {
                    "total_tests": len(test_plan.get("tests", [])),
                    "completed_tests": 0,
                    "failed_tests": 0,
                    "start_time": self.created_at.isoformat(),
                },
            }
        )

    def add_test_result(self, test_result: dict[str, Any]) -> None:
        """Add a test result to the session."""
        with self._lock:
            self.test_results.append(test_result)
            self.data["test_results"] = self.test_results

            # Update metrics
            metrics = self.data["session_metrics"]
            metrics["completed_tests"] = len(self.test_results)
            if test_result.get("status") == "failed":
                metrics["failed_tests"] += 1

            self.updated_at = datetime.utcnow()

    def get_session_summary(self) -> dict[str, Any]:
        """Get a summary of the test session."""
        with self._lock:
            metrics = self.data["session_metrics"]
            duration = (self.updated_at - self.created_at).total_seconds()

            return {
                "session_id": self.context_id,
                "session_name": self.session_name,
                "status": self.status.value,
                "duration_seconds": duration,
                "total_tests": metrics["total_tests"],
                "completed_tests": metrics["completed_tests"],
                "failed_tests": metrics["failed_tests"],
                "success_rate": (metrics["completed_tests"] - metrics["failed_tests"])
                / max(metrics["completed_tests"], 1),
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat(),
            }


class WorkflowContext(BaseContext):
    """Context for tracking multi-step testing workflows."""

    def __init__(
        self, context_id: str, workflow_name: str, workflow_steps: list[dict[str, Any]]
    ):
        super().__init__(context_id, ContextType.WORKFLOW)
        self.workflow_name = workflow_name
        self.workflow_steps = workflow_steps
        self.current_step_index = 0
        self.step_results: list[dict[str, Any]] = []

        # Initialize workflow-specific data
        self.data.update(
            {
                "workflow_name": workflow_name,
                "workflow_steps": workflow_steps,
                "current_step_index": self.current_step_index,
                "step_results": self.step_results,
                "workflow_state": "initialized",
                "can_pause": True,
                "can_resume": True,
            }
        )

    def advance_step(self, step_result: dict[str, Any] | None = None) -> bool:
        """Advance to the next workflow step."""
        with self._lock:
            if step_result:
                self.step_results.append(step_result)
                self.data["step_results"] = self.step_results

            if self.current_step_index < len(self.workflow_steps) - 1:
                self.current_step_index += 1
                self.data["current_step_index"] = self.current_step_index
                self.updated_at = datetime.utcnow()
                return True
            else:
                self.data["workflow_state"] = "completed"
                self.status = ContextStatus.COMPLETED
                return False

    def get_current_step(self) -> dict[str, Any] | None:
        """Get the current workflow step."""
        with self._lock:
            if self.current_step_index < len(self.workflow_steps):
                return self.workflow_steps[self.current_step_index]
            return None

    def pause_workflow(self) -> bool:
        """Pause the workflow execution."""
        with self._lock:
            if self.data.get("can_pause", True):
                self.status = ContextStatus.PAUSED
                self.data["workflow_state"] = "paused"
                self.updated_at = datetime.utcnow()
                return True
            return False

    def resume_workflow(self) -> bool:
        """Resume the workflow execution."""
        with self._lock:
            if self.status == ContextStatus.PAUSED and self.data.get(
                "can_resume", True
            ):
                self.status = ContextStatus.ACTIVE
                self.data["workflow_state"] = "running"
                self.updated_at = datetime.utcnow()
                return True
            return False


class ScenarioContext(BaseContext):
    """Context for managing active scenario configurations."""

    def __init__(
        self, context_id: str, scenario_name: str, scenario_config: dict[str, Any]
    ):
        super().__init__(context_id, ContextType.SCENARIO)
        self.scenario_name = scenario_name
        self.scenario_config = scenario_config
        self.deployment_info: dict[str, Any] | None = None

        # Initialize scenario-specific data
        self.data.update(
            {
                "scenario_name": scenario_name,
                "scenario_config": scenario_config,
                "deployment_info": self.deployment_info,
                "scenario_state": "configured",
                "active_endpoints": [],
                "scenario_metrics": {
                    "requests_processed": 0,
                    "errors_generated": 0,
                    "last_activity": None,
                },
            }
        )

    def deploy_scenario(self, deployment_info: dict[str, Any]) -> None:
        """Mark scenario as deployed with deployment information."""
        with self._lock:
            self.deployment_info = deployment_info
            self.data["deployment_info"] = deployment_info
            self.data["scenario_state"] = "deployed"
            self.updated_at = datetime.utcnow()

    def update_metrics(self, metric_updates: dict[str, Any]) -> None:
        """Update scenario metrics."""
        with self._lock:
            metrics = self.data["scenario_metrics"]
            metrics.update(metric_updates)
            metrics["last_activity"] = datetime.utcnow().isoformat()
            self.updated_at = datetime.utcnow()


class PerformanceContext(BaseContext):
    """Context for tracking performance metrics across test runs."""

    def __init__(self, context_id: str, test_run_id: str):
        super().__init__(context_id, ContextType.PERFORMANCE)
        self.test_run_id = test_run_id
        self.metrics_history: list[dict[str, Any]] = []

        # Initialize performance-specific data
        self.data.update(
            {
                "test_run_id": test_run_id,
                "metrics_history": self.metrics_history,
                "current_metrics": {},
                "performance_thresholds": {
                    "max_response_time_ms": 1000,
                    "min_throughput_rps": 100,
                    "max_error_rate_percent": 5.0,
                },
                "alerts": [],
            }
        )

    def add_metrics(self, metrics: dict[str, Any]) -> None:
        """Add performance metrics to the context."""
        with self._lock:
            timestamped_metrics = {
                **metrics,
                "timestamp": datetime.utcnow().isoformat(),
            }
            self.metrics_history.append(timestamped_metrics)
            self.data["metrics_history"] = self.metrics_history
            self.data["current_metrics"] = metrics

            # Check thresholds and generate alerts
            self._check_performance_thresholds(metrics)
            self.updated_at = datetime.utcnow()

    def _check_performance_thresholds(self, metrics: dict[str, Any]) -> None:
        """Check performance metrics against thresholds and generate alerts."""
        thresholds = self.data["performance_thresholds"]
        alerts = self.data["alerts"]

        # Check response time
        if metrics.get("avg_response_time_ms", 0) > thresholds["max_response_time_ms"]:
            alerts.append(
                {
                    "type": "response_time_exceeded",
                    "message": f"Average response time {metrics['avg_response_time_ms']}ms exceeds threshold {thresholds['max_response_time_ms']}ms",
                    "timestamp": datetime.utcnow().isoformat(),
                    "severity": "warning",
                }
            )

        # Check throughput
        if metrics.get("throughput_rps", 0) < thresholds["min_throughput_rps"]:
            alerts.append(
                {
                    "type": "throughput_below_threshold",
                    "message": f"Throughput {metrics['throughput_rps']} RPS below threshold {thresholds['min_throughput_rps']} RPS",
                    "timestamp": datetime.utcnow().isoformat(),
                    "severity": "warning",
                }
            )

        # Check error rate
        if metrics.get("error_rate_percent", 0) > thresholds["max_error_rate_percent"]:
            alerts.append(
                {
                    "type": "error_rate_exceeded",
                    "message": f"Error rate {metrics['error_rate_percent']}% exceeds threshold {thresholds['max_error_rate_percent']}%",
                    "timestamp": datetime.utcnow().isoformat(),
                    "severity": "critical",
                }
            )


class GlobalContext(BaseContext):
    """Context for data shared across sessions and AI-driven orchestration."""

    def __init__(self, context_id: str = "global_context"):
        super().__init__(context_id, ContextType.GLOBAL)

        # Initialize global-specific data
        self.data.update(
            {
                "shared_configurations": {},
                "cross_session_metrics": {
                    "total_sessions": 0,
                    "total_tests_executed": 0,
                    "global_success_rate": 0.0,
                    "most_common_failures": [],
                    "performance_trends": [],
                },
                "global_settings": {
                    "default_timeout_seconds": 300,
                    "max_concurrent_sessions": 10,
                    "enable_cross_session_learning": True,
                    "auto_optimize_scenarios": True,
                },
                "orchestration_state": {
                    "active_orchestrations": [],
                    "queued_orchestrations": [],
                    "orchestration_history": [],
                },
                "shared_test_data": {},
                "global_analytics": {
                    "api_usage_patterns": {},
                    "performance_baselines": {},
                    "security_findings": [],
                },
            }
        )

    def update_cross_session_metrics(self, session_metrics: dict[str, Any]) -> None:
        """Update global metrics with data from a completed session."""
        with self._lock:
            global_metrics = self.data["cross_session_metrics"]
            global_metrics["total_sessions"] += 1
            global_metrics["total_tests_executed"] += session_metrics.get(
                "total_tests", 0
            )

            # Update global success rate
            total_successful = global_metrics[
                "total_tests_executed"
            ] - session_metrics.get("failed_tests", 0)
            global_metrics["global_success_rate"] = total_successful / max(
                global_metrics["total_tests_executed"], 1
            )

            self.updated_at = datetime.utcnow()

    def add_orchestration(self, orchestration_config: dict[str, Any]) -> str:
        """Add a new orchestration to the queue."""
        with self._lock:
            orchestration_id = str(uuid.uuid4())
            orchestration = {
                "orchestration_id": orchestration_id,
                "config": orchestration_config,
                "status": "queued",
                "created_at": datetime.utcnow().isoformat(),
            }

            self.data["orchestration_state"]["queued_orchestrations"].append(
                orchestration
            )
            self.updated_at = datetime.utcnow()
            return orchestration_id

    def start_orchestration(self, orchestration_id: str) -> bool:
        """Move an orchestration from queued to active."""
        with self._lock:
            queued = self.data["orchestration_state"]["queued_orchestrations"]
            active = self.data["orchestration_state"]["active_orchestrations"]

            for i, orchestration in enumerate(queued):
                if orchestration["orchestration_id"] == orchestration_id:
                    orchestration["status"] = "active"
                    orchestration["started_at"] = datetime.utcnow().isoformat()
                    active.append(orchestration)
                    queued.pop(i)
                    self.updated_at = datetime.utcnow()
                    return True
            return False


class AgentContext(BaseContext):
    """Context for integrating agent-specific state when using LangGraph/CrewAI."""

    def __init__(
        self,
        context_id: str,
        agent_id: str,
        agent_type: str,
        agent_config: dict[str, Any] | None = None,
    ):
        super().__init__(context_id, ContextType.AGENT)
        self.agent_id = agent_id
        self.agent_type = agent_type  # "langgraph", "crewai", "custom"
        self.agent_config = agent_config or {}

        # Initialize agent-specific data
        self.data.update(
            {
                "agent_id": agent_id,
                "agent_type": agent_type,
                "agent_config": self.agent_config,
                "agent_state": {},
                "memory": {"short_term": {}, "long_term": {}, "learned_patterns": []},
                "workflow_state": {
                    "current_workflow": None,
                    "workflow_history": [],
                    "pending_actions": [],
                },
                "collaboration": {
                    "connected_agents": [],
                    "shared_context_ids": [],
                    "communication_log": [],
                },
                "performance_tracking": {
                    "tasks_completed": 0,
                    "success_rate": 0.0,
                    "average_task_duration": 0.0,
                    "optimization_suggestions": [],
                },
            }
        )

    def update_agent_state(self, state_updates: dict[str, Any]) -> None:
        """Update agent-specific state."""
        with self._lock:
            self.data["agent_state"].update(state_updates)
            self.updated_at = datetime.utcnow()

    def add_memory(self, memory_type: str, key: str, value: Any) -> None:
        """Add information to agent memory."""
        with self._lock:
            if memory_type in self.data["memory"]:
                self.data["memory"][memory_type][key] = value
                self.updated_at = datetime.utcnow()

    def get_memory(self, memory_type: str, key: str | None = None) -> Any:
        """Retrieve information from agent memory."""
        with self._lock:
            memory = self.data["memory"].get(memory_type, {})
            if key is None:
                return memory.copy()
            return memory.get(key)

    def add_learned_pattern(self, pattern: dict[str, Any]) -> None:
        """Add a learned pattern to agent memory."""
        with self._lock:
            self.data["memory"]["learned_patterns"].append(
                {**pattern, "learned_at": datetime.utcnow().isoformat()}
            )
            self.updated_at = datetime.utcnow()

    def connect_agent(self, other_agent_id: str, shared_context_id: str) -> None:
        """Connect this agent to another agent for collaboration."""
        with self._lock:
            collaboration = self.data["collaboration"]
            if other_agent_id not in collaboration["connected_agents"]:
                collaboration["connected_agents"].append(other_agent_id)
            if shared_context_id not in collaboration["shared_context_ids"]:
                collaboration["shared_context_ids"].append(shared_context_id)
            self.updated_at = datetime.utcnow()

    def log_communication(self, message: dict[str, Any]) -> None:
        """Log communication with other agents."""
        with self._lock:
            self.data["collaboration"]["communication_log"].append(
                {**message, "timestamp": datetime.utcnow().isoformat()}
            )
            self.updated_at = datetime.utcnow()

    def update_performance_metrics(self, task_result: dict[str, Any]) -> None:
        """Update agent performance tracking."""
        with self._lock:
            performance = self.data["performance_tracking"]
            performance["tasks_completed"] += 1

            if task_result.get("success", False):
                # Update success rate
                total_tasks = performance["tasks_completed"]
                current_successes = performance["success_rate"] * (total_tasks - 1)
                performance["success_rate"] = (current_successes + 1) / total_tasks

            # Update average task duration
            if "duration_seconds" in task_result:
                total_tasks = performance["tasks_completed"]
                current_avg = performance["average_task_duration"]
                new_duration = task_result["duration_seconds"]
                performance["average_task_duration"] = (
                    current_avg * (total_tasks - 1) + new_duration
                ) / total_tasks

            self.updated_at = datetime.utcnow()


class ContextStorage:
    """Handles context persistence and storage using SQLite database."""

    def __init__(self, db_path: str = "mcp_context.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the SQLite database with required tables."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # Create contexts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS contexts (
                        context_id TEXT PRIMARY KEY,
                        context_type TEXT NOT NULL,
                        parent_context_id TEXT,
                        data TEXT NOT NULL,
                        metadata TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        status TEXT NOT NULL,
                        expiry_time TEXT,
                        tags TEXT,
                        FOREIGN KEY (parent_context_id) REFERENCES contexts (context_id)
                    )
                """)

                # Create snapshots table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS context_snapshots (
                        snapshot_id TEXT PRIMARY KEY,
                        context_id TEXT NOT NULL,
                        snapshot_data TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (context_id) REFERENCES contexts (context_id)
                    )
                """)

                # Create indexes for better performance
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_context_type ON contexts (context_type)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_context_status ON contexts (status)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_context_parent ON contexts (parent_context_id)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_snapshot_context ON context_snapshots (context_id)"
                )

                conn.commit()
            finally:
                conn.close()

    def save_context(self, context: BaseContext) -> None:
        """Save context to database."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO contexts
                    (context_id, context_type, parent_context_id, data, metadata,
                     created_at, updated_at, status, expiry_time, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        context.context_id,
                        context.context_type.value,
                        context.parent_context_id,
                        json.dumps(context.data),
                        json.dumps(context.metadata),
                        context.created_at.isoformat(),
                        context.updated_at.isoformat(),
                        context.status.value,
                        context.expiry_time.isoformat()
                        if context.expiry_time
                        else None,
                        json.dumps(list(context.tags)),
                    ),
                )

                # Save snapshots
                for snapshot in context._snapshots:
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO context_snapshots
                        (snapshot_id, context_id, snapshot_data, timestamp)
                        VALUES (?, ?, ?, ?)
                    """,
                        (
                            snapshot.snapshot_id,
                            snapshot.context_id,
                            json.dumps(snapshot.snapshot_data),
                            snapshot.timestamp.isoformat(),
                        ),
                    )

                conn.commit()
            finally:
                conn.close()

    def load_context(self, context_id: str) -> BaseContext | None:
        """Load context from database."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT context_id, context_type, parent_context_id, data, metadata,
                           created_at, updated_at, status, expiry_time, tags
                    FROM contexts WHERE context_id = ?
                """,
                    (context_id,),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                # Load snapshots
                cursor.execute(
                    """
                    SELECT snapshot_id, snapshot_data, timestamp
                    FROM context_snapshots WHERE context_id = ?
                    ORDER BY timestamp
                """,
                    (context_id,),
                )

                snapshots = []
                for snapshot_row in cursor.fetchall():
                    snapshot_data = {
                        "snapshot_id": snapshot_row[0],
                        "context_id": context_id,
                        "snapshot_data": json.loads(snapshot_row[1]),
                        "timestamp": snapshot_row[2],
                    }
                    snapshots.append(ContextSnapshot.from_dict(snapshot_data))

                # Create context object based on type
                context_data = {
                    "context_id": row[0],
                    "context_type": row[1],
                    "parent_context_id": row[2],
                    "data": json.loads(row[3]),
                    "metadata": json.loads(row[4]) if row[4] else {},
                    "created_at": row[5],
                    "updated_at": row[6],
                    "status": row[7],
                    "expiry_time": row[8],
                    "tags": json.loads(row[9]) if row[9] else [],
                    "snapshots": [snapshot.to_dict() for snapshot in snapshots],
                }

                # Create appropriate context type
                context_type = ContextType(row[1])
                if context_type == ContextType.TEST_SESSION:
                    context = TestSessionContext(
                        context_id=row[0],
                        session_name=context_data["data"].get("session_name", ""),
                        test_plan=context_data["data"].get("test_plan", {}),
                        session_config=context_data["data"].get("session_config", {}),
                    )
                elif context_type == ContextType.WORKFLOW:
                    context = WorkflowContext(
                        context_id=row[0],
                        workflow_name=context_data["data"].get("workflow_name", ""),
                        workflow_steps=context_data["data"].get("workflow_steps", []),
                    )
                elif context_type == ContextType.SCENARIO:
                    context = ScenarioContext(
                        context_id=row[0],
                        scenario_name=context_data["data"].get("scenario_name", ""),
                        scenario_config=context_data["data"].get("scenario_config", {}),
                    )
                elif context_type == ContextType.PERFORMANCE:
                    context = PerformanceContext(
                        context_id=row[0],
                        test_run_id=context_data["data"].get("test_run_id", ""),
                    )
                elif context_type == ContextType.GLOBAL:
                    context = GlobalContext(context_id=row[0])
                elif context_type == ContextType.AGENT:
                    context = AgentContext(
                        context_id=row[0],
                        agent_id=context_data["data"].get("agent_id", ""),
                        agent_type=context_data["data"].get("agent_type", ""),
                        agent_config=context_data["data"].get("agent_config", {}),
                    )
                else:
                    context = BaseContext.from_dict(context_data)

                # Restore state from loaded data
                context.data = context_data["data"]
                context.metadata = context_data["metadata"]
                context.parent_context_id = context_data["parent_context_id"]
                context.created_at = datetime.fromisoformat(context_data["created_at"])
                context.updated_at = datetime.fromisoformat(context_data["updated_at"])
                context.status = ContextStatus(context_data["status"])
                if context_data["expiry_time"]:
                    context.expiry_time = datetime.fromisoformat(
                        context_data["expiry_time"]
                    )
                context.tags = set(context_data["tags"])
                context._snapshots = snapshots

                return context

            finally:
                conn.close()

    def list_contexts(
        self,
        context_type: ContextType | None = None,
        status: ContextStatus | None = None,
        parent_context_id: str | None = None,
        tags: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List contexts with optional filtering."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                query = """
                    SELECT context_id, context_type, parent_context_id, data, metadata,
                           created_at, updated_at, status, expiry_time, tags
                    FROM contexts WHERE 1=1
                """
                params = []

                if context_type:
                    query += " AND context_type = ?"
                    params.append(context_type.value)

                if status:
                    query += " AND status = ?"
                    params.append(status.value)

                if parent_context_id:
                    query += " AND parent_context_id = ?"
                    params.append(parent_context_id)

                query += " ORDER BY created_at DESC"

                cursor.execute(query, params)
                contexts = []

                for row in cursor.fetchall():
                    context_tags = set(json.loads(row[9]) if row[9] else [])

                    # Filter by tags if specified
                    if tags and not any(tag in context_tags for tag in tags):
                        continue

                    contexts.append(
                        {
                            "context_id": row[0],
                            "context_type": row[1],
                            "parent_context_id": row[2],
                            "data": json.loads(row[3]),
                            "metadata": json.loads(row[4]) if row[4] else {},
                            "created_at": row[5],
                            "updated_at": row[6],
                            "status": row[7],
                            "expiry_time": row[8],
                            "tags": list(context_tags),
                        }
                    )

                return contexts

            finally:
                conn.close()

    def delete_context(self, context_id: str) -> bool:
        """Delete context and its snapshots from database."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # Delete snapshots first (foreign key constraint)
                cursor.execute(
                    "DELETE FROM context_snapshots WHERE context_id = ?", (context_id,)
                )

                # Delete context
                cursor.execute(
                    "DELETE FROM contexts WHERE context_id = ?", (context_id,)
                )

                deleted = cursor.rowcount > 0
                conn.commit()
                return deleted

            finally:
                conn.close()

    def cleanup_expired_contexts(self) -> int:
        """Remove expired contexts from database."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                current_time = datetime.utcnow().isoformat()

                # Find expired contexts
                cursor.execute(
                    """
                    SELECT context_id FROM contexts
                    WHERE expiry_time IS NOT NULL AND expiry_time < ?
                """,
                    (current_time,),
                )

                expired_ids = [row[0] for row in cursor.fetchall()]

                # Delete expired contexts and their snapshots
                for context_id in expired_ids:
                    cursor.execute(
                        "DELETE FROM context_snapshots WHERE context_id = ?",
                        (context_id,),
                    )
                    cursor.execute(
                        "DELETE FROM contexts WHERE context_id = ?", (context_id,)
                    )

                conn.commit()
                return len(expired_ids)

            finally:
                conn.close()


class ContextManager:
    """Main context manager for coordinating all context operations."""

    def __init__(
        self, db_path: str = "mcp_context.db", audit_logger: Any | None = None
    ):
        self.storage = ContextStorage(db_path)
        self.audit_logger = audit_logger
        self._contexts: dict[str, BaseContext] = {}
        self._lock = threading.RLock()
        self._global_context: GlobalContext | None = None

        # Initialize global context
        self._init_global_context()

        # Start cleanup task
        self._cleanup_task = None
        self._start_cleanup_task()

    def _init_global_context(self) -> None:
        """Initialize or load the global context."""
        try:
            global_context = self.storage.load_context("global_context")
            if global_context and isinstance(global_context, GlobalContext):
                self._global_context = global_context
                self._contexts["global_context"] = global_context
            else:
                # Create new global context
                self._global_context = GlobalContext()
                self.storage.save_context(self._global_context)
                self._contexts["global_context"] = self._global_context
        except Exception:
            logger.exception("Failed to initialize global context")
            # Create new global context as fallback
            self._global_context = GlobalContext()
            self._contexts["global_context"] = self._global_context

    def _start_cleanup_task(self) -> None:
        """Start background task for cleaning up expired contexts."""

        def cleanup_worker():
            while True:
                try:
                    time.sleep(300)  # Run every 5 minutes
                    self.cleanup_expired_contexts()
                except Exception:
                    logger.exception("Error in cleanup task")

        self._cleanup_task = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_task.start()

    def create_context(
        self,
        context_type: ContextType,
        context_id: str | None = None,
        parent_context_id: str | None = None,
        **kwargs,
    ) -> BaseContext:
        """Create a new context of the specified type."""
        with self._lock:
            if context_id is None:
                context_id = str(uuid.uuid4())

            # Create context based on type
            if context_type == ContextType.TEST_SESSION:
                context = TestSessionContext(
                    context_id=context_id,
                    session_name=kwargs.get(
                        "session_name", f"session_{context_id[:8]}"
                    ),
                    test_plan=kwargs.get("test_plan", {}),
                    session_config=kwargs.get("session_config", {}),
                )
            elif context_type == ContextType.WORKFLOW:
                context = WorkflowContext(
                    context_id=context_id,
                    workflow_name=kwargs.get(
                        "workflow_name", f"workflow_{context_id[:8]}"
                    ),
                    workflow_steps=kwargs.get("workflow_steps", []),
                )
            elif context_type == ContextType.SCENARIO:
                context = ScenarioContext(
                    context_id=context_id,
                    scenario_name=kwargs.get(
                        "scenario_name", f"scenario_{context_id[:8]}"
                    ),
                    scenario_config=kwargs.get("scenario_config", {}),
                )
            elif context_type == ContextType.PERFORMANCE:
                context = PerformanceContext(
                    context_id=context_id,
                    test_run_id=kwargs.get("test_run_id", f"run_{context_id[:8]}"),
                )
            elif context_type == ContextType.AGENT:
                context = AgentContext(
                    context_id=context_id,
                    agent_id=kwargs.get("agent_id", f"agent_{context_id[:8]}"),
                    agent_type=kwargs.get("agent_type", "custom"),
                    agent_config=kwargs.get("agent_config", {}),
                )
            else:
                context = BaseContext(
                    context_id=context_id,
                    context_type=context_type,
                    data=kwargs.get("data", {}),
                    parent_context_id=parent_context_id,
                    metadata=kwargs.get("metadata", {}),
                )

            # Set parent context if specified
            if parent_context_id:
                context.parent_context_id = parent_context_id

            # Store context
            self._contexts[context_id] = context
            self.storage.save_context(context)

            # Log context creation
            if self.audit_logger:
                self.audit_logger.log_context_operation(
                    operation="create",
                    context_id=context_id,
                    context_type=context_type.value,
                    details={"parent_context_id": parent_context_id},
                )

            return context

    def get_context(self, context_id: str) -> BaseContext | None:
        """Get context by ID, loading from storage if necessary."""
        with self._lock:
            # Check in-memory cache first
            if context_id in self._contexts:
                return self._contexts[context_id]

            # Load from storage
            context = self.storage.load_context(context_id)
            if context:
                self._contexts[context_id] = context
                return context

            return None

    def update_context(
        self, context_id: str, updates: dict[str, Any], merge: bool = True
    ) -> bool:
        """Update context data."""
        with self._lock:
            context = self.get_context(context_id)
            if not context:
                return False

            context.update_data(updates, merge)
            self.storage.save_context(context)

            # Log context update
            if self.audit_logger:
                self.audit_logger.log_context_operation(
                    operation="update",
                    context_id=context_id,
                    context_type=context.context_type.value,
                    details={"updates": updates, "merge": merge},
                )

            return True

    def delete_context(self, context_id: str) -> bool:
        """Delete context."""
        with self._lock:
            # Remove from memory
            if context_id in self._contexts:
                context = self._contexts.pop(context_id)
                context_type = context.context_type.value
            else:
                context_type = "unknown"

            # Remove from storage
            deleted = self.storage.delete_context(context_id)

            # Log context deletion
            if deleted and self.audit_logger:
                self.audit_logger.log_context_operation(
                    operation="delete", context_id=context_id, context_type=context_type
                )

            return deleted

    def list_contexts(
        self,
        context_type: ContextType | None = None,
        status: ContextStatus | None = None,
        parent_context_id: str | None = None,
        tags: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List contexts with optional filtering."""
        return self.storage.list_contexts(context_type, status, parent_context_id, tags)

    def create_snapshot(
        self, context_id: str, description: str | None = None
    ) -> str | None:
        """Create a snapshot of context state."""
        with self._lock:
            context = self.get_context(context_id)
            if not context:
                return None

            snapshot = context.create_snapshot(description)
            self.storage.save_context(context)

            # Log snapshot creation
            if self.audit_logger:
                self.audit_logger.log_context_operation(
                    operation="snapshot",
                    context_id=context_id,
                    context_type=context.context_type.value,
                    details={
                        "snapshot_id": snapshot.snapshot_id,
                        "description": description,
                    },
                )

            return snapshot.snapshot_id

    def restore_snapshot(self, context_id: str, snapshot_id: str) -> bool:
        """Restore context from snapshot."""
        with self._lock:
            context = self.get_context(context_id)
            if not context:
                return False

            restored = context.restore_from_snapshot(snapshot_id)
            if restored:
                self.storage.save_context(context)

                # Log snapshot restoration
                if self.audit_logger:
                    self.audit_logger.log_context_operation(
                        operation="restore",
                        context_id=context_id,
                        context_type=context.context_type.value,
                        details={"snapshot_id": snapshot_id},
                    )

            return restored

    def get_global_context(self) -> GlobalContext:
        """Get the global context instance."""
        return self._global_context

    def cleanup_expired_contexts(self) -> int:
        """Clean up expired contexts."""
        with self._lock:
            # Remove expired contexts from memory
            expired_ids = []
            for context_id, context in list(self._contexts.items()):
                if context.is_expired():
                    expired_ids.append(context_id)
                    del self._contexts[context_id]

            # Clean up from storage
            storage_cleaned = self.storage.cleanup_expired_contexts()

            # Log cleanup
            if (expired_ids or storage_cleaned) and self.audit_logger:
                self.audit_logger.log_context_operation(
                    operation="cleanup",
                    context_id="system",
                    context_type="cleanup",
                    details={
                        "memory_cleaned": len(expired_ids),
                        "storage_cleaned": storage_cleaned,
                    },
                )

            return len(expired_ids) + storage_cleaned

    @asynccontextmanager
    async def context_session(self, context_type: ContextType, **kwargs):
        """Async context manager for automatic context lifecycle management."""
        context = self.create_context(context_type, **kwargs)
        try:
            yield context
        finally:
            # Auto-save context on exit
            self.storage.save_context(context)

    def get_context_hierarchy(self, context_id: str) -> list[dict[str, Any]]:
        """Get the full hierarchy of a context (parent chain)."""
        hierarchy = []
        current_id = context_id

        while current_id:
            context = self.get_context(current_id)
            if not context:
                break

            hierarchy.append(
                {
                    "context_id": context.context_id,
                    "context_type": context.context_type.value,
                    "status": context.status.value,
                    "created_at": context.created_at.isoformat(),
                    "updated_at": context.updated_at.isoformat(),
                }
            )

            current_id = context.parent_context_id

        return hierarchy

    def get_child_contexts(self, parent_context_id: str) -> list[dict[str, Any]]:
        """Get all child contexts of a parent context."""
        return self.list_contexts(parent_context_id=parent_context_id)

    def shutdown(self) -> None:
        """Shutdown the context manager and save all contexts."""
        with self._lock:
            # Save all in-memory contexts
            for context in self._contexts.values():
                try:
                    self.storage.save_context(context)
                except Exception:
                    logger.exception(f"Failed to save context {context.context_id}")

            # Clear memory
            self._contexts.clear()

            # Log shutdown
            if self.audit_logger:
                self.audit_logger.log_context_operation(
                    operation="shutdown", context_id="system", context_type="system"
                )


# Global context manager instance
_global_context_manager: ContextManager | None = None


def get_context_manager(
    db_path: str = "mcp_context.db", audit_logger: Any | None = None
) -> ContextManager:
    """Get or create the global context manager instance."""
    global _global_context_manager  # noqa: PLW0603
    if _global_context_manager is None:
        _global_context_manager = ContextManager(db_path, audit_logger)
    return _global_context_manager


def initialize_context_manager(
    db_path: str = "mcp_context.db", audit_logger: Any | None = None
) -> ContextManager:
    """Initialize the global context manager with specific configuration."""
    global _global_context_manager  # noqa: PLW0603
    _global_context_manager = ContextManager(db_path, audit_logger)
    return _global_context_manager


# Context management functions for MCP tools
async def create_test_session_context(
    session_name: str,
    test_plan: dict[str, Any],
    session_config: dict[str, Any] | None = None,
) -> str:
    """Create a new test session context."""
    manager = get_context_manager()
    context = manager.create_context(
        ContextType.TEST_SESSION,
        session_name=session_name,
        test_plan=test_plan,
        session_config=session_config,
    )
    return context.context_id


async def create_workflow_context(
    workflow_name: str,
    workflow_steps: list[dict[str, Any]],
    parent_context_id: str | None = None,
) -> str:
    """Create a new workflow context."""
    manager = get_context_manager()
    context = manager.create_context(
        ContextType.WORKFLOW,
        workflow_name=workflow_name,
        workflow_steps=workflow_steps,
        parent_context_id=parent_context_id,
    )
    return context.context_id


async def create_agent_context(
    agent_id: str, agent_type: str, agent_config: dict[str, Any] | None = None
) -> str:
    """Create a new agent context."""
    manager = get_context_manager()
    context = manager.create_context(
        ContextType.AGENT,
        agent_id=agent_id,
        agent_type=agent_type,
        agent_config=agent_config,
    )
    return context.context_id


async def get_context_data(context_id: str, key: str | None = None) -> Any | None:
    """Get data from a context."""
    manager = get_context_manager()
    context = manager.get_context(context_id)
    if context:
        return context.get_data(key)
    return None


async def update_context_data(
    context_id: str, updates: dict[str, Any], merge: bool = True
) -> bool:
    """Update context data."""
    manager = get_context_manager()
    return manager.update_context(context_id, updates, merge)


async def create_context_snapshot(
    context_id: str, description: str | None = None
) -> str | None:
    """Create a snapshot of context state."""
    manager = get_context_manager()
    return manager.create_snapshot(context_id, description)


async def restore_context_snapshot(context_id: str, snapshot_id: str) -> bool:
    """Restore context from snapshot."""
    manager = get_context_manager()
    return manager.restore_snapshot(context_id, snapshot_id)


async def list_contexts_by_type(
    context_type: ContextType, status: ContextStatus | None = None
) -> list[dict[str, Any]]:
    """List contexts by type and optional status."""
    manager = get_context_manager()
    return manager.list_contexts(context_type=context_type, status=status)


async def get_global_context_data(key: str | None = None) -> Any:
    """Get data from the global context."""
    manager = get_context_manager()
    global_context = manager.get_global_context()
    return global_context.get_data(key)


async def update_global_context_data(
    updates: dict[str, Any], merge: bool = True
) -> bool:
    """Update global context data."""
    manager = get_context_manager()
    global_context = manager.get_global_context()
    global_context.update_data(updates, merge)
    manager.storage.save_context(global_context)
    return True
