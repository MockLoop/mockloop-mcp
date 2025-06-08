"""
MCP Compliance Reporter for regulatory compliance and data governance.

This module provides comprehensive compliance reporting capabilities including:
- Generate compliance reports showing all MCP data usage
- Track data sources and transformations for model training transparency
- Export audit logs in standard compliance formats (JSON, CSV)
- Data retention and purging capabilities per regulatory requirements
- GDPR, CCPA, and other data privacy regulation support
"""

import csv
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import zipfile
import hashlib


class ComplianceRegulation(Enum):
    """Supported compliance regulations."""

    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    SOX = "sox"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"


class ReportFormat(Enum):
    """Supported report formats."""

    JSON = "json"
    CSV = "csv"
    XML = "xml"
    PDF = "pdf"


@dataclass
class ComplianceReport:
    """Structured compliance report."""

    report_id: str
    report_type: str
    regulation: str
    generated_at: str
    period_start: str
    period_end: str
    total_operations: int
    data_subjects_count: int
    data_sources: list[str]
    processing_purposes: list[str]
    legal_bases: list[str]
    retention_policies: list[str]
    compliance_violations: list[dict[str, Any]]
    recommendations: list[str]
    metadata: dict[str, Any]


class MCPComplianceReporter:
    """
    Comprehensive compliance reporter for MCP audit logs.

    Features:
    - Generate compliance reports for various regulations
    - Export audit data in multiple formats
    - Data lineage tracking and visualization
    - Automated compliance checking
    - Data retention policy enforcement
    - Privacy impact assessments
    """

    def __init__(
        self,
        audit_db_path: str,
        reports_output_dir: str = "compliance_reports",
        default_regulation: ComplianceRegulation = ComplianceRegulation.GDPR,
    ):
        """
        Initialize the compliance reporter.

        Args:
            audit_db_path: Path to the MCP audit database
            reports_output_dir: Directory to store generated reports
            default_regulation: Default compliance regulation to apply
        """
        self.audit_db_path = Path(audit_db_path)
        self.reports_output_dir = Path(reports_output_dir)
        self.default_regulation = default_regulation

        # Create reports directory if it doesn't exist
        self.reports_output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize compliance rules
        self._init_compliance_rules()

    def _init_compliance_rules(self) -> None:
        """Initialize compliance rules for different regulations."""
        self.compliance_rules = {
            ComplianceRegulation.GDPR: {
                "max_retention_days": 2555,  # 7 years
                "required_legal_bases": [
                    "consent",
                    "contract",
                    "legal_obligation",
                    "vital_interests",
                    "public_task",
                    "legitimate_interests",
                ],
                "data_subject_rights": [
                    "access",
                    "rectification",
                    "erasure",
                    "portability",
                    "restriction",
                    "objection",
                    "automated_decision_making",
                ],
                "breach_notification_hours": 72,
                "privacy_by_design": True,
            },
            ComplianceRegulation.CCPA: {
                "max_retention_days": 1825,  # 5 years
                "consumer_rights": ["know", "delete", "opt_out", "non_discrimination"],
                "sale_disclosure_required": True,
                "privacy_policy_required": True,
            },
            ComplianceRegulation.HIPAA: {
                "max_retention_days": 2190,  # 6 years
                "minimum_necessary_standard": True,
                "encryption_required": True,
                "audit_controls_required": True,
                "access_controls_required": True,
            },
        }

    def generate_compliance_report(
        self,
        regulation: ComplianceRegulation | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        include_violations: bool = True,
        include_recommendations: bool = True,
    ) -> ComplianceReport:
        """
        Generate a comprehensive compliance report.

        Args:
            regulation: Compliance regulation to report against
            start_date: Start date for the report period (ISO format)
            end_date: End date for the report period (ISO format)
            include_violations: Whether to include compliance violations
            include_recommendations: Whether to include recommendations

        Returns:
            Generated compliance report
        """
        regulation = regulation or self.default_regulation

        # Set default date range if not provided
        if not end_date:
            end_date = datetime.now(timezone.utc).isoformat()  # noqa: UP017
        if not start_date:
            start_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()  # noqa: UP017

        # Query audit logs for the period
        audit_logs = self._query_audit_logs(start_date, end_date)

        # Analyze compliance
        compliance_analysis = self._analyze_compliance(audit_logs, regulation)

        # Generate report
        report = ComplianceReport(
            report_id=self._generate_report_id(),
            report_type=f"{regulation.value}_compliance",
            regulation=regulation.value,
            generated_at=datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            period_start=start_date,
            period_end=end_date,
            total_operations=len(audit_logs),
            data_subjects_count=compliance_analysis["data_subjects_count"],
            data_sources=compliance_analysis["data_sources"],
            processing_purposes=compliance_analysis["processing_purposes"],
            legal_bases=compliance_analysis["legal_bases"],
            retention_policies=compliance_analysis["retention_policies"],
            compliance_violations=compliance_analysis["violations"]
            if include_violations
            else [],
            recommendations=compliance_analysis["recommendations"]
            if include_recommendations
            else [],
            metadata=compliance_analysis["metadata"],
        )

        return report

    def export_audit_logs(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        filter_criteria: dict[str, Any] | None = None,
        include_sensitive_data: bool = False,
        export_format: ReportFormat = ReportFormat.JSON,
    ) -> str:
        """
        Export audit logs in specified format.

        Args:
            start_date: Start date filter (ISO format)
            end_date: End date filter (ISO format)
            filter_criteria: Additional filtering criteria
            include_sensitive_data: Whether to include sensitive data
            export_format: Export format (JSON, CSV, XML)

        Returns:
            Path to the exported file
        """
        # Query audit logs
        audit_logs = self._query_audit_logs(start_date, end_date, filter_criteria)

        # Sanitize data if needed
        if not include_sensitive_data:
            audit_logs = self._sanitize_audit_logs(audit_logs)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mcp_audit_export_{timestamp}.{export_format.value}"
        filepath = self.reports_output_dir / filename

        # Export based on format
        if export_format == ReportFormat.JSON:
            self._export_json(audit_logs, filepath)
        elif export_format == ReportFormat.CSV:
            self._export_csv(audit_logs, filepath)
        elif export_format == ReportFormat.XML:
            self._export_xml(audit_logs, filepath)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")

        return str(filepath)

    def generate_data_lineage_report(
        self,
        data_source: str | None = None,
        operation_type: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate data lineage report for model training transparency.

        Args:
            data_source: Specific data source to trace
            operation_type: Filter by operation type
            start_date: Start date filter (ISO format)
            end_date: End date filter (ISO format)

        Returns:
            Data lineage report with source tracking
        """
        with sqlite3.connect(str(self.audit_db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Build query for data lineage
            query = """
                SELECT
                    mal.entry_id,
                    mal.timestamp,
                    mal.operation_type,
                    mal.operation_name,
                    mal.data_sources,
                    mdl.source_type,
                    mdl.source_identifier,
                    mdl.source_metadata,
                    mdl.transformation_applied
                FROM mcp_audit_logs mal
                LEFT JOIN mcp_data_lineage mdl ON mal.entry_id = mdl.entry_id
                WHERE 1=1
            """
            params = []

            if data_source:
                query += " AND mdl.source_identifier LIKE ?"
                params.append(f"%{data_source}%")

            if operation_type:
                query += " AND mal.operation_type = ?"
                params.append(operation_type)

            if start_date:
                query += " AND mal.timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND mal.timestamp <= ?"
                params.append(end_date)

            query += " ORDER BY mal.timestamp DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            # Process lineage data
            lineage_map = {}
            source_stats = {}

            for row in rows:
                entry_id = row["entry_id"]
                source_id = row["source_identifier"]

                if entry_id not in lineage_map:
                    lineage_map[entry_id] = {
                        "timestamp": row["timestamp"],
                        "operation_type": row["operation_type"],
                        "operation_name": row["operation_name"],
                        "sources": [],
                    }

                if source_id:
                    source_info = {
                        "source_type": row["source_type"],
                        "source_identifier": source_id,
                        "metadata": json.loads(row["source_metadata"])
                        if row["source_metadata"]
                        else {},
                        "transformation": row["transformation_applied"],
                    }
                    lineage_map[entry_id]["sources"].append(source_info)

                    # Update source statistics
                    if source_id not in source_stats:
                        source_stats[source_id] = {
                            "usage_count": 0,
                            "first_used": row["timestamp"],
                            "last_used": row["timestamp"],
                            "operations": set(),
                        }

                    source_stats[source_id]["usage_count"] += 1
                    source_stats[source_id]["last_used"] = max(
                        source_stats[source_id]["last_used"], row["timestamp"]
                    )
                    source_stats[source_id]["operations"].add(row["operation_type"])

            # Convert sets to lists for JSON serialization
            for stats in source_stats.values():
                stats["operations"] = list(stats["operations"])

            return {
                "lineage_entries": list(lineage_map.values()),
                "source_statistics": source_stats,
                "total_entries": len(lineage_map),
                "unique_sources": len(source_stats),
                "generated_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            }

    def check_retention_compliance(self) -> dict[str, Any]:
        """
        Check compliance with data retention policies.

        Returns:
            Retention compliance report
        """
        current_time = datetime.now(timezone.utc)  # noqa: UP017

        with sqlite3.connect(str(self.audit_db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check for expired logs
            cursor.execute(
                """
                SELECT
                    COUNT(*) as expired_count,
                    MIN(expires_at) as oldest_expired,
                    MAX(expires_at) as newest_expired
                FROM mcp_audit_logs
                WHERE expires_at < ?
            """,
                (current_time.isoformat(),),
            )

            expired_result = cursor.fetchone()

            # Check retention policy distribution
            cursor.execute("""
                SELECT
                    retention_policy,
                    COUNT(*) as count,
                    MIN(timestamp) as oldest_entry,
                    MAX(timestamp) as newest_entry
                FROM mcp_audit_logs
                GROUP BY retention_policy
            """)

            retention_distribution = [dict(row) for row in cursor.fetchall()]

            # Check for logs without retention policy
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM mcp_audit_logs
                WHERE retention_policy IS NULL OR retention_policy = ''
            """)

            missing_policy_count = cursor.fetchone()["count"]

            return {
                "expired_logs": {
                    "count": expired_result["expired_count"],
                    "oldest_expired": expired_result["oldest_expired"],
                    "newest_expired": expired_result["newest_expired"],
                },
                "retention_distribution": retention_distribution,
                "missing_retention_policy": missing_policy_count,
                "compliance_status": "compliant"
                if expired_result["expired_count"] == 0
                else "non_compliant",
                "checked_at": current_time.isoformat(),
            }

    def purge_expired_data(self, dry_run: bool = True) -> dict[str, Any]:
        """
        Purge expired audit data according to retention policies.

        Args:
            dry_run: If True, only report what would be deleted

        Returns:
            Purge operation results
        """
        current_time = datetime.now(timezone.utc)  # noqa: UP017

        with sqlite3.connect(str(self.audit_db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Find expired logs
            cursor.execute(
                """
                SELECT entry_id, timestamp, operation_type, expires_at
                FROM mcp_audit_logs
                WHERE expires_at < ?
                ORDER BY expires_at
            """,
                (current_time.isoformat(),),
            )

            expired_logs = [dict(row) for row in cursor.fetchall()]

            if not dry_run and expired_logs:
                # Delete expired logs and related data
                expired_ids = [log["entry_id"] for log in expired_logs]

                if expired_ids:
                    # Create placeholders for safe SQL execution
                    placeholders = ",".join(["?" for _ in expired_ids])

                    # Delete from data lineage table
                    sql_data_lineage = f"DELETE FROM mcp_data_lineage WHERE entry_id IN ({placeholders})"  # noqa: S608
                    cursor.execute(sql_data_lineage, expired_ids)

                    # Delete from compliance events table
                    sql_compliance_events = f"DELETE FROM mcp_compliance_events WHERE entry_id IN ({placeholders})"  # noqa: S608
                    cursor.execute(sql_compliance_events, expired_ids)

                    # Delete from audit logs table
                    sql_audit_logs = (
                        f"DELETE FROM mcp_audit_logs WHERE entry_id IN ({placeholders})"  # noqa: S608
                    )
                    cursor.execute(sql_audit_logs, expired_ids)

                conn.commit()

            return {
                "operation": "purge_expired_data",
                "dry_run": dry_run,
                "expired_logs_found": len(expired_logs),
                "logs_deleted": len(expired_logs) if not dry_run else 0,
                "oldest_expired": expired_logs[0]["timestamp"]
                if expired_logs
                else None,
                "newest_expired": expired_logs[-1]["timestamp"]
                if expired_logs
                else None,
                "executed_at": current_time.isoformat(),
            }

    def generate_privacy_impact_assessment(
        self,
        processing_purpose: str,
        data_types: list[str],
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate Privacy Impact Assessment (PIA) report.

        Args:
            processing_purpose: Purpose of data processing
            data_types: Types of data being processed
            start_date: Assessment period start date
            end_date: Assessment period end date

        Returns:
            Privacy Impact Assessment report
        """
        # Query relevant audit logs
        filter_criteria = {"processing_purpose": processing_purpose}
        audit_logs = self._query_audit_logs(start_date, end_date, filter_criteria)

        # Analyze privacy risks
        risk_analysis = self._analyze_privacy_risks(audit_logs, data_types)

        # Generate recommendations
        recommendations = self._generate_privacy_recommendations(risk_analysis)

        return {
            "assessment_id": self._generate_report_id(),
            "processing_purpose": processing_purpose,
            "data_types": data_types,
            "assessment_period": {"start": start_date, "end": end_date},
            "operations_analyzed": len(audit_logs),
            "risk_analysis": risk_analysis,
            "recommendations": recommendations,
            "compliance_status": risk_analysis.get("overall_risk_level", "unknown"),
            "generated_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }

    def _query_audit_logs(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
        filter_criteria: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Query audit logs with optional filtering."""
        with sqlite3.connect(str(self.audit_db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM mcp_audit_logs WHERE 1=1"
            params = []

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)

            if filter_criteria:
                for key, value in filter_criteria.items():
                    if key in ["operation_type", "user_id", "processing_purpose"]:
                        query += f" AND {key} = ?"
                        params.append(value)

            query += " ORDER BY timestamp DESC"

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def _analyze_compliance(
        self, audit_logs: list[dict[str, Any]], regulation: ComplianceRegulation
    ) -> dict[str, Any]:
        """Analyze audit logs for compliance violations."""
        rules = self.compliance_rules.get(regulation, {})
        violations = []
        recommendations = []

        # Track unique data subjects and sources
        data_subjects = set()
        data_sources = set()
        processing_purposes = set()
        legal_bases = set()
        retention_policies = set()

        for log in audit_logs:
            # Parse JSON fields
            try:
                data_sources_list = json.loads(log.get("data_sources", "[]"))
                json.loads(log.get("compliance_tags", "[]"))
            except (json.JSONDecodeError, TypeError):
                data_sources_list = []

            # Collect metadata
            if log.get("data_subject_id"):
                data_subjects.add(log["data_subject_id"])

            data_sources.update(data_sources_list)

            if log.get("processing_purpose"):
                processing_purposes.add(log["processing_purpose"])

            if log.get("legal_basis"):
                legal_bases.add(log["legal_basis"])

            if log.get("retention_policy"):
                retention_policies.add(log["retention_policy"])

            # Check for violations
            if regulation == ComplianceRegulation.GDPR:
                violations.extend(self._check_gdpr_compliance(log, rules))
            elif regulation == ComplianceRegulation.CCPA:
                violations.extend(self._check_ccpa_compliance(log, rules))

        # Generate recommendations
        if not legal_bases and regulation == ComplianceRegulation.GDPR:
            recommendations.append(
                "Ensure all data processing has a valid legal basis under GDPR"
            )

        if len(data_subjects) > 100 and regulation in [
            ComplianceRegulation.GDPR,
            ComplianceRegulation.CCPA,
        ]:
            recommendations.append(
                "Consider implementing automated data subject rights management"
            )

        return {
            "data_subjects_count": len(data_subjects),
            "data_sources": list(data_sources),
            "processing_purposes": list(processing_purposes),
            "legal_bases": list(legal_bases),
            "retention_policies": list(retention_policies),
            "violations": violations,
            "recommendations": recommendations,
            "metadata": {
                "regulation": regulation.value,
                "total_logs_analyzed": len(audit_logs),
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            },
        }

    def _check_gdpr_compliance(
        self, log: dict[str, Any], rules: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Check GDPR compliance for a single log entry."""
        violations = []

        # Check for missing legal basis
        if log.get("gdpr_applicable") and not log.get("legal_basis"):
            violations.append(
                {
                    "type": "missing_legal_basis",
                    "severity": "high",
                    "entry_id": log["entry_id"],
                    "description": "GDPR-applicable operation without legal basis",
                    "regulation": "GDPR Article 6",
                }
            )

        # Check retention period
        if log.get("expires_at"):
            try:
                expires_at = datetime.fromisoformat(
                    log["expires_at"].replace("Z", "+00:00")
                )
                created_at = datetime.fromisoformat(
                    log["timestamp"].replace("Z", "+00:00")
                )
                retention_days = (expires_at - created_at).days

                if retention_days > rules.get("max_retention_days", 2555):
                    violations.append(
                        {
                            "type": "excessive_retention",
                            "severity": "medium",
                            "entry_id": log["entry_id"],
                            "description": f"Retention period ({retention_days} days) exceeds GDPR limits",
                            "regulation": "GDPR Article 5(1)(e)",
                        }
                    )
            except (ValueError, TypeError):
                pass

        return violations

    def _check_ccpa_compliance(
        self, log: dict[str, Any], _rules: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Check CCPA compliance for a single log entry."""
        violations = []

        # Check for missing privacy disclosures
        if log.get("ccpa_applicable") and not log.get("processing_purpose"):
            violations.append(
                {
                    "type": "missing_processing_purpose",
                    "severity": "medium",
                    "entry_id": log["entry_id"],
                    "description": "CCPA-applicable operation without clear processing purpose",
                    "regulation": "CCPA Section 1798.100",
                }
            )

        return violations

    def _analyze_privacy_risks(
        self, audit_logs: list[dict[str, Any]], data_types: list[str]
    ) -> dict[str, Any]:
        """Analyze privacy risks in audit logs."""
        risk_factors = {
            "high_volume_processing": len(audit_logs) > 10000,
            "sensitive_data_types": any(
                dt in ["pii", "health", "financial"] for dt in data_types
            ),
            "cross_border_transfers": False,  # Would need geolocation analysis
            "automated_decision_making": any(
                "automated" in log.get("operation_name", "") for log in audit_logs
            ),
            "data_sharing": any(
                "share" in log.get("processing_purpose", "") for log in audit_logs
            ),
        }

        # Calculate overall risk level
        risk_score = sum(risk_factors.values())
        if risk_score >= 4:
            risk_level = "high"
        elif risk_score >= 2:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "overall_risk_level": risk_level,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "mitigation_required": risk_level in ["high", "medium"],
        }

    def _generate_privacy_recommendations(
        self, risk_analysis: dict[str, Any]
    ) -> list[str]:
        """Generate privacy recommendations based on risk analysis."""
        recommendations = []

        if risk_analysis["risk_factors"]["high_volume_processing"]:
            recommendations.append(
                "Implement data minimization techniques to reduce processing volume"
            )

        if risk_analysis["risk_factors"]["sensitive_data_types"]:
            recommendations.append(
                "Apply additional security controls for sensitive data processing"
            )

        if risk_analysis["risk_factors"]["automated_decision_making"]:
            recommendations.append(
                "Ensure transparency and explainability in automated decision-making"
            )

        if risk_analysis["overall_risk_level"] == "high":
            recommendations.append(
                "Conduct formal Data Protection Impact Assessment (DPIA)"
            )

        return recommendations

    def _sanitize_audit_logs(
        self, audit_logs: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove or mask sensitive data from audit logs."""
        sanitized_logs = []

        for log in audit_logs.copy():
            # Remove sensitive fields
            sensitive_fields = ["data_subject_id", "input_parameters", "output_data"]
            for field in sensitive_fields:
                if field in log:
                    log[field] = "[REDACTED]"

            # Hash user IDs
            if log.get("user_id"):
                log["user_id"] = hashlib.sha256(log["user_id"].encode()).hexdigest()[
                    :16
                ]

            sanitized_logs.append(log)

        return sanitized_logs

    def _export_json(self, data: list[dict[str, Any]], filepath: Path) -> None:
        """Export data to JSON format."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _export_csv(self, data: list[dict[str, Any]], filepath: Path) -> None:
        """Export data to CSV format."""
        if not data:
            return

        fieldnames = data[0].keys()
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

    def _export_xml(self, data: list[dict[str, Any]], filepath: Path) -> None:
        """Export data to XML format."""
        try:
            import defusedxml.ElementTree as ET
        except ImportError:
            # Fallback to standard library with security warning
            import xml.etree.ElementTree as ET  # nosec B405
            import warnings

            warnings.warn(
                "defusedxml not available. Using xml.etree.ElementTree which may be vulnerable to XML attacks. "
                "Install defusedxml for secure XML processing: pip install defusedxml",
                UserWarning,
                stacklevel=2,
            )

        root = ET.Element("audit_logs")

        for log in data:
            log_element = ET.SubElement(root, "log_entry")
            for key, value in log.items():
                if value is not None:
                    elem = ET.SubElement(log_element, key)
                    elem.text = str(value)

        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)

    def _generate_report_id(self) -> str:
        """Generate unique report ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"compliance_report_{timestamp}_{hash(timestamp) % 10000:04d}"


def create_compliance_reporter(
    audit_db_path: str,
    reports_output_dir: str = "compliance_reports",
    regulation: ComplianceRegulation = ComplianceRegulation.GDPR,
) -> MCPComplianceReporter:
    """
    Factory function to create an MCP compliance reporter instance.

    Args:
        audit_db_path: Path to the MCP audit database
        reports_output_dir: Directory to store generated reports
        regulation: Default compliance regulation

    Returns:
        Configured MCPComplianceReporter instance
    """
    return MCPComplianceReporter(
        audit_db_path=audit_db_path,
        reports_output_dir=reports_output_dir,
        default_regulation=regulation,
    )
