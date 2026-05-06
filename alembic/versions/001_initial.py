"""Initial schema - all FoxRecon tables.

Revision ID: 001_initial
Revises:
Create Date: 2026-05-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable extensions
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')

    # Users
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("api_key_hash", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_username", "users", ["username"])

    # Organizations
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("settings", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("slug", name="uq_org_slug"),
    )
    op.create_index("ix_organizations_name", "organizations", ["name"])
    op.create_index("ix_organizations_slug", "organizations", ["slug"])

    # User Organizations (many-to-many)
    op.create_table(
        "user_organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="member"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "organization_id", name="uq_user_org"),
    )

    # Targets
    op.create_table(
        "targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False, server_default="in_scope"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "value", name="uq_org_target"),
    )
    op.create_index("ix_targets_name", "targets", ["name"])
    op.create_index("ix_targets_value", "targets", ["value"])
    op.create_index("ix_targets_org_type", "targets", ["organization_id", "target_type"])

    # Subdomains
    op.create_table(
        "subdomains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("is_apex", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("source", sa.String(100), nullable=True),
        sa.Column("resolved_ip", sa.String(45), nullable=True),
        sa.Column("first_seen_scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("last_seen_scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "domain", name="uq_target_subdomain"),
    )
    op.create_index("ix_subdomains_domain", "subdomains", ["domain"])

    # Live Hosts
    op.create_table(
        "live_hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("url", sa.String(750), nullable=False),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("port", sa.Integer, nullable=False, server_default="443"),
        sa.Column("scheme", sa.String(5), nullable=False, server_default="https"),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("title", sa.String(500), nullable=True),
        sa.Column("content_type", sa.String(200), nullable=True),
        sa.Column("content_length", sa.Integer, nullable=True),
        sa.Column("response_time_ms", sa.Integer, nullable=True),
        sa.Column("tech_stack", postgresql.JSONB, nullable=True),
        sa.Column("webserver", sa.String(200), nullable=True),
        sa.Column("hash", sa.String(64), nullable=True),
        sa.Column("last_scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "hostname", "port", name="uq_target_host_port"),
    )
    op.create_index("ix_live_hosts_hostname", "live_hosts", ["hostname"])
    op.create_index("ix_live_hosts_url", "live_hosts", ["url"])
    op.create_index("ix_live_hosts_status", "live_hosts", ["status_code"])

    # Ports
    op.create_table(
        "ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("live_host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("live_hosts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("port_number", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(10), nullable=False, server_default="tcp"),
        sa.Column("state", sa.String(20), nullable=False, server_default="open"),
        sa.Column("service_name", sa.String(100), nullable=True),
        sa.Column("service_version", sa.String(200), nullable=True),
        sa.Column("product", sa.String(200), nullable=True),
        sa.Column("extra_info", sa.Text, nullable=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "host", "port_number", "protocol", name="uq_port"),
    )
    op.create_index("ix_ports_host_port", "ports", ["host", "port_number"])
    op.create_index("ix_ports_service", "ports", ["service_name"])

    # Technologies
    op.create_table(
        "technologies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("live_host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("live_hosts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("category", sa.String(100), nullable=True),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "name", "version", name="uq_technology"),
    )
    op.create_index("ix_technologies_name", "technologies", ["name"])

    # Screenshots
    op.create_table(
        "screenshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("live_host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("live_hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(750), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("file_hash", sa.String(64), nullable=True),
        sa.Column("width", sa.Integer, nullable=True),
        sa.Column("height", sa.Integer, nullable=True),
        sa.Column("title", sa.String(500), nullable=True),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Scan Jobs
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("priority", sa.Integer, nullable=False, server_default="5"),
        sa.Column("configuration", postgresql.JSONB, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("subdomains_found", sa.Integer, nullable=False, server_default="0"),
        sa.Column("live_hosts_found", sa.Integer, nullable=False, server_default="0"),
        sa.Column("ports_found", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_target_status", "scan_jobs", ["target_id", "status"])

    # Scan Results
    op.create_table(
        "scan_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stage", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("tool_name", sa.String(100), nullable=True),
        sa.Column("tool_version", sa.String(50), nullable=True),
        sa.Column("input_data", postgresql.JSONB, nullable=True),
        sa.Column("output_summary", postgresql.JSONB, nullable=True),
        sa.Column("raw_output_path", sa.String(500), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("item_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_scan_results_job_stage", "scan_results", ["scan_job_id", "stage"])

    # Findings
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("host", sa.String(255), nullable=True),
        sa.Column("port", sa.Integer, nullable=True),
        sa.Column("url", sa.String(750), nullable=True),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("references", postgresql.JSONB, nullable=True),
        sa.Column("tags", postgresql.JSONB, nullable=True),
        sa.Column("tool_source", sa.String(100), nullable=True),
        sa.Column("raw_data", postgresql.JSONB, nullable=True),
        sa.Column("is_duplicate", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("duplicate_of", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("is_verified", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("false_positive", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cve_ids", postgresql.JSONB, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_findings_severity_type", "findings", ["severity", "finding_type"])
    op.create_index("ix_findings_host", "findings", ["host"])
    op.create_index("ix_findings_target_severity", "findings", ["target_id", "severity"])

    # Vulnerabilities
    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("template_id", sa.String(200), nullable=False),
        sa.Column("template_name", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("matched_url", sa.String(750), nullable=True),
        sa.Column("matched_at", sa.String(750), nullable=True),
        sa.Column("extracted_results", postgresql.JSONB, nullable=True),
        sa.Column("cve_ids", postgresql.JSONB, nullable=True),
        sa.Column("cwe_ids", postgresql.JSONB, nullable=True),
        sa.Column("cvss_metrics", postgresql.JSONB, nullable=True),
        sa.Column("curl_command", sa.Text, nullable=True),
        sa.Column("request", sa.Text, nullable=True),
        sa.Column("response", sa.Text, nullable=True),
        sa.Column("info", postgresql.JSONB, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_vulns_template_severity", "vulnerabilities", ["template_id", "severity"])
    op.create_index("ix_vulns_host", "vulnerabilities", ["host"])

    # Reports
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("content", sa.Text, nullable=True),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
        sa.Column("scan_job_ids", postgresql.JSONB, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Activity Logs
    op.create_table(
        "activity_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_activity_logs_action", "activity_logs", ["action"])
    op.create_index("ix_activity_logs_timestamp", "activity_logs", ["created_at"])


def downgrade() -> None:
    # Drop in reverse order (respecting foreign keys)
    op.drop_table("activity_logs")
    op.drop_table("reports")
    op.drop_table("vulnerabilities")
    op.drop_table("findings")
    op.drop_table("scan_results")
    op.drop_table("scan_jobs")
    op.drop_table("screenshots")
    op.drop_table("technologies")
    op.drop_table("ports")
    op.drop_table("live_hosts")
    op.drop_table("subdomains")
    op.drop_table("targets")
    op.drop_table("user_organizations")
    op.drop_table("organizations")
    op.drop_table("users")
