"""FoxRecon V2 - extended features schema.

Revision ID: 002_v2_features
Revises: 001_initial
Create Date: 2026-05-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "002_v2_features"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Scan Schedules
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("timezone", sa.String(50), nullable=False, server_default="UTC"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("notification_email", sa.String(255), nullable=True),
        sa.Column("last_run", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_runs", sa.Integer, nullable=False, server_default="0"),
        sa.Column("celery_schedule_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_schedules_enabled", "scan_schedules", ["enabled"])
    op.create_index("ix_schedules_target", "scan_schedules", ["target_id"])

    # JS Endpoints
    op.create_table(
        "js_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("source_file", sa.String(750), nullable=False),
        sa.Column("url", sa.String(750), nullable=False),
        sa.Column("endpoint_type", sa.String(50), nullable=False),
        sa.Column("method", sa.String(10), nullable=False, server_default="GET"),
        sa.Column("full_url", sa.String(750), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_js_endpoints_target", "js_endpoints", ["target_id"])
    op.create_index("ix_js_endpoints_source", "js_endpoints", ["source_file"])

    # JS Secrets
    op.create_table(
        "js_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("secret_type", sa.String(100), nullable=False),
        sa.Column("masked_value", sa.String(200), nullable=False),
        sa.Column("source_file", sa.String(750), nullable=False),
        sa.Column("line_number", sa.Integer, nullable=False, server_default="0"),
        sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
        sa.Column("is_verified", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_js_secrets_target", "js_secrets", ["target_id"])
    op.create_index("ix_js_secrets_type", "js_secrets", ["secret_type"])

    # DNS Records
    op.create_table(
        "dns_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("record_name", sa.String(255), nullable=False),
        sa.Column("record_type", sa.String(10), nullable=False),
        sa.Column("record_value", sa.String(500), nullable=False),
        sa.Column("ttl", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_dns_records_target_type", "dns_records", ["target_id", "record_type"])
    op.create_index("ix_dns_records_value", "dns_records", ["record_value"])

    # API Discoveries
    op.create_table(
        "api_discoveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("discovery_type", sa.String(50), nullable=False),
        sa.Column("url", sa.String(750), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("is_public", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_api_discovery_target_type", "api_discoveries", ["target_id", "discovery_type"])
    op.create_index("ix_api_discovery_url", "api_discoveries", ["url"])

    # Cloud Exposures
    op.create_table(
        "cloud_exposures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("cloud_provider", sa.String(20), nullable=False),
        sa.Column("bucket_name", sa.String(255), nullable=False),
        sa.Column("url", sa.String(750), nullable=False),
        sa.Column("is_public", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("is_listable", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_cloud_exposure_target", "cloud_exposures", ["target_id"])
    op.create_index("ix_cloud_exposure_provider", "cloud_exposures", ["cloud_provider"])
    op.create_index("ix_cloud_exposure_public", "cloud_exposures", ["is_public"])


def downgrade() -> None:
    op.drop_table("cloud_exposures")
    op.drop_table("api_discoveries")
    op.drop_table("dns_records")
    op.drop_table("js_secrets")
    op.drop_table("js_endpoints")
    op.drop_table("scan_schedules")
