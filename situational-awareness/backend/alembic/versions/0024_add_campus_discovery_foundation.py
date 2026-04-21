"""add campus discovery foundation

Revision ID: 0024_add_campus_discovery_foundation
Revises: 0023_vuln_intel_and_governance
Create Date: 2026-04-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0024_add_campus_discovery_foundation"
down_revision: str | None = "0023_vuln_intel_and_governance"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "scanner_zones" not in table_names:
        op.create_table(
            "scanner_zones",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("zone_type", sa.String(length=32), nullable=False, server_default="office"),
            sa.Column("description", sa.String(length=255), nullable=True),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("cidrs_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("default_scan_profile_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("allowed_data_source_types_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_scanner_zones_name", "scanner_zones", ["name"], unique=True)
        op.create_index("ix_scanner_zones_zone_type", "scanner_zones", ["zone_type"], unique=False)
        op.create_index("ix_scanner_zones_priority", "scanner_zones", ["priority"], unique=False)

    if "scanner_node_assignments" not in table_names:
        op.create_table(
            "scanner_node_assignments",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("scanner_zone_id", sa.String(length=36), nullable=False),
            sa.Column("asset_id", sa.String(length=36), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("visible_cidrs_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("max_concurrent_jobs", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["scanner_zone_id"], ["scanner_zones.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("scanner_zone_id", "asset_id", name="uq_scanner_zone_asset"),
        )
        op.create_index("ix_scanner_node_assignments_asset_id", "scanner_node_assignments", ["asset_id"], unique=False)

    if "campus_data_sources" not in table_names:
        op.create_table(
            "campus_data_sources",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("scanner_zone_id", sa.String(length=36), nullable=False),
            sa.Column("asset_id", sa.String(length=36), nullable=True),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("source_type", sa.String(length=32), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("collection_interval_seconds", sa.Integer(), nullable=False, server_default="1800"),
            sa.Column("config_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("last_summary_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("secret_ciphertext", sa.String(length=4096), nullable=True),
            sa.Column("last_collected_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["scanner_zone_id"], ["scanner_zones.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_campus_data_sources_name", "campus_data_sources", ["name"], unique=False)
        op.create_index("ix_campus_data_sources_source_type", "campus_data_sources", ["source_type"], unique=False)

    if "discovery_job_executions" not in table_names:
        op.create_table(
            "discovery_job_executions",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("discovery_job_id", sa.String(length=36), nullable=False),
            sa.Column("scanner_zone_id", sa.String(length=36), nullable=True),
            sa.Column("asset_id", sa.String(length=36), nullable=True),
            sa.Column("target_cidr", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("task_run_id", sa.String(length=36), nullable=True),
            sa.Column("summary_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("error_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["discovery_job_id"], ["discovery_jobs.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["scanner_zone_id"], ["scanner_zones.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["task_run_id"], ["task_runs.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_discovery_job_executions_status", "discovery_job_executions", ["status"], unique=False)

    asset_columns = {item["name"] for item in inspector.get_columns("assets")}
    if "mac_address" not in asset_columns:
        op.add_column("assets", sa.Column("mac_address", sa.String(length=32), nullable=True))
        op.create_index("ix_assets_mac_address", "assets", ["mac_address"], unique=False)
    if "vendor" not in asset_columns:
        op.add_column("assets", sa.Column("vendor", sa.String(length=255), nullable=True))
    if "network_zone" not in asset_columns:
        op.add_column("assets", sa.Column("network_zone", sa.String(length=128), nullable=True))
        op.create_index("ix_assets_network_zone", "assets", ["network_zone"], unique=False)
    if "network_vlan" not in asset_columns:
        op.add_column("assets", sa.Column("network_vlan", sa.String(length=64), nullable=True))
        op.create_index("ix_assets_network_vlan", "assets", ["network_vlan"], unique=False)
    if "building" not in asset_columns:
        op.add_column("assets", sa.Column("building", sa.String(length=128), nullable=True))
    if "department" not in asset_columns:
        op.add_column("assets", sa.Column("department", sa.String(length=128), nullable=True))
    if "asset_category" not in asset_columns:
        op.add_column("assets", sa.Column("asset_category", sa.String(length=64), nullable=True))
        op.create_index("ix_assets_asset_category", "assets", ["asset_category"], unique=False)
    if "device_role" not in asset_columns:
        op.add_column("assets", sa.Column("device_role", sa.String(length=128), nullable=True))
    if "identity_source" not in asset_columns:
        op.add_column("assets", sa.Column("identity_source", sa.String(length=64), nullable=True))
    if "last_auth_time" not in asset_columns:
        op.add_column("assets", sa.Column("last_auth_time", sa.DateTime(timezone=True), nullable=True))
        op.create_index("ix_assets_last_auth_time", "assets", ["last_auth_time"], unique=False)
    if "is_infrastructure_device" not in asset_columns:
        op.add_column("assets", sa.Column("is_infrastructure_device", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    if "is_iot" not in asset_columns:
        op.add_column("assets", sa.Column("is_iot", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    if "is_virtual_network_component" not in asset_columns:
        op.add_column("assets", sa.Column("is_virtual_network_component", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    if "ipv6_addresses_json" not in asset_columns:
        op.add_column("assets", sa.Column("ipv6_addresses_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")))

    runner_columns = {item["name"] for item in inspector.get_columns("host_runners")}
    if "node_role" not in runner_columns:
        op.add_column("host_runners", sa.Column("node_role", sa.String(length=32), nullable=False, server_default="hybrid"))
        op.create_index("ix_host_runners_node_role", "host_runners", ["node_role"], unique=False)
    if "scanner_zone_id" not in runner_columns:
        op.add_column("host_runners", sa.Column("scanner_zone_id", sa.String(length=36), nullable=True))
        op.create_index("ix_host_runners_scanner_zone_id", "host_runners", ["scanner_zone_id"], unique=False)
        op.create_foreign_key("fk_host_runners_scanner_zone_id", "host_runners", "scanner_zones", ["scanner_zone_id"], ["id"], ondelete="SET NULL")
    if "visible_cidrs_json" not in runner_columns:
        op.add_column("host_runners", sa.Column("visible_cidrs_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")))
    if "max_concurrent_jobs" not in runner_columns:
        op.add_column("host_runners", sa.Column("max_concurrent_jobs", sa.Integer(), nullable=False, server_default="1"))

    job_columns = {item["name"] for item in inspector.get_columns("discovery_jobs")}
    if "scanner_zone_id" not in job_columns:
        op.add_column("discovery_jobs", sa.Column("scanner_zone_id", sa.String(length=36), nullable=True))
        op.create_index("ix_discovery_jobs_scanner_zone_id", "discovery_jobs", ["scanner_zone_id"], unique=False)
        op.create_foreign_key("fk_discovery_jobs_scanner_zone_id", "discovery_jobs", "scanner_zones", ["scanner_zone_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "discovery_jobs" in table_names:
        columns = {item["name"] for item in inspector.get_columns("discovery_jobs")}
        if "scanner_zone_id" in columns:
            indexes = {item["name"] for item in inspector.get_indexes("discovery_jobs")}
            if "ix_discovery_jobs_scanner_zone_id" in indexes:
                op.drop_index("ix_discovery_jobs_scanner_zone_id", table_name="discovery_jobs")
            with op.batch_alter_table("discovery_jobs") as batch_op:
                batch_op.drop_constraint("fk_discovery_jobs_scanner_zone_id", type_="foreignkey")
                batch_op.drop_column("scanner_zone_id")

    if "host_runners" in table_names:
        columns = {item["name"] for item in inspector.get_columns("host_runners")}
        indexes = {item["name"] for item in inspector.get_indexes("host_runners")}
        if "max_concurrent_jobs" in columns:
            op.drop_column("host_runners", "max_concurrent_jobs")
        if "visible_cidrs_json" in columns:
            op.drop_column("host_runners", "visible_cidrs_json")
        if "scanner_zone_id" in columns:
            if "ix_host_runners_scanner_zone_id" in indexes:
                op.drop_index("ix_host_runners_scanner_zone_id", table_name="host_runners")
            with op.batch_alter_table("host_runners") as batch_op:
                batch_op.drop_constraint("fk_host_runners_scanner_zone_id", type_="foreignkey")
                batch_op.drop_column("scanner_zone_id")
        if "node_role" in columns:
            if "ix_host_runners_node_role" in indexes:
                op.drop_index("ix_host_runners_node_role", table_name="host_runners")
            op.drop_column("host_runners", "node_role")

    if "assets" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("assets")}
        columns = {item["name"] for item in inspector.get_columns("assets")}
        for index_name, column_name in (
            ("ix_assets_last_auth_time", "last_auth_time"),
            ("ix_assets_asset_category", "asset_category"),
            ("ix_assets_network_vlan", "network_vlan"),
            ("ix_assets_network_zone", "network_zone"),
            ("ix_assets_mac_address", "mac_address"),
        ):
            if column_name in columns:
                if index_name in indexes:
                    op.drop_index(index_name, table_name="assets")
                op.drop_column("assets", column_name)
                columns.remove(column_name)
        for column_name in (
            "vendor",
            "building",
            "department",
            "device_role",
            "identity_source",
            "is_infrastructure_device",
            "is_iot",
            "is_virtual_network_component",
            "ipv6_addresses_json",
        ):
            if column_name in columns:
                op.drop_column("assets", column_name)

    if "discovery_job_executions" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("discovery_job_executions")}
        if "ix_discovery_job_executions_status" in indexes:
            op.drop_index("ix_discovery_job_executions_status", table_name="discovery_job_executions")
        op.drop_table("discovery_job_executions")

    if "campus_data_sources" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("campus_data_sources")}
        if "ix_campus_data_sources_source_type" in indexes:
            op.drop_index("ix_campus_data_sources_source_type", table_name="campus_data_sources")
        if "ix_campus_data_sources_name" in indexes:
            op.drop_index("ix_campus_data_sources_name", table_name="campus_data_sources")
        op.drop_table("campus_data_sources")

    if "scanner_node_assignments" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("scanner_node_assignments")}
        if "ix_scanner_node_assignments_asset_id" in indexes:
            op.drop_index("ix_scanner_node_assignments_asset_id", table_name="scanner_node_assignments")
        op.drop_table("scanner_node_assignments")

    if "scanner_zones" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("scanner_zones")}
        for index_name in ("ix_scanner_zones_priority", "ix_scanner_zones_zone_type", "ix_scanner_zones_name"):
            if index_name in indexes:
                op.drop_index(index_name, table_name="scanner_zones")
        op.drop_table("scanner_zones")
