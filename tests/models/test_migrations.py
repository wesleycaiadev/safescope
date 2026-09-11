"""Exercise real Alembic revisions instead of creating the current ORM schema."""

from argparse import Namespace
from io import StringIO

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


def test_upgrade_from_initial_preserves_data_and_creates_memberships_once(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'migrations.db'}"
    config = Config("alembic.ini")
    config.cmd_opts = Namespace(x=[f"db_url={url}"])
    engine = create_engine(url)
    try:
        command.upgrade(config, "20260910_01")
        assert "organization_memberships" not in inspect(engine).get_table_names()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO organizations (id, name, created_at) "
                    "VALUES ('org-1', 'Preserved organization', CURRENT_TIMESTAMP)"
                )
            )
        command.upgrade(config, "head")
        command.upgrade(config, "head")
        inspector = inspect(engine)
        assert "organization_memberships" in inspector.get_table_names()
        assert any(
            index["name"] == "ix_organization_memberships_user_id"
            for index in inspector.get_indexes("organization_memberships")
        )
        with engine.begin() as connection:
            assert connection.scalar(text("SELECT name FROM organizations")) == "Preserved organization"
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "000baf345f21"
            connection.execute(
                text(
                    "INSERT INTO organization_memberships (organization_id, user_id, created_at) "
                    "VALUES ('org-1', 'user-1', CURRENT_TIMESTAMP)"
                )
            )
            assert connection.scalar(text("SELECT role FROM organization_memberships")) == "MEMBER"
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(text("UPDATE organization_memberships SET role = 'INVALID'"))
        command.downgrade(config, "20260910_01")
        assert "organization_memberships" not in inspect(engine).get_table_names()
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT name FROM organizations")) == "Preserved organization"
        command.upgrade(config, "head")
    finally:
        engine.dispose()


def test_postgresql_migrations_emit_one_membership_table() -> None:
    output = StringIO()
    config = Config("alembic.ini", output_buffer=output)
    config.cmd_opts = Namespace(x=["db_url=postgresql+psycopg://localhost/unused"])
    command.upgrade(config, "head", sql=True)
    sql = output.getvalue()
    assert sql.count("CREATE TABLE organization_memberships") == 1
    assert "ck_membership_role" in sql
    assert "ix_organization_memberships_user_id" in sql
