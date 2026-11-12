"""Dropping the app role as a NON-superuser owner, the way Neon runs it
(RC1-640). Needs a Postgres superuser URL in CIK_TEST_PG_ADMIN_URL to set
the scene; skipped otherwise."""

import os
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest

from kit.install.engine import InstallError, drop_role

ADMIN = os.environ.get("CIK_TEST_PG_ADMIN_URL")
pytestmark = pytest.mark.skipif(not ADMIN, reason="CIK_TEST_PG_ADMIN_URL not set")


@pytest.fixture()
def owner_url():
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute("DROP DATABASE IF EXISTS cik_td")
        for role in ("cik_td_app", "cik_td_owner"):
            conn.execute(f"DROP ROLE IF EXISTS {role}")
        conn.execute("CREATE ROLE cik_td_owner LOGIN PASSWORD 'cik-td-owner' CREATEROLE")
        conn.execute("CREATE DATABASE cik_td OWNER cik_td_owner")
    p = urlsplit(ADMIN)
    url = urlunsplit(p._replace(netloc=f"cik_td_owner:cik-td-owner@{p.hostname}:{p.port}",
                                path="/cik_td"))
    with psycopg.connect(url, autocommit=True) as conn:  # as the owner, like db_setup
        conn.execute("CREATE TABLE review_audit (x int)")
        conn.execute("INSERT INTO review_audit VALUES (1)")
        conn.execute("CREATE ROLE cik_td_app LOGIN PASSWORD 'x'")
        conn.execute("GRANT SELECT, INSERT ON review_audit TO cik_td_app")
        conn.execute("GRANT USAGE ON SCHEMA public TO cik_td_app")
    return url


def test_owner_drops_the_role_and_keeps_the_data(owner_url):
    assert drop_role(owner_url, "cik_td_app") == "dropped"
    with psycopg.connect(owner_url) as conn:
        assert conn.execute("SELECT count(*) FROM review_audit").fetchone()[0] == 1
        assert not conn.execute("SELECT 1 FROM pg_roles WHERE rolname='cik_td_app'").fetchone()
    assert drop_role(owner_url, "cik_td_app") == "absent"  # re-run is a no-op


def test_a_role_that_owns_data_is_never_dropped(owner_url):
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute("GRANT cik_td_app TO CURRENT_USER")
        conn.execute("GRANT CREATE ON SCHEMA public TO cik_td_app")
        conn.execute("CREATE TABLE app_owned (y int)")
        conn.execute("ALTER TABLE app_owned OWNER TO cik_td_app")
    with pytest.raises(InstallError, match="owns 1 relation"):
        drop_role(owner_url, "cik_td_app")
    with psycopg.connect(owner_url) as conn:
        assert conn.execute("SELECT to_regclass('app_owned')").fetchone()[0] is not None
