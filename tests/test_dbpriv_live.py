"""FUP-DB-PRIV against a real Postgres (RC1-644). With the app role's USAGE
on schema public revoked, the matrix must show exactly that grant missing and
every table grant intact: a lookup by name (to_regclass) needs USAGE, so it
used to report every table as missing. Needs CIK_TEST_PG_ADMIN_URL (CI
provides one); skipped otherwise."""

import os
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest

from kit.triage import followup, registry

ADMIN = os.environ.get("CIK_TEST_PG_ADMIN_URL")
pytestmark = pytest.mark.skipif(not ADMIN, reason="CIK_TEST_PG_ADMIN_URL not set")


def _url(user: str, password: str, db: str) -> str:
    p = urlsplit(ADMIN)
    return urlunsplit(p._replace(netloc=f"{user}:{password}@{p.hostname}:{p.port}",
                                 path=f"/{db}"))


@pytest.fixture()
def esp_db():
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute("DROP DATABASE IF EXISTS cik_dbpriv")
        for role in ("cik_dbpriv_app", "cik_dbpriv_owner"):
            conn.execute(f"DROP ROLE IF EXISTS {role}")
        conn.execute("CREATE ROLE cik_dbpriv_owner LOGIN PASSWORD 'cik-dbpriv-owner'")
        conn.execute("CREATE DATABASE cik_dbpriv OWNER cik_dbpriv_owner")
    owner = _url("cik_dbpriv_owner", "cik-dbpriv-owner", "cik_dbpriv")
    app = registry.knowledge()["app_role"]
    tables = {g.rsplit(" ", 1)[0] for g in app["expected"] + app["must_not_have"]
              if not g.startswith(("schema ", "database "))}
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute("CREATE ROLE cik_dbpriv_app LOGIN PASSWORD 'cik-dbpriv-app'")
    with psycopg.connect(owner, autocommit=True) as conn:
        conn.execute("GRANT USAGE ON SCHEMA public TO cik_dbpriv_app")
        for t in sorted(tables):
            conn.execute(f"CREATE TABLE {t} (x int)")
        for g in app["expected"]:
            obj, priv = g.rsplit(" ", 1)
            if not obj.startswith(("schema ", "database")):
                conn.execute(f"GRANT {priv} ON {obj} TO cik_dbpriv_app")
    return owner, _url("cik_dbpriv_app", "cik-dbpriv-app", "cik_dbpriv")


def _missing(out):
    return sorted(f"{g['object']} {g['privilege']}" for g in out["grants"]
                  if g["expected"] and not g["granted"])


def test_all_grants_present(esp_db):
    _, app = esp_db
    out = followup.db_privileges(app, psycopg.connect)
    assert out["connected"] and _missing(out) == []
    assert all(g["object_exists"] for g in out["grants"] if g["object"] != "database")


def test_schema_usage_revoked_shows_only_that_grant_missing(esp_db):
    owner, app = esp_db
    with psycopg.connect(owner, autocommit=True) as conn:
        conn.execute("REVOKE USAGE ON SCHEMA public FROM cik_dbpriv_app")
        conn.execute("REVOKE USAGE ON SCHEMA public FROM PUBLIC")
    try:
        out = followup.db_privileges(app, psycopg.connect)
        assert _missing(out) == ["schema public USAGE"]
        assert all(g["object_exists"] for g in out["grants"]
                   if not g["object"].startswith(("schema ", "database")))
    finally:
        with psycopg.connect(owner, autocommit=True) as conn:
            conn.execute("GRANT USAGE ON SCHEMA public TO PUBLIC")


def test_a_table_privilege_revoked_shows_that_grant(esp_db):
    owner, app = esp_db
    with psycopg.connect(owner, autocommit=True) as conn:
        conn.execute("REVOKE SELECT ON review_audit FROM cik_dbpriv_app")
    assert _missing(followup.db_privileges(app, psycopg.connect)) == ["review_audit SELECT"]
