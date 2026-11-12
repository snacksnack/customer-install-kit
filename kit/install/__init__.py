"""Operator-side install path (RC1-640, ADR 0006): signed-release
verification, install, rollback and teardown.

Separate from `kit` proper on purpose: `python -m kit preflight` also runs
inside the customer's machine, which has psycopg but not sigstore, so
nothing the runtime context imports may depend on this package.
"""
