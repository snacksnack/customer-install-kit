"""Keep planted secrets and PII out of Datadog test reporting (RC1-676, ADR 0009).

Test Optimization records test names, parameters, and failure messages, so a
file holding planted values cannot run under `--ddtrace`. Detection reads the
source, so a new file with planted values is excluded without a list to update.
"""

import re

import pytest

PLANTED_SHAPES = re.compile(
    r"canar(?:y|ies)|xkeysib-|sk-ant-|219-09-9999|4111111111111111|203\.0\.113\.",
    re.IGNORECASE,
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    planted: dict[str, bool] = {}
    for item in items:
        path = str(item.path)
        if path not in planted:
            planted[path] = bool(PLANTED_SHAPES.search(item.path.read_text(encoding="utf-8")))
        if planted[path]:
            item.add_marker(pytest.mark.planted_values)
