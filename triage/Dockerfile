# The vendor's triage runtime (RC1-643, ADR 0009; identity per ADR 0002).
#
# Holds the kit and nothing of the customer's. Runs as an unprivileged user
# with an empty home: no ~/.fly, no .env files, no database URLs. Its only
# network is an internal Docker network whose one way out is the egress
# proxy (triage/egress/), which permits the Claude API and the Datadog LLM
# Obs intake and refuses everything else.
FROM python:3.12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir uv==0.9.5
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY kit ./kit

FROM python:3.12-slim
RUN useradd --uid 10001 --create-home --home-dir /home/triage triage
COPY --from=build /app /app
COPY triage/isolation_test.py /app/isolation_test.py
ENV PATH=/app/.venv/bin:$PATH PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 \
    CIK_CASE_STORE=/case-store
WORKDIR /app
USER triage
# -P keeps the working directory off sys.path; PYTHONPATH names the kit explicitly.
ENTRYPOINT ["python", "-P", "-m", "kit.triage"]
