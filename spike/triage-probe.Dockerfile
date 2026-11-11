# Triage execution identity probe (ADR 0002, RC1-638 exit).
# Built vendor-side; run with NO mounts and NO credentials. The container
# must be unable to reach any customer surface — denial_test.py exits 0
# only if every probe is refused.
FROM python:3.12-slim
RUN pip install --no-cache-dir "psycopg[binary]>=3.2"
COPY denial_test.py /denial_test.py
ENTRYPOINT ["python", "-I", "/denial_test.py"]
