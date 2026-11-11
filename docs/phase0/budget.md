# Budget ceiling (RC1-638 commitment; RC1-646 measures against it)

**Ceiling: $120 for the build plus the evaluation suite.** Confirmed by Reid 2026-11-10; precedent is RC1-595's working figure of $100–130.

## What it covers

- **Fly, customer org (`cik-customer`):** one shared-cpu-1x/512MB machine, scale-to-zero, plus a small volume for the storage fault family. Cents to low dollars per month; fault-injection runs briefly add machines.
- **Neon, customer project:** free plan; $0 while the fixture-scale data stays under 1 GB. Billed only if the project outgrows free.
- **Claude API (the dominant line):** triage investigations over bundles (dev cases, the evaluation matrix, and the rules-versus-agent comparison in Phase 6). Phase 0B's job (RC1-646): measure the full per-case lifecycle cost — install, fault injection, bundle, triage, model calls — on one real case *before* the evaluation matrix size is committed, and re-estimate at Phase 5. Model cost is provisional until real dev-case Claude calls exist.
- **Everything else** (GitHub Actions on the public repo, Sigstore): $0.

## Rules

- Phase 0B reports projected total = (per-case lifecycle cost × planned matrix size) + fixed infrastructure; if it exceeds the ceiling, the matrix shrinks or the ceiling is explicitly re-committed by Reid — it never silently stretches.
- Benchmark/evaluation spend and projected ongoing operating cost are reported as separate lines (the RC1-595 convention).
