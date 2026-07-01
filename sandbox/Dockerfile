# Minimal, throwaway image for AI-BOM's Stage 3 isolated load probe.
# It carries only strace + a Python stdlib probe; it does NOT need torch. The
# container is run locked down (network none, read-only rootfs, cap-drop ALL,
# no-new-privileges) by aibom.stages.stage3_sandbox.build_run_kwargs.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

# Never write .pyc; keep the load probe's footprint minimal and predictable.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY probe.py /probe/probe.py

# A non-root user; the load runs with no privileges it doesn't need.
RUN useradd --create-home --uid 10001 prober
USER prober

ENTRYPOINT ["python3", "/probe/probe.py"]
