# Build from the shared parent:
# docker build -f 001AI-SOC-Agent/Dockerfile -t ai-soc-agent:0.1 .

FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build/001AI-SOC-Agent
COPY 000shared-llm-core /build/000shared-llm-core
COPY 001AI-SOC-Agent /build/001AI-SOC-Agent

RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels /build/001AI-SOC-Agent

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-deps /wheels/*.whl \
    && python -m pip check \
    && rm -rf /wheels

USER 65532:65532
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]

CMD ["uvicorn", "ai_soc_agent.server:app", "--host", "0.0.0.0", "--port", "8080"]
