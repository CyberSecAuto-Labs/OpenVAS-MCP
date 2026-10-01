FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml requirements.txt ./
COPY openvas_mcp/ ./openvas_mcp/
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir --prefix=/install -c requirements.txt .

FROM python:3.11-slim

# python:3.11-slim is a floating tag, but upstream rebuilds on its own cadence, so
# its Debian packages can sit on a superseded patch level while a security fix is
# already published. Upgrading here closes those fixable CVEs instead of waiting
# on an upstream rebuild.
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -U pip setuptools wheel && \
    useradd --create-home --shell /bin/sh --uid 1000 mcp

WORKDIR /app

COPY --from=builder /install /usr/local
COPY examples/ ./examples/

USER mcp

EXPOSE 8000

ENV MCP_TRANSPORT=sse \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    LOG_LEVEL=INFO \
    GVM_USERNAME=admin

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>/dev/null || exit 1

CMD ["python", "-m", "openvas_mcp"]
