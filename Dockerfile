# Container image for running sigma-mcp-server as a public HTTP service.
#
# The SigmaHQ rule index and the MITRE data are built into the image, so a
# container starts at once and needs no writable volume. Rebuild the image to
# update the rules (the "Container image" workflow does that every week).
#
#   docker build -t sigma-mcp-server .
#   docker run --rm -p 8000:8000 sigma-mcp-server
#
# The MCP endpoint is http://localhost:8000/mcp, the health check /health.

# Another registry can be used with --build-arg, e.g. when Docker Hub limits
# pulls: --build-arg PYTHON_IMAGE=mirror.gcr.io/library/python:3.13-slim
ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# UID 1000 is what Hugging Face Spaces runs containers as.
RUN useradd --create-home --uid 1000 app

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY sigma ./sigma
RUN pip install .

USER app
ENV HOME=/home/app \
    SIGMA_MCP_DATA_DIR=/home/app/data

# Download the SigmaHQ rules, build the index and cache the MITRE data
# (pySigma keeps it below ~/.cache/pysigma).
RUN sigma-mcp-server --prepare

# Serve the index from the image; clients cannot trigger downloads. The port
# is taken from PORT (set by Cloud Run, Render and others), else 8000.
ENV SIGMA_MCP_TRANSPORT=http \
    SIGMA_MCP_HOST=0.0.0.0 \
    SIGMA_MCP_PUBLIC=1 \
    SIGMA_MCP_INDEX_MAX_AGE_DAYS=0

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"SIGMA_MCP_PORT\") or os.environ.get(\"PORT\") or 8000}/health', timeout=4)"

CMD ["sigma-mcp-server"]
