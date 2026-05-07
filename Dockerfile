FROM python:3.11-slim

LABEL maintainer="TrustedSec"
LABEL description="Odoo Application Security Harness"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Install optional scanner tools
RUN pip install --no-cache-dir \
    semgrep \
    bandit \
    ruff \
    pylint \
    pylint-odoo \
    pip-audit \
    pyyaml

# Install osv-scanner
RUN curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/install.sh | sh -s -- -b /usr/local/bin

# Create working directory
WORKDIR /workspace

# Copy project files
COPY . /workspace/

# Install the harness itself
RUN pip install -e ".[dev,scanners]"

# Create non-root user
RUN useradd -m -u 1000 auditor && \
    chown -R auditor:auditor /workspace
USER auditor

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ODOO_REVIEW_ALLOW_UNSAFE_PROBES=0

# Default command
ENTRYPOINT ["odoo-review-run"]
CMD ["--help"]
