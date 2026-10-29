# Multi-stage Dockerfile para Suricata MCP Server
FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libyaml-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir .

FROM python:3.12-slim AS final

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libyaml-0-2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Cria usuário não privilegiado para execução segura
RUN groupadd -g 1000 suricata && \
    useradd -u 1000 -g suricata -s /bin/bash -m suricata

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/ /app/src/
COPY pyproject.toml /app/

RUN pip install --no-cache-dir -e .

RUN mkdir -p /app/reports_output /app/pcaps /app/log /app/rules && \
    chown -R suricata:suricata /app

USER suricata

EXPOSE 8080

ENTRYPOINT ["suricata-mcp"]
CMD ["--transport", "stdio"]

