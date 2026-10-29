"""Auditoria estruturada e trilha de conformidade do Suricata MCP Server."""

import json
import logging
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import get_settings
from .policies import redact_secrets

# Logging interno direcionado exclusivamente para stderr para preservar stdout no transporte stdio
logger = logging.getLogger("suricata_mcp.audit")

# Buffer circular em memória das últimas 500 execuções para consulta via MCP
_MEMORY_AUDIT_LOG: deque[dict[str, Any]] = deque(maxlen=500)


def record_audit_entry(
    tool_name: str,
    params: dict[str, Any],
    success: bool,
    duration_ms: float,
    error: str | None = None,
    caller_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Registra uma entrada de auditoria estruturada no log e no buffer em memória."""
    settings = get_settings()

    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "tool_name": tool_name,
        "success": success,
        "duration_ms": round(duration_ms, 2),
        "params": redact_secrets(params),
        "error": error,
        "caller_context": caller_context or {},
        "operation_mode": settings.mcp_operation_mode,
    }

    _MEMORY_AUDIT_LOG.append(entry)

    if settings.mcp_audit_enabled:
        try:
            log_path = Path(settings.mcp_audit_log_path).resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error("Falha ao gravar arquivo de auditoria: %s", e)

    return entry


def get_audit_history(limit: int = 50, tool_filter: str | None = None) -> list[dict[str, Any]]:
    """Recupera histórico recente de chamadas registradas em memória."""
    entries = list(_MEMORY_AUDIT_LOG)
    if tool_filter:
        entries = [e for e in entries if tool_filter.lower() in e["tool_name"].lower()]
    return entries[-limit:]
