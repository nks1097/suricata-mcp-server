"""Leitor incremental de alta performance para arquivos EVE JSON do Suricata."""

import json
import logging
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import get_settings
from .exceptions import SuricataEveNotFoundError
from .models import EventQueryFilter

logger = logging.getLogger("suricata_mcp.eve_reader")


def _parse_iso_datetime(dt_str: str) -> datetime | None:
    """Converte strings de data/hora em datetime com timezone."""
    if not dt_str:
        return None
    try:
        # Trata formato ISO padrão Suricata: '2026-10-29T14:30:00.123456+0000'
        cleaned = dt_str.replace("Z", "+00:00")
        if "+" in cleaned and len(cleaned.split("+")[-1]) == 4:
            # Converte +0000 para +00:00
            parts = cleaned.rsplit("+", 1)
            cleaned = f"{parts[0]}+{parts[1][:2]}:{parts[1][2:]}"
        return datetime.fromisoformat(cleaned)
    except Exception:
        try:
            return datetime.strptime(dt_str[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None


def match_event_filter(event: dict[str, Any], query_filter: EventQueryFilter) -> bool:
    """Avalia se um evento EVE JSON atende aos critérios do filtro especificado."""
    # 1. Filtro por tipo de evento
    if query_filter.tipo_evento and event.get("event_type") != query_filter.tipo_evento:
        return False

    # 2. Filtro por IP de origem
    if query_filter.ip_origem and event.get("src_ip") != query_filter.ip_origem:
        return False

    # 3. Filtro por IP de destino
    if query_filter.ip_destino and event.get("dest_ip") != query_filter.ip_destino:
        return False

    # 4. Filtro por Portas
    if query_filter.porta_origem is not None and event.get("src_port") != query_filter.porta_origem:
        return False
    if query_filter.porta_destino is not None and event.get("dest_port") != query_filter.porta_destino:
        return False

    # 5. Filtro por Protocolo de transporte
    if query_filter.protocolo:
        proto = str(event.get("proto", "")).upper()
        if proto != query_filter.protocolo.upper():
            return False

    # 6. Filtros específicos para Alertas
    if query_filter.severidade_max is not None:
        alert = event.get("alert")
        if not alert or alert.get("severity", 99) > query_filter.severidade_max:
            return False

    if query_filter.sid is not None:
        alert = event.get("alert")
        if not alert or alert.get("signature_id") != query_filter.sid:
            return False

    # 7. Filtro Temporal
    if query_filter.data_inicio or query_filter.data_fim:
        event_time_str = event.get("timestamp")
        if event_time_str:
            event_dt = _parse_iso_datetime(event_time_str)
            if event_dt:
                if query_filter.data_inicio:
                    dt_start = _parse_iso_datetime(query_filter.data_inicio)
                    if dt_start and event_dt < dt_start:
                        return False
                if query_filter.data_fim:
                    dt_end = _parse_iso_datetime(query_filter.data_fim)
                    if dt_end and event_dt > dt_end:
                        return False

    # 8. Busca textual livre em campos relevantes
    if query_filter.termo_busca:
        term = query_filter.termo_busca.lower()
        search_targets = [
            str(event.get("src_ip", "")),
            str(event.get("dest_ip", "")),
            str(event.get("app_proto", "")),
        ]
        if "alert" in event and isinstance(event["alert"], dict):
            search_targets.append(str(event["alert"].get("signature", "")))
            search_targets.append(str(event["alert"].get("category", "")))
        if "dns" in event and isinstance(event["dns"], dict):
            search_targets.append(str(event["dns"].get("rrname", "")))
            search_targets.append(str(event["dns"].get("rdata", "")))
        if "http" in event and isinstance(event["http"], dict):
            search_targets.append(str(event["http"].get("hostname", "")))
            search_targets.append(str(event["http"].get("url", "")))
        if "tls" in event and isinstance(event["tls"], dict):
            search_targets.append(str(event["tls"].get("sni", "")))
            search_targets.append(str(event["tls"].get("subject", "")))

        if not any(term in s.lower() for s in search_targets):
            return False

    return True


def tail_eve_events(
    eve_path: str | Path | None = None,
    query_filter: EventQueryFilter | None = None,
    max_results: int | None = None,
    chunk_size: int = 65536,
) -> tuple[list[dict[str, Any]], bool, int]:
    """Lê eficientemente os eventos mais recentes do final do arquivo EVE JSON sem carregá-lo todo na memória.

    Retorna: (eventos_encontrados, truncado, total_coletado).
    """
    settings = get_settings()
    path = Path(eve_path) if eve_path else settings.get_eve_path()

    if not path.is_file():
        raise SuricataEveNotFoundError(str(path))

    effective_filter = query_filter or EventQueryFilter()
    limit = max_results or effective_filter.limite or settings.suricata_max_results

    matched_events: list[dict[str, Any]] = []
    file_size = path.stat().st_size
    if file_size == 0:
        return [], False, 0

    with open(path, "rb") as f:
        buffer = bytearray()
        pos = file_size

        while pos > 0 and len(matched_events) < limit:
            read_size = min(chunk_size, pos)
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size)
            buffer = bytearray(chunk) + buffer

            lines = buffer.split(b"\n")
            # Deixa a primeira linha (possivelmente incompleta) no buffer caso não tenhamos chegado ao início do arquivo
            if pos > 0:
                buffer = lines[0]
                lines_to_process = lines[1:]
            else:
                lines_to_process = lines
                buffer = bytearray()

            # Processa as linhas em ordem reversa (mais recentes primeiro)
            for raw_line in reversed(lines_to_process):
                line_str = raw_line.strip()
                if not line_str:
                    continue
                try:
                    event = json.loads(line_str.decode("utf-8", errors="ignore"))
                    if match_event_filter(event, effective_filter):
                        matched_events.append(event)
                        if len(matched_events) >= limit:
                            break
                except Exception:
                    continue

    truncado = len(matched_events) >= limit
    return matched_events, truncado, len(matched_events)


def stream_eve_events(
    eve_path: str | Path | None = None,
    query_filter: EventQueryFilter | None = None,
) -> Generator[dict[str, Any], None, None]:
    """Gera eventos sequencialmente a partir do início do arquivo EVE com consumo mínimo de memória."""
    settings = get_settings()
    path = Path(eve_path) if eve_path else settings.get_eve_path()

    if not path.is_file():
        raise SuricataEveNotFoundError(str(path))

    effective_filter = query_filter or EventQueryFilter()

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
                if match_event_filter(event, effective_filter):
                    yield event
            except Exception:
                continue
