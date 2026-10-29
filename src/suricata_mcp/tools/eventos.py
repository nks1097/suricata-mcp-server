"""Categoria B — Eventos EVE e pesquisa de telemetria (Ferramentas 11 a 20)."""

import time
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..eve_parser import summarize_events
from ..eve_reader import tail_eve_events
from ..models import EventQueryFilter, MetadataEnvelope, StandardResponseEnvelope


@require_permission("somente_leitura")
def suricata_pesquisar_eventos(
    tipo_evento: str | None = None,
    ip_origem: str | None = None,
    ip_destino: str | None = None,
    porta_origem: int | None = None,
    porta_destino: int | None = None,
    protocolo: str | None = None,
    termo_busca: str | None = None,
    data_inicio: str | None = None,
    data_fim: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """11. Pesquisa eventos arbitrários no EVE JSON aplicando filtros compostos e limites."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(
        tipo_evento=tipo_evento,
        ip_origem=ip_origem,
        ip_destino=ip_destino,
        porta_origem=porta_origem,
        porta_destino=porta_destino,
        protocolo=protocolo,
        termo_busca=termo_busca,
        data_inicio=data_inicio,
        data_fim=data_fim,
        limite=limite,
    )

    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_pesquisar_eventos", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"eventos": events, "total_retornado": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_alertas(
    severidade_max: int | None = None,
    sid: int | None = None,
    ip_origem: str | None = None,
    ip_destino: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """12. Recupera alertas de segurança (event_type: 'alert') registrados pelo Suricata."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(
        tipo_evento="alert",
        severidade_max=severidade_max,
        sid=sid,
        ip_origem=ip_origem,
        ip_destino=ip_destino,
        limite=limite,
    )

    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_alertas", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"alertas": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_eventos_fluxo(
    ip_origem: str | None = None,
    ip_destino: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """13. Consulta registros de fluxos de rede (event_type: 'flow') e estatísticas de pacotes/bytes."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="flow", ip_origem=ip_origem, ip_destino=ip_destino, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_eventos_fluxo", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"fluxos": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_eventos_dns(
    termo_busca_dominio: str | None = None,
    ip_origem: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """14. Consulta eventos de resolução DNS (event_type: 'dns'), consultas e respostas."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="dns", ip_origem=ip_origem, termo_busca=termo_busca_dominio, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_eventos_dns", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"eventos_dns": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_eventos_http(
    termo_url_ou_host: str | None = None,
    ip_origem: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """15. Consulta eventos de transações HTTP (event_type: 'http'), hosts, métodos e URLs."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="http", ip_origem=ip_origem, termo_busca=termo_url_ou_host, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_eventos_http", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"eventos_http": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_eventos_tls(
    sni: str | None = None,
    ip_origem: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """16. Consulta eventos de sessões criptografadas TLS/SSL (event_type: 'tls'), SNI e certificados."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="tls", ip_origem=ip_origem, termo_busca=sni, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_eventos_tls", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"eventos_tls": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_anomalias(
    ip_origem: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """17. Consulta anomalias de protocolo e pacotes malformados (event_type: 'anomaly')."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="anomaly", ip_origem=ip_origem, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_anomalias", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"anomalias": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_eventos_arquivos(
    nome_arquivo: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """18. Consulta arquivos identificados e extraídos pelo motor (event_type: 'fileinfo')."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="fileinfo", termo_busca=nome_arquivo, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_eventos_arquivos", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"arquivos_detectados": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_eventos_ssh(
    ip_origem: str | None = None,
    limite: int = 100,
) -> dict[str, Any]:
    """19. Consulta eventos e metadados de conexões SSH observadas (event_type: 'ssh')."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="ssh", ip_origem=ip_origem, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_consultar_eventos_ssh", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"eventos_ssh": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_obter_resumo_eventos(amostra_eventos: int = 1000) -> dict[str, Any]:
    """20. Consolida contagens, volumetria e distribuições por tipo, IP e protocolo."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=amostra_eventos)
    summary = summarize_events(events)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_obter_resumo_eventos", {"amostra_eventos": amostra_eventos}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=summary,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()
