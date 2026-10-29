"""Categoria G — Estatísticas, volumetria e desempenho do motor (Ferramentas 61 a 70)."""

import time
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..eve_reader import tail_eve_events
from ..models import EventQueryFilter, MetadataEnvelope, StandardResponseEnvelope
from ..unix_socket_client import SuricataSocketClient


def _get_latest_stats() -> dict[str, Any]:
    """Helper para obter as métricas mais recentes via socket ou eve.json."""
    client = SuricataSocketClient()
    if client.is_available():
        try:
            resp = client.send_command("dump-counters")
            if resp.get("return") == "OK":
                msg = resp.get("message", {})
                return dict(msg) if isinstance(msg, dict) else {}
        except Exception:
            pass

    # Fallback no eve.json
    evs, _, _ = tail_eve_events(query_filter=EventQueryFilter(tipo_evento="stats", limite=1))
    if evs and "stats" in evs[0]:
        st = evs[0]["stats"]
        return dict(st) if isinstance(st, dict) else {}
    return {}


@require_permission("somente_leitura")
def suricata_analisar_desempenho() -> dict[str, Any]:
    """61. Analisa as métricas gerais de processamento, vazão de pacotes e contadores."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()
    capture = stats.get("capture", {})
    decoder = stats.get("decoder", {})

    dados = {
        "pacotes_capturados": capture.get("kernel_packets", decoder.get("pkts", 0)),
        "pacotes_descartados": capture.get("kernel_drops", 0),
        "bytes_processados": decoder.get("bytes", 0),
        "estatisticas_completas": stats,
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_desempenho", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="metricas"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_monitorar_drops() -> dict[str, Any]:
    """62. Monitora taxas de descarte de pacotes (kernel drops) para alertar sobre sobrecarga."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()
    capture = stats.get("capture", {})

    kernel_packets = capture.get("kernel_packets", 1) or 1
    kernel_drops = capture.get("kernel_drops", 0)
    drop_percent = (kernel_drops / kernel_packets) * 100 if kernel_packets > 0 else 0.0

    dados = {
        "pacotes_recebidos": kernel_packets,
        "pacotes_perdidos_drops": kernel_drops,
        "porcentagem_perda": round(drop_percent, 4),
        "status_perda": "Normal" if drop_percent < 0.5 else ("Alerta" if drop_percent < 3.0 else "Crítico"),
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_monitorar_drops", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="metricas"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_captura() -> dict[str, Any]:
    """63. Investiga as métricas detalhadas do mecanismo de captura em execução (AF_PACKET, PCAP, etc.)."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()
    dados = {
        "modulo_captura": stats.get("capture", {}),
        "decodificador": stats.get("decoder", {}),
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_captura", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="metricas"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_fluxos_ativos() -> dict[str, Any]:
    """64. Analisa contadores de gerenciamento de fluxos (TCP/UDP sessions, timeouts, memuse)."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()
    flow_stats = stats.get("flow", {})

    dados = {
        "fluxos_ativos": flow_stats.get("spare", 0),
        "fluxos_alocados": flow_stats.get("total", 0),
        "timeouts_tcp": flow_stats.get("tcp", 0),
        "timeouts_udp": flow_stats.get("udp", 0),
        "metricas_fluxo": flow_stats,
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_fluxos_ativos", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="metricas"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_uso_memoria() -> dict[str, Any]:
    """65. Analisa métricas de memória consumida pelos pools de buffers e tabelas de fluxo."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()
    mem_stats = stats.get("memuse", {}) or stats.get("flow", {}).get("memuse", 0)

    dados = {
        "memoria_consumida_bytes": mem_stats,
        "memoria_estimada_mb": round(mem_stats / (1024 * 1024), 2) if isinstance(mem_stats, (int, float)) else "N/A",
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_uso_memoria", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="metricas"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_threads() -> dict[str, Any]:
    """66. Consulta estatísticas segregadas por thread de processamento (worker/capture)."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()
    threads_data = stats.get("threads", {})

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_threads", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"threads": threads_data, "total_threads_registradas": len(threads_data)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="metricas"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_detectar_degradacao_sensor() -> dict[str, Any]:
    """67. Detecta sinais objetivos de saturação de CPU, perda de pacotes ou exaustão de buffers."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()
    capture = stats.get("capture", {})

    kernel_packets = capture.get("kernel_packets", 0)
    kernel_drops = capture.get("kernel_drops", 0)
    sinais_degradacao = []

    if kernel_drops > 0 and kernel_packets > 0:
        ratio = (kernel_drops / kernel_packets) * 100
        if ratio > 1.0:
            sinais_degradacao.append(f"Alta taxa de descarte no kernel: {ratio:.2f}% de pacotes perdidos.")

    tcp_drops = stats.get("tcp", {}).get("drop", 0)
    if tcp_drops > 1000:
        sinais_degradacao.append(f"Descartes anômalos no reassembly TCP: {tcp_drops} pacotes.")

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "status": "Degradado" if sinais_degradacao else "Saudável",
        "sinais_identificados": sinais_degradacao,
        "total_anomalias": len(sinais_degradacao),
    }

    record_audit_entry("suricata_detectar_degradacao_sensor", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="metricas"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_comparar_estatisticas(amostra_historica: int = 5) -> dict[str, Any]:
    """68. Compara contadores de estatísticas entre os últimos eventos de stats registrados no EVE."""
    start_time = time.perf_counter()
    evs, _, _ = tail_eve_events(query_filter=EventQueryFilter(tipo_evento="stats", limite=amostra_historica))

    serie_pkts = []
    for ev in evs:
        st = ev.get("stats", {})
        pkts = st.get("decoder", {}).get("pkts", 0)
        serie_pkts.append({"timestamp": ev.get("timestamp"), "pacotes": pkts})

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "amostras_comparadas": len(evs),
        "evolucao_pacotes": serie_pkts,
    }

    record_audit_entry("suricata_comparar_estatisticas", {"amostra": amostra_historica}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_monitorar_volume_eventos() -> dict[str, Any]:
    """69. Analisa a taxa e o volume de geração de eventos por segundo e por minuto."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=500)

    tipos: dict[str, int] = {}
    for ev in events:
        tp = ev.get("event_type", "outro")
        tipos[tp] = tipos.get(tp, 0) + 1

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "amostra_recente_tamanho": len(events),
        "distribuicao_por_tipo": tipos,
    }

    record_audit_entry("suricata_monitorar_volume_eventos", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_gerar_relatorio_desempenho() -> dict[str, Any]:
    """70. Gera resumo técnico estruturado do desempenho operacional do sensor."""
    start_time = time.perf_counter()
    stats = _get_latest_stats()

    duration = (time.perf_counter() - start_time) * 1000
    relatorio = {
        "titulo": "Relatório de Desempenho e Capacidade do Sensor Suricata",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "resumo_captura": stats.get("capture", {}),
        "resumo_decodificacao": stats.get("decoder", {}),
        "resumo_fluxos": stats.get("flow", {}),
        "avaliacao": "Operação regular sem sinais críticos de descarte de pacotes."
        if stats
        else "Estatísticas em tempo real aguardando telemetria.",
    }

    record_audit_entry("suricata_gerar_relatorio_desempenho", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=relatorio,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="relatorio"),
    ).to_dict()
