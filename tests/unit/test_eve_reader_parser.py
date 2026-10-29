"""Testes unitários para o leitor e agregador de eventos EVE JSON."""

from suricata_mcp.eve_parser import (
    analyze_top_talkers,
    build_network_timeline,
    calculate_shannon_entropy,
    detect_suspicious_dns,
    summarize_events,
)
from suricata_mcp.eve_reader import stream_eve_events, tail_eve_events
from suricata_mcp.models import EventQueryFilter


def test_calculate_shannon_entropy() -> None:
    """Valida o cálculo de entropia para detecção de DGAs."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaa") == 0.0
    high_entropy = calculate_shannon_entropy("xjq78ab19zm204klmn9921bvaq")
    assert high_entropy > 3.5


def test_tail_eve_events_unfiltered() -> None:
    """Verifica a leitura reversa do arquivo EVE de fixture."""
    events, truncado, total = tail_eve_events(max_results=50)
    assert len(events) > 0
    assert total == len(events)
    assert not truncado


def test_tail_eve_events_filter_alert() -> None:
    """Verifica filtro por tipo de evento e SID."""
    q_filter = EventQueryFilter(tipo_evento="alert", sid=2100498)
    events, _, _ = tail_eve_events(query_filter=q_filter)
    assert len(events) == 1
    assert events[0]["alert"]["signature_id"] == 2100498
    assert "log4j" in events[0]["alert"]["signature"].lower()


def test_tail_eve_events_filter_ip() -> None:
    """Verifica filtro por IP de origem."""
    q_filter = EventQueryFilter(ip_origem="203.0.113.55")
    events, _, _ = tail_eve_events(query_filter=q_filter)
    assert len(events) >= 2
    assert all(e["src_ip"] == "203.0.113.55" for e in events)


def test_stream_eve_events() -> None:
    """Verifica gerador sequencial de eventos."""
    events = list(stream_eve_events())
    assert len(events) >= 10
    event_types = {e.get("event_type") for e in events}
    assert "alert" in event_types
    assert "dns" in event_types
    assert "http" in event_types


def test_summarize_and_analysis_helpers() -> None:
    """Verifica helpers de agregação analítica."""
    events, _, _ = tail_eve_events(max_results=100)
    summary = summarize_events(events)
    assert summary["total_eventos"] == len(events)
    assert "alertas_por_severidade" in summary

    talkers = analyze_top_talkers(events)
    assert "top_ips_origem" in talkers
    assert "top_portas_destino" in talkers

    suspicious_dns = detect_suspicious_dns(events)
    assert len(suspicious_dns) >= 1
    assert "xjq78ab19zm204klmn9921bvaq.biz" in [d["dominio"] for d in suspicious_dns]

    timeline = build_network_timeline(events)
    assert len(timeline) == len(events)
