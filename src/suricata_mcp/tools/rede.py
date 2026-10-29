"""Categoria C — Análise de rede e conexões (Ferramentas 21 a 30)."""

import time
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..eve_parser import (
    analyze_top_talkers,
    build_network_timeline,
    detect_network_scans,
    detect_suspicious_dns,
    summarize_events,
)
from ..eve_reader import tail_eve_events
from ..models import EventQueryFilter, MetadataEnvelope, StandardResponseEnvelope


@require_permission("somente_leitura")
def suricata_investigar_ip(ip: str, limite: int = 200) -> dict[str, Any]:
    """21. Correlaciona todos os alertas, fluxos e protocolos associados a um endereço IP específico."""
    start_time = time.perf_counter()
    # Busca tanto onde o IP é origem quanto destino
    q_src = EventQueryFilter(ip_origem=ip, limite=limite // 2)
    q_dst = EventQueryFilter(ip_destino=ip, limite=limite // 2)

    ev_src, _, _ = tail_eve_events(query_filter=q_src)
    ev_dst, _, _ = tail_eve_events(query_filter=q_dst)
    all_events = ev_src + ev_dst

    summary = summarize_events(all_events)
    alerts = [e for e in all_events if e.get("event_type") == "alert"]
    dns_queries = [e.get("dns", {}).get("rrname") for e in all_events if e.get("event_type") == "dns" and "dns" in e]

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "ip_investigado": ip,
        "total_eventos_observados": len(all_events),
        "total_alertas_gerados": len(alerts),
        "dominios_consultados": sorted(list(set(filter(None, dns_queries))))[:15],
        "resumo_atividades": summary,
        "amostra_alertas": alerts[:10],
    }

    record_audit_entry("suricata_investigar_ip", {"ip": ip, "limite": limite}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(all_events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_investigar_conexao(
    ip_origem: str,
    ip_destino: str,
    porta_origem: int | None = None,
    porta_destino: int | None = None,
    protocolo: str | None = None,
) -> dict[str, Any]:
    """22. Analisa uma conexão específica por 5-tuple ou par de IPs."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(
        ip_origem=ip_origem,
        ip_destino=ip_destino,
        porta_origem=porta_origem,
        porta_destino=porta_destino,
        protocolo=protocolo,
        limite=100,
    )
    events, _, _ = tail_eve_events(query_filter=q_filter)
    timeline = build_network_timeline(events)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "conexao": f"{ip_origem}:{porta_origem or '*'} -> {ip_destino}:{porta_destino or '*'}",
        "protocolo": protocolo or "QUALQUER",
        "total_eventos": len(events),
        "cronologia_conexao": timeline[:25],
    }

    record_audit_entry("suricata_investigar_conexao", q_filter.model_dump(), True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_identificar_ips_mais_ativos(top_n: int = 10, amostra: int = 1000) -> dict[str, Any]:
    """23. Classifica os endereços IP mais ativos por contagem de eventos e volume de tráfego."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=amostra)
    talkers = analyze_top_talkers(events, top_n=top_n)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_identificar_ips_mais_ativos", {"top_n": top_n, "amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=talkers,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_identificar_portas_mais_ativas(top_n: int = 10, amostra: int = 1000) -> dict[str, Any]:
    """24. Analisa a distribuição e ranking das portas TCP/UDP de origem e destino mais frequentes."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=amostra)
    talkers = analyze_top_talkers(events, top_n=top_n)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "top_portas_destino": talkers.get("top_portas_destino", []),
        "top_portas_origem": talkers.get("top_portas_origem", []),
    }

    record_audit_entry("suricata_identificar_portas_mais_ativas", {"top_n": top_n}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_protocolos(amostra: int = 1000) -> dict[str, Any]:
    """25. Analisa a divisão proporcional de protocolos de transporte e aplicação observados."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=amostra)
    summary = summarize_events(events)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "distribuicao_transporte": summary.get("distribuicao_protocolos", {}),
        "distribuicao_eventos": summary.get("distribuicao_tipos", {}),
        "total_eventos_analisados": len(events),
    }

    record_audit_entry("suricata_analisar_protocolos", {"amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_conexoes_suspeitas(limite: int = 50) -> dict[str, Any]:
    """26. Identifica padrões potencialmente suspeitos, como portas incomuns e proporções anômalas."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(limite=limite * 4)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    # Identifica conexões com alertas ou portas altas desconhecidas
    suspeitas = []
    for ev in events:
        dest_port = ev.get("dest_port", 0)
        proto = ev.get("proto", "")
        # Portas altas não padrão ou tráfego com alertas
        if ev.get("event_type") == "alert" or dest_port in (4444, 1337, 31337, 6667, 5555):
            suspeitas.append(
                {
                    "timestamp": ev.get("timestamp"),
                    "origem": f"{ev.get('src_ip')}:{ev.get('src_port')}",
                    "destino": f"{ev.get('dest_ip')}:{dest_port}",
                    "protocolo": proto,
                    "motivo": "Alerta gerado" if ev.get("event_type") == "alert" else "Porta de risco conhecido",
                    "detalhes": ev.get("alert", {}).get("signature", "Conexão em porta de administração/trojan"),
                }
            )

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_conexoes_suspeitas", {"limite": limite}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"conexoes_suspeitas": suspeitas[:limite], "total": len(suspeitas[:limite])},
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(suspeitas), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_detectar_varreduras_rede(limiar_portas: int = 10, amostra: int = 2000) -> dict[str, Any]:
    """27. Identifica origens compatíveis com varreduras de portas ou hosts (Portscan/Hostscan defensivo)."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=amostra)
    scans = detect_network_scans(events, threshold_ports=limiar_portas)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "limiar_portas": limiar_portas,
        "total_scanners_detectados": len(scans),
        "scanners": scans,
    }

    record_audit_entry("suricata_detectar_varreduras_rede", {"limiar": limiar_portas}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(scans), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_detectar_padroes_dns_suspeitos(amostra: int = 1000) -> dict[str, Any]:
    """28. Investiga padrões DNS potencialmente maliciosos, alta entropia (DGA) e tunelamento."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="dns", limite=amostra)
    events, _, _ = tail_eve_events(query_filter=q_filter)
    suspicious_dns = detect_suspicious_dns(events)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "total_consultas_analisadas": len(events),
        "total_suspeitas": len(suspicious_dns),
        "dominios_suspeitos": suspicious_dns,
    }

    record_audit_entry("suricata_detectar_padroes_dns_suspeitos", {"amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(suspicious_dns), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_sessoes_tls(amostra: int = 200) -> dict[str, Any]:
    """29. Analisa metadados TLS disponíveis, SNIs frequentes, versões e emissores."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="tls", limite=amostra)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    snis: dict[str, int] = {}
    versoes: dict[str, int] = {}

    for ev in events:
        tls = ev.get("tls", {})
        sni = tls.get("sni", "sem_sni")
        ver = tls.get("version", "desconhecida")
        snis[sni] = snis.get(sni, 0) + 1
        versoes[ver] = versoes.get(ver, 0) + 1

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "top_snis": sorted(snis.items(), key=lambda x: x[1], reverse=True)[:15],
        "distribuicao_versoes_tls": versoes,
        "total_sessoes_analisadas": len(events),
    }

    record_audit_entry("suricata_analisar_sessoes_tls", {"amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_gerar_linha_tempo_rede(ip: str | None = None, limite: int = 100) -> dict[str, Any]:
    """30. Organiza eventos relacionados cronologicamente para reconstrução defensiva de incidentes."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=limite * 2)
    timeline = build_network_timeline(events, target_ip=ip)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "filtro_ip": ip or "TODOS",
        "total_eventos_linha_tempo": len(timeline[:limite]),
        "eventos": timeline[:limite],
    }

    record_audit_entry("suricata_gerar_linha_tempo_rede", {"ip": ip, "limite": limite}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(timeline), fonte_dados="eve_json"),
    ).to_dict()
