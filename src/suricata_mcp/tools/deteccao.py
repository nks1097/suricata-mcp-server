"""Categoria D — Alertas e engenharia de detecção (Ferramentas 31 a 40)."""

import time
from collections import Counter
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..eve_reader import tail_eve_events
from ..models import EventQueryFilter, MetadataEnvelope, StandardResponseEnvelope


@require_permission("somente_leitura")
def suricata_obter_alerta(sid: int | None = None, limite: int = 1) -> dict[str, Any]:
    """31. Recupera os detalhes completos do alerta mais recente ou correspondente ao SID."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", sid=sid, limite=limite)
    events, _, _ = tail_eve_events(query_filter=q_filter, max_results=limite)

    duration = (time.perf_counter() - start_time) * 1000
    alerta = events[0] if events else None

    record_audit_entry("suricata_obter_alerta", {"sid": sid}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"alerta": alerta, "encontrado": bool(alerta)},
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_filtrar_alertas_por_severidade(severidade: int, limite: int = 100) -> dict[str, Any]:
    """32. Filtra alertas por nível de severidade (1=Crítico, 2=Alto, 3=Médio, 4=Info)."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", severidade_max=severidade, limite=limite)
    events, truncado, total = tail_eve_events(query_filter=q_filter, max_results=limite)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_filtrar_alertas_por_severidade", {"severidade": severidade}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"severidade_consultada": severidade, "alertas": events, "total": len(events)},
        metadados=MetadataEnvelope(
            duracao_ms=duration, truncado=truncado, total_encontrado=total, fonte_dados="eve_json"
        ),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_agrupar_alertas_por_assinatura(amostra: int = 500) -> dict[str, Any]:
    """33. Agrupa e conta alertas por assinatura (nome da regra) e SID."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", limite=amostra)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    grupos: dict[str, dict[str, Any]] = {}
    for ev in events:
        al = ev.get("alert", {})
        sig = al.get("signature", "Desconhecido")
        sid = al.get("signature_id", 0)
        sev = al.get("severity", 3)

        key = f"{sig} (SID: {sid})"
        if key not in grupos:
            grupos[key] = {
                "assinatura": sig,
                "sid": sid,
                "severidade": sev,
                "contagem": 0,
                "categoria": al.get("category", "Geral"),
                "ultimas_origens": set(),
            }
        grupos[key]["contagem"] += 1
        if "src_ip" in ev:
            grupos[key]["ultimas_origens"].add(ev["src_ip"])

    resultado = [
        {
            "assinatura": v["assinatura"],
            "sid": v["sid"],
            "severidade": v["severidade"],
            "contagem": v["contagem"],
            "categoria": v["categoria"],
            "origens_distintas": len(v["ultimas_origens"]),
        }
        for v in grupos.values()
    ]
    resultado.sort(key=lambda x: x["contagem"], reverse=True)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_agrupar_alertas_por_assinatura", {"amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"grupos_assinaturas": resultado, "total_grupos": len(resultado)},
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_analisar_frequencia_alertas(amostra: int = 1000) -> dict[str, Any]:
    """34. Identifica a frequência e recorrência temporal de disparo de alertas."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", limite=amostra)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    frequencia_hora: Counter = Counter()
    for ev in events:
        ts = str(ev.get("timestamp", ""))
        if len(ts) >= 13:
            hora = ts[:13]  # YYYY-MM-DDTHH
            frequencia_hora[hora] += 1

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "distribuicao_por_hora": dict(sorted(frequencia_hora.items())),
        "total_alertas_analisados": len(events),
    }

    record_audit_entry("suricata_analisar_frequencia_alertas", {"amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_detectar_picos_alertas(limiar_pico: int = 50, amostra: int = 1000) -> dict[str, Any]:
    """35. Detecta anomalias de volumetria e picos anormais de alertas em intervalos temporais."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", limite=amostra)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    frequencia_minuto: Counter = Counter()
    for ev in events:
        ts = str(ev.get("timestamp", ""))
        if len(ts) >= 16:
            minuto = ts[:16]  # YYYY-MM-DDTHH:MM
            frequencia_minuto[minuto] += 1

    picos = [
        {"minuto": k, "alertas_no_minuto": v, "excedente": v - limiar_pico}
        for k, v in frequencia_minuto.items()
        if v >= limiar_pico
    ]
    picos.sort(key=lambda x: x["alertas_no_minuto"], reverse=True)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "limiar_configurado": limiar_pico,
        "picos_detectados": picos,
        "total_picos": len(picos),
    }

    record_audit_entry("suricata_detectar_picos_alertas", {"limiar": limiar_pico}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_correlacionar_alertas(ip_alvo: str, janela_eventos: int = 500) -> dict[str, Any]:
    """36. Correlaciona múltiplos alertas disparados pelo mesmo ator ou contra o mesmo alvo."""
    start_time = time.perf_counter()
    q_src = EventQueryFilter(tipo_evento="alert", ip_origem=ip_alvo, limite=janela_eventos // 2)
    q_dst = EventQueryFilter(tipo_evento="alert", ip_destino=ip_alvo, limite=janela_eventos // 2)

    ev_src, _, _ = tail_eve_events(query_filter=q_src)
    ev_dst, _, _ = tail_eve_events(query_filter=q_dst)
    all_alerts = ev_src + ev_dst

    sids: Counter = Counter()
    categorias: Counter = Counter()
    alvos_tocados: set[str] = set()

    for ev in all_alerts:
        al = ev.get("alert", {})
        sids[al.get("signature_id")] += 1
        categorias[al.get("category", "Sem Categoria")] += 1
        if "dest_ip" in ev:
            alvos_tocados.add(ev["dest_ip"])

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "ip_correlacionado": ip_alvo,
        "total_alertas_vinculados": len(all_alerts),
        "sids_disparados": dict(sids.most_common(10)),
        "categorias_ameaca": dict(categorias.most_common(5)),
        "alvos_impactados": sorted(list(alvos_tocados))[:10],
    }

    record_audit_entry("suricata_correlacionar_alertas", {"ip": ip_alvo}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(all_alerts), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_investigar_indicador_comprometimento(ioc_valor: str, tipo_ioc: str = "auto") -> dict[str, Any]:
    """37. Pesquisa um IoC específico (IP, domínio, hash MD5/SHA256) em toda a telemetria do Suricata."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(termo_busca=ioc_valor, limite=100)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "ioc": ioc_valor,
        "tipo": tipo_ioc,
        "encontrado": len(events) > 0,
        "ocorrencias": len(events),
        "eventos_relacionados": events[:15],
    }

    record_audit_entry("suricata_investigar_indicador_comprometimento", {"ioc": ioc_valor}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_classificar_incidente(ip_suspeito: str) -> dict[str, Any]:
    """38. Sugere classificação defensiva fundamentada com severidade e nível de confiança."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(ip_origem=ip_suspeito, limite=100)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    alerts = [e for e in events if e.get("event_type") == "alert"]
    sev_critica = any(e.get("alert", {}).get("severity") == 1 for e in alerts)

    classificacao = "Atividade Normal"
    confianca = "Baixa"
    severidade = "Baixa"

    if len(alerts) > 10 or sev_critica:
        classificacao = "Incidente de Segurança Provável"
        confianca = "Alta" if sev_critica else "Média"
        severidade = "Crítica" if sev_critica else "Alta"
    elif alerts:
        classificacao = "Alerta Isolado em Análise"
        confianca = "Média"
        severidade = "Média"

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "ip": ip_suspeito,
        "classificacao_sugerida": classificacao,
        "severidade": severidade,
        "nivel_confianca": confianca,
        "evidencias_alertas": len(alerts),
        "total_eventos": len(events),
    }

    record_audit_entry("suricata_classificar_incidente", {"ip": ip_suspeito}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_identificar_falsos_positivos_candidatos(min_ocorrencias: int = 20) -> dict[str, Any]:
    """39. Identifica assinaturas hiperativas candidatas a falso positivo para revisão humana qualificada."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", limite=1000)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    assinaturas: Counter = Counter()
    for ev in events:
        al = ev.get("alert", {})
        sig = f"{al.get('signature', 'Desconhecido')} (SID: {al.get('signature_id')})"
        assinaturas[sig] += 1

    candidatos = [
        {"assinatura": k, "disparos": v, "motivo": "Volume desproporcional de alertas recorrentes"}
        for k, v in assinaturas.items()
        if v >= min_ocorrencias
    ]

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "criterio_min_disparos": min_ocorrencias,
        "total_candidatos": len(candidatos),
        "candidatos_para_revisao": candidatos,
    }

    record_audit_entry("suricata_identificar_falsos_positivos_candidatos", {"min": min_ocorrencias}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        avisos=["Nunca desative regras sem homologação e validação técnica do ambiente de rede."],
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(candidatos), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_gerar_relatorio_investigacao(ip: str) -> dict[str, Any]:
    """40. Gera um dossiê técnico estruturado de investigação sobre um endereço IP investigado."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(ip_origem=ip, limite=200)
    events, _, _ = tail_eve_events(query_filter=q_filter)
    alerts = [e for e in events if e.get("event_type") == "alert"]

    duration = (time.perf_counter() - start_time) * 1000
    dossie = {
        "ip_alvo": ip,
        "resumo_executivo": f"Investigação forense defensiva gerada para o IP {ip} com base em {len(events)} eventos.",
        "alertas_criticos": len([a for a in alerts if a.get("alert", {}).get("severity") == 1]),
        "total_alertas": len(alerts),
        "amostra_evidencias": alerts[:10],
    }

    record_audit_entry("suricata_gerar_relatorio_investigacao", {"ip": ip}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dossie,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(events), fonte_dados="eve_json"),
    ).to_dict()
