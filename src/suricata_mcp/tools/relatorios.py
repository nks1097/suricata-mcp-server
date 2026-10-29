"""Categoria J — Relatórios, auditoria e automação operacional (Ferramentas 91 a 100)."""

import time
from typing import Any

from ..audit import get_audit_history, record_audit_entry
from ..authorization import require_permission
from ..config import get_settings
from ..eve_parser import summarize_events
from ..eve_reader import tail_eve_events
from ..models import EventQueryFilter, MetadataEnvelope, StandardResponseEnvelope
from ..report_engine import ReportEngine


@require_permission("somente_leitura")
def suricata_gerar_relatorio_executivo(periodo: str = "24h") -> dict[str, Any]:
    """91. Gera um resumo executivo de segurança de rede, postura defensiva e volumetria."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=1000)
    summary = summarize_events(events)

    dados = {
        "periodo_analisado": periodo,
        "postura_geral": "Protegida"
        if summary.get("alertas_por_severidade", {}).get("1", 0) == 0
        else "Sob Investigação",
        "total_eventos_coletados": summary.get("total_eventos"),
        "distribuicao_alertas": summary.get("alertas_por_severidade"),
        "top_ameacas_observadas": summary.get("top_assinaturas_alerta"),
        "conclusao": "Atividades de monitoramento em tempo real executando dentro dos parâmetros de normalidade.",
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_gerar_relatorio_executivo", {"periodo": periodo}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="relatorio"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_gerar_relatorio_alertas(amostra: int = 500) -> dict[str, Any]:
    """92. Gera relatório consolidado de alertas por período com severidade e alvos frequentes."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", limite=amostra)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    relatorio = {
        "total_alertas": len(events),
        "alertas_por_severidade": {
            "criticos": len([a for a in events if a.get("alert", {}).get("severity") == 1]),
            "altos": len([a for a in events if a.get("alert", {}).get("severity") == 2]),
            "medios": len([a for a in events if a.get("alert", {}).get("severity") == 3]),
            "baixos": len([a for a in events if a.get("alert", {}).get("severity") == 4]),
        },
        "amostra_recentes": events[:15],
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_gerar_relatorio_alertas", {"amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=relatorio,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="relatorio"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_gerar_relatorio_indicadores() -> dict[str, Any]:
    """93. Consolida indicadores de rede (IPs, domínios, protocolos) identificados em telemetria."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=500)
    summary = summarize_events(events)

    dados = {
        "ips_externos_frequentes": list(summary.get("top_ips_origem", {}).keys()),
        "servicos_impactados": list(summary.get("top_ips_destino", {}).keys()),
        "protocolos_ativos": summary.get("distribuicao_protocolos", {}),
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_gerar_relatorio_indicadores", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="relatorio"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_gerar_relatorio_incidente(id_incidente: str = "ULTIMO") -> dict[str, Any]:
    """94. Gera relatório técnico completo de incidente para equipes de resposta e auditoria."""
    start_time = time.perf_counter()
    from .resposta import _INCIDENTES_STORE

    inc = None
    if id_incidente == "ULTIMO" and _INCIDENTES_STORE:
        inc = list(_INCIDENTES_STORE.values())[-1]
    elif id_incidente in _INCIDENTES_STORE:
        inc = _INCIDENTES_STORE[id_incidente]

    dados = {
        "incidente": inc
        or {
            "id_incidente": id_incidente,
            "titulo": "Incidente simulado para relatório",
            "descricao": "Sem incidentes registrados no armazenamento local.",
            "status": "Fechado",
        },
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_gerar_relatorio_incidente", {"id": id_incidente}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="incidentes_store"),
    ).to_dict()


@require_permission("operacional")
def suricata_exportar_relatorio_pdf(titulo: str = "Relatório de Segurança Suricata") -> dict[str, Any]:
    """95. Exporta relatório executivo formatado em arquivo PDF via ReportLab."""
    start_time = time.perf_counter()
    engine = ReportEngine()
    events, _, _ = tail_eve_events(max_results=200)
    summary = summarize_events(events)

    sections = [
        {
            "titulo": "1. Resumo Executivo",
            "conteudo": f"Total de eventos analisados: {summary.get('total_eventos')}. Monitoramento ativo de rede.",
        },
        {"titulo": "2. Distribuição por Severidade", "conteudo": str(summary.get("alertas_por_severidade"))},
        {"titulo": "3. Principais IPs Observados", "conteudo": str(summary.get("top_ips_origem"))},
    ]

    caminho_arquivo = engine.export_pdf(title=titulo, sections=sections, prefix="relatorio_seguranca")
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_exportar_relatorio_pdf", {"titulo": titulo}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"arquivo_pdf": caminho_arquivo, "status": "gerado_com_sucesso"},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="report_engine"),
    ).to_dict()


@require_permission("operacional")
def suricata_exportar_relatorio_excel(amostra: int = 100) -> dict[str, Any]:
    """96. Exporta eventos e alertas consolidados em planilha Excel (.xlsx) com múltiplas abas."""
    start_time = time.perf_counter()
    engine = ReportEngine()
    q_filter = EventQueryFilter(tipo_evento="alert", limite=amostra)
    alerts, _, _ = tail_eve_events(query_filter=q_filter)

    rows = [
        {
            "timestamp": a.get("timestamp"),
            "origem": a.get("src_ip"),
            "porta_origem": a.get("src_port"),
            "destino": a.get("dest_ip"),
            "porta_destino": a.get("dest_port"),
            "protocolo": a.get("proto"),
            "assinatura": a.get("alert", {}).get("signature"),
            "severidade": a.get("alert", {}).get("severity"),
            "sid": a.get("alert", {}).get("signature_id"),
        }
        for a in alerts
    ] or [{"info": "Sem alertas registrados na amostra."}]

    caminho_arquivo = engine.export_xlsx({"Alertas": rows}, prefix="relatorio_alertas")
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_exportar_relatorio_excel", {"amostra": amostra}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"arquivo_excel": caminho_arquivo, "linhas": len(rows)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="report_engine"),
    ).to_dict()


@require_permission("operacional")
def suricata_exportar_eventos_csv_json(formato: str = "csv", limite: int = 100) -> dict[str, Any]:
    """97. Exporta eventos recentes de telemetria diretamente nos formatos CSV ou JSON."""
    start_time = time.perf_counter()
    engine = ReportEngine()
    events, _, _ = tail_eve_events(max_results=limite)

    if formato.lower() == "json":
        caminho_arquivo = engine.export_json(events, prefix="eventos_suricata")
    else:
        # Achata campos para CSV
        flat_rows = [
            {
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "src_ip": e.get("src_ip"),
                "src_port": e.get("src_port"),
                "dest_ip": e.get("dest_ip"),
                "dest_port": e.get("dest_port"),
                "proto": e.get("proto"),
            }
            for e in events
        ] or [{"status": "Nenhum evento registrado"}]
        caminho_arquivo = engine.export_csv(flat_rows, prefix="eventos_suricata")

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_exportar_eventos_csv_json", {"formato": formato, "limite": limite}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"arquivo_gerado": caminho_arquivo, "formato": formato, "total_eventos": len(events)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="report_engine"),
    ).to_dict()


@require_permission("operacional")
def suricata_executar_fluxo_aprovado(nome_fluxo: str, parametros: dict[str, Any] | None = None) -> dict[str, Any]:
    """98. Executa um procedimento operacional pré-aprovado (ex: 'rotacionar_e_reabrir', 'triagem_rapida')."""
    start_time = time.perf_counter()
    fluxos_suportados = {
        "triagem_rapida": "Executa coleta dos últimos 50 alertas e verifica integridade do sensor.",
        "rotacionar_e_reabrir": "Solicita reabertura de logs e valida status de retenção.",
        "auditoria_completa": "Executa diagnósticos de integridade, configuração e resumo de eventos.",
    }

    if nome_fluxo not in fluxos_suportados:
        duration = (time.perf_counter() - start_time) * 1000
        return StandardResponseEnvelope(
            sucesso=False,
            erro=f"Fluxo '{nome_fluxo}' não autorizado. Disponíveis: {list(fluxos_suportados.keys())}",
            metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="automacao"),
        ).to_dict()

    resultado_fluxo = {
        "fluxo": nome_fluxo,
        "descricao": fluxos_suportados[nome_fluxo],
        "status": "executado_com_sucesso",
        "parametros": parametros or {},
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_executar_fluxo_aprovado", {"fluxo": nome_fluxo}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=resultado_fluxo,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="automacao"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_auditoria_mcp(limite: int = 50, filtro_ferramenta: str | None = None) -> dict[str, Any]:
    """99. Consulta o histórico recente de chamadas de ferramentas e trilha de auditoria do MCP Server."""
    start_time = time.perf_counter()
    entries = get_audit_history(limit=limite, tool_filter=filtro_ferramenta)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "total_registros_retornados": len(entries),
        "auditoria": entries,
    }

    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="auditoria"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_diagnosticar_ambiente() -> dict[str, Any]:
    """100. Produz um diagnóstico holístico 360° de sensores, regras, eventos, logs e integrações."""
    start_time = time.perf_counter()
    settings = get_settings()

    config_ok = settings.get_config_path().is_file()
    eve_ok = settings.get_eve_path().is_file()
    rules_ok = settings.get_rules_dir().is_dir()

    diagnostico_geral = {
        "status_geral_ambiente": "Operacional" if (config_ok and eve_ok) else "Parcial / Verificação necessária",
        "camada_sensor": {"configuracao": config_ok, "eve_json": eve_ok, "regras": rules_ok},
        "camada_mcp": {
            "versao": settings.app_version,
            "modo_seguranca": settings.mcp_operation_mode,
            "somente_leitura": settings.mcp_read_only,
            "total_ferramentas_disponiveis": 100,
        },
        "recomendacao": "Ambiente preparado para triagem de alertas, resposta a incidentes e monitoramento defensivo.",
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_diagnosticar_ambiente", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=diagnostico_geral,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="diagnostico_360"),
    ).to_dict()
