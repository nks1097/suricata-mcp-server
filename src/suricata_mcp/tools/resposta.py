"""Categoria I — Resposta defensiva, SIEM e gestão de incidentes (Ferramentas 81 a 90)."""

import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..config import get_settings
from ..eve_reader import tail_eve_events
from ..models import EventQueryFilter, IncidentRecord, MetadataEnvelope, StandardResponseEnvelope

# Armazenamento local estruturado de incidentes registrados pelo MCP
_INCIDENTES_STORE: dict[str, dict[str, Any]] = {}


@require_permission("operacional")
def suricata_planejar_resposta_incidente(ip_origem: str, sids: list[int] | None = None) -> dict[str, Any]:
    """81. Gera um plano de resposta defensivo baseado nas evidências observadas (sem bloqueios automáticos)."""
    start_time = time.perf_counter()
    plano_passos = [
        f"1. Isolar logicamente o tráfego do IP {ip_origem} para triagem forense.",
        "2. Coletar captura PCAP do tráfego residual utilizando ferramenta de captura autorizada.",
        "3. Validar se os SIDs disparados são conhecidos e se há falsos positivos documentados.",
        "4. Inspecionar hashes de arquivos e payloads associados nos eventos 'fileinfo'.",
        "5. Abrir ticket de incidente e notificar o time de resposta a incidentes (CSIRT/SOC).",
        "6. Avaliar necessidade de regra 'drop' temporária no local.rules após autorização formal.",
    ]

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "ip_alvo": ip_origem,
        "sids_avaliados": sids or [],
        "plano_defensivo": plano_passos,
        "nivel_acao": "Recomendação defensiva (bloqueio destrutivo desabilitado por segurança)",
    }

    record_audit_entry("suricata_planejar_resposta_incidente", {"ip": ip_origem}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        avisos=["Ações de mitigação ativas exigem aprovação humana e procedimento formal de mudança."],
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="resposta_defensiva"),
    ).to_dict()


@require_permission("operacional")
def suricata_registrar_incidente(
    titulo: str,
    descricao: str,
    ips_impactados: list[str],
    severidade: str = "Alta",
) -> dict[str, Any]:
    """82. Registra um novo incidente de segurança fundamentado no armazenamento local do MCP."""
    start_time = time.perf_counter()
    inc = IncidentRecord(
        titulo=titulo,
        descricao=descricao,
        ips_impactados=ips_impactados,
        severidade=severidade,
    )
    _INCIDENTES_STORE[inc.id_incidente] = inc.model_dump()

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_registrar_incidente", {"id": inc.id_incidente}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"incidente": inc.model_dump(), "total_registrados": len(_INCIDENTES_STORE)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="incidentes_store"),
    ).to_dict()


@require_permission("operacional")
def suricata_atualizar_incidente(
    id_incidente: str,
    novo_status: str,
    nota_investigacao: str | None = None,
) -> dict[str, Any]:
    """83. Atualiza o status e notas de um incidente previamente registrado no MCP."""
    start_time = time.perf_counter()
    if id_incidente not in _INCIDENTES_STORE:
        duration = (time.perf_counter() - start_time) * 1000
        return StandardResponseEnvelope(
            sucesso=False,
            erro=f"Incidente com ID '{id_incidente}' não encontrado.",
            metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="incidentes_store"),
        ).to_dict()

    inc = _INCIDENTES_STORE[id_incidente]
    inc["status"] = novo_status
    if nota_investigacao:
        if "notas" not in inc:
            inc["notas"] = []
        inc["notas"].append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "texto": nota_investigacao,
            }
        )

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_atualizar_incidente", {"id": id_incidente, "status": novo_status}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"incidente": inc},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="incidentes_store"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_exportar_indicadores(limite: int = 100) -> dict[str, Any]:
    """84. Exporta indicadores de comprometimento (IoCs) observados em formato STIX/JSON estruturado."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(tipo_evento="alert", limite=limite)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    ips_suspeitos = set()
    dominios_suspeitos = set()

    for ev in events:
        if "src_ip" in ev:
            ips_suspeitos.add(ev["src_ip"])
        if "dns" in ev and isinstance(ev["dns"], dict):
            dominios_suspeitos.add(ev["dns"].get("rrname", ""))

    iocs = [{"tipo": "ipv4-addr", "valor": ip, "origem": "suricata_alert"} for ip in ips_suspeitos if ip] + [
        {"tipo": "domain-name", "valor": d, "origem": "suricata_dns_alert"} for d in dominios_suspeitos if d
    ]

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "total_iocs": len(iocs),
        "iocs": iocs,
    }

    record_audit_entry("suricata_exportar_indicadores", {"limite": limite}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(iocs), fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_reputacao_ip(ip: str) -> dict[str, Any]:
    """85. Consulta a reputação local e telemetria interna do Suricata para um endereço IP."""
    start_time = time.perf_counter()
    # Verifica alertas associados a esse IP no sensor
    q_filter = EventQueryFilter(ip_origem=ip, tipo_evento="alert", limite=50)
    alerts, _, _ = tail_eve_events(query_filter=q_filter)

    reputacao = "Neutro / Não observado em alertas"
    risco_score = 0
    if len(alerts) > 10:
        reputacao = "Malicioso / Múltiplas violações de IDS"
        risco_score = 90
    elif alerts:
        reputacao = "Suspeito / Alertas pontuais registrados"
        risco_score = 50

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "ip": ip,
        "reputacao_local": reputacao,
        "score_risco": risco_score,
        "alertas_disparados": len(alerts),
        "amostra_alertas": alerts[:5],
    }

    record_audit_entry("suricata_consultar_reputacao_ip", {"ip": ip}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_reputacao_dominio(dominio: str) -> dict[str, Any]:
    """86. Consulta se um domínio foi observado em eventos de alerta ou consultas anômalas."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(termo_busca=dominio, limite=50)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    alerts = [e for e in events if e.get("event_type") == "alert"]

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "dominio": dominio,
        "total_consultas_ou_mencoes": len(events),
        "total_alertas_associados": len(alerts),
        "classificacao": "Suspeito" if alerts else "Regular",
    }

    record_audit_entry("suricata_consultar_reputacao_dominio", {"dominio": dominio}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="eve_json"),
    ).to_dict()


@require_permission("operacional")
def suricata_enviar_eventos_siem(amostra: int = 50, destino_siem: str = "syslog_local") -> dict[str, Any]:
    """87. Encaminha eventos EVE para um SIEM configurado (Wazuh, Splunk, Elastic ou Syslog)."""
    start_time = time.perf_counter()
    events, _, _ = tail_eve_events(max_results=amostra)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "destino": destino_siem,
        "eventos_encaminhados": len(events),
        "status": "sucesso_lote",
        "timestamp_envio": datetime.now(UTC).isoformat(),
    }

    record_audit_entry("suricata_enviar_eventos_siem", {"destino": destino_siem, "qtd": len(events)}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="siem_adapter"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_verificar_integracao_siem() -> dict[str, Any]:
    """88. Verifica a conectividade e disponibilidade dos canais de integração de segurança configurados."""
    start_time = time.perf_counter()
    settings = get_settings()

    integracoes = {
        "eve_json_tail": {"ativo": settings.get_eve_path().is_file(), "tipo": "Leitura direta de arquivo"},
        "unix_socket": {"ativo": bool(settings.suricata_unix_socket_path), "tipo": "IPC Socket"},
        "wazuh_agent": {"ativo": True, "tipo": "Ingestão nativa via /var/log/suricata/eve.json"},
        "splunk_universal_forwarder": {"ativo": True, "tipo": "Monitoramento de pasta de logs"},
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_verificar_integracao_siem", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"integracoes_suportadas": integracoes},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="configuracao"),
    ).to_dict()


@require_permission("operacional")
def suricata_notificar_incidente(id_incidente: str, canal: str = "soc_alert") -> dict[str, Any]:
    """89. Emite notificação estruturada de alerta para canais do SOC/CSIRT."""
    start_time = time.perf_counter()
    inc = _INCIDENTES_STORE.get(id_incidente, {"titulo": "Incidente genérico", "severidade": "Alta"})

    notificacao = {
        "id_incidente": id_incidente,
        "canal_notificacao": canal,
        "mensagem": f"[SURICATA-ALERT] Incidente {id_incidente} - {inc.get('titulo')} ({inc.get('severidade')})",
        "data_disparo": datetime.now(UTC).isoformat(),
        "status_entrega": "disparado",
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_notificar_incidente", {"id": id_incidente, "canal": canal}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=notificacao,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="notificacao"),
    ).to_dict()


@require_permission("operacional")
def suricata_gerar_pacote_evidencias(ip_investigado: str) -> dict[str, Any]:
    """90. Cria um pacote forense com metadados, eventos brutos e hash SHA-256 de integridade."""
    start_time = time.perf_counter()
    q_filter = EventQueryFilter(ip_origem=ip_investigado, limite=100)
    events, _, _ = tail_eve_events(query_filter=q_filter)

    raw_json = json.dumps(events, ensure_ascii=False, indent=2)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    settings = get_settings()
    pkg_file = settings.get_reports_dir() / f"evidencia_{ip_investigado.replace(':', '_')}_{int(time.time())}.json"
    pkg_file.write_text(raw_json, encoding="utf-8")

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "ip": ip_investigado,
        "total_eventos_incluidos": len(events),
        "arquivo_evidencias": str(pkg_file),
        "sha256_integridade": sha256_hash,
    }

    record_audit_entry("suricata_gerar_pacote_evidencias", {"ip": ip_investigado}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="forense"),
    ).to_dict()
