"""Categoria A — Sensores e estado operacional (Ferramentas 1 a 10)."""

import os
import time
from pathlib import Path
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..config import get_settings
from ..config_validator import ConfigValidator
from ..models import MetadataEnvelope, StandardResponseEnvelope
from ..subprocess_runner import run_suricata_command
from ..unix_socket_client import SuricataSocketClient


@require_permission("somente_leitura")
def suricata_testar_conexao() -> dict[str, Any]:
    """1. Verifica o acesso aos recursos do sensor Suricata, arquivos configurados e permissões."""
    start_time = time.perf_counter()
    settings = get_settings()
    avisos = []

    config_ok = settings.get_config_path().is_file()
    if not config_ok:
        avisos.append(f"Arquivo de configuração não encontrado em: {settings.suricata_config_path}")

    eve_ok = settings.get_eve_path().is_file()
    if not eve_ok:
        avisos.append(f"Arquivo EVE JSON não encontrado em: {settings.suricata_eve_path}")

    socket_client = SuricataSocketClient()
    socket_ok = socket_client.is_available()
    if not socket_ok and settings.suricata_unix_socket_path:
        avisos.append(f"Unix socket configurado mas indisponível em: {settings.suricata_unix_socket_path}")

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "status_geral": "operacional" if (config_ok or eve_ok) else "degradado",
        "configuracao_acessivel": config_ok,
        "eve_json_acessivel": eve_ok,
        "socket_acessivel": socket_ok,
        "diretorio_regras_acessivel": settings.get_rules_dir().is_dir(),
        "modo_operacao": settings.mcp_operation_mode,
    }

    record_audit_entry("suricata_testar_conexao", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        avisos=avisos,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="sistema"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_obter_versao() -> dict[str, Any]:
    """2. Consulta a versão exata do Suricata e suas capacidades detectáveis."""
    start_time = time.perf_counter()
    settings = get_settings()
    versao_str = "Desconhecida"
    sucesso = False
    erro = None

    try:
        res = run_suricata_command(["-V"])
        if res.get("sucesso"):
            versao_str = res.get("stdout") or res.get("stderr") or "Suricata detectado"
            sucesso = True
        else:
            erro = res.get("stderr")
    except Exception as e:
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "versao": versao_str,
        "executavel": settings.suricata_executable,
        "mcp_server_versao": settings.app_version,
    }

    record_audit_entry("suricata_obter_versao", {}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="binario"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_obter_estado_sensor() -> dict[str, Any]:
    """3. Consulta o estado operacional observável do sensor Suricata."""
    start_time = time.perf_counter()
    settings = get_settings()
    socket_client = SuricataSocketClient()

    estado = "desconhecido"
    uptime_segundos = None
    modo_captura = "offline/arquivo"

    if socket_client.is_available():
        try:
            resp = socket_client.send_command("uptime")
            if resp.get("return") == "OK":
                uptime_segundos = resp.get("message")
                estado = "ativo_em_execucao"
                modo_captura = "live_socket"
        except Exception:
            estado = "socket_inativo"

    # Se não foi possível via socket, avalia modificação recente no eve.json
    if estado == "desconhecido" and settings.get_eve_path().is_file():
        mtime = settings.get_eve_path().stat().st_mtime
        delta = time.time() - mtime
        if delta < 120:
            estado = "ativo_coletando (eve.json recente)"
        else:
            estado = f"inativo_ou_ocioso (último log há {int(delta)} segundos)"

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "estado": estado,
        "uptime_segundos": uptime_segundos,
        "modo_observado": modo_captura,
        "eve_path": str(settings.get_eve_path()),
    }

    record_audit_entry("suricata_obter_estado_sensor", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="sensor"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_listar_interfaces() -> dict[str, Any]:
    """4. Lista interfaces de rede configuradas ou disponíveis no escopo do sensor."""
    start_time = time.perf_counter()
    socket_client = SuricataSocketClient()
    interfaces = []
    fonte = "socket"

    if socket_client.is_available():
        try:
            resp = socket_client.send_command("iface-list")
            if resp.get("return") == "OK":
                interfaces = resp.get("message", {}).get("ifaces", [])
        except Exception:
            pass

    # Fallback: extrai interfaces do suricata.yaml
    if not interfaces:
        fonte = "suricata.yaml"
        try:
            validator = ConfigValidator()
            cfg = validator.load_config_dict()
            for key in ("af-packet", "pcap", "netmap", "pcap-file"):
                if key in cfg and isinstance(cfg[key], list):
                    for item in cfg[key]:
                        if isinstance(item, dict) and "interface" in item:
                            interfaces.append(item["interface"])
        except Exception:
            pass

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_listar_interfaces", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"interfaces": sorted(list(set(interfaces))), "total": len(interfaces)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados=fonte),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_configuracao_carregada(filtro_chave: str | None = None) -> dict[str, Any]:
    """5. Consulta parâmetros permitidos de configuração do Suricata sem expor segredos."""
    start_time = time.perf_counter()
    validator = ConfigValidator()
    cfg = validator.load_config_dict()

    if filtro_chave:
        cfg = {k: v for k, v in cfg.items() if filtro_chave.lower() in k.lower()}

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_consultar_configuracao_carregada", {"filtro_chave": filtro_chave}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"configuracao": cfg, "total_chaves": len(cfg)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="configuracao"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_obter_estatisticas() -> dict[str, Any]:
    """6. Recupera métricas e contadores de desempenho do motor do Suricata."""
    start_time = time.perf_counter()
    socket_client = SuricataSocketClient()
    stats = {}
    fonte = "socket"

    if socket_client.is_available():
        try:
            resp = socket_client.send_command("dump-counters")
            if resp.get("return") == "OK":
                stats = resp.get("message", {})
        except Exception:
            pass

    # Fallback: obtém último evento de stats no eve.json
    if not stats:
        fonte = "eve_json"
        from ..eve_reader import tail_eve_events
        from ..models import EventQueryFilter

        evs, _, _ = tail_eve_events(query_filter=EventQueryFilter(tipo_evento="stats", limite=1))
        if evs and "stats" in evs[0]:
            stats = evs[0]["stats"]

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_obter_estatisticas", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"estatisticas": stats, "disponivel": bool(stats)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados=fonte),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_estado_socket() -> dict[str, Any]:
    """7. Verifica a conectividade e comandos disponíveis no Unix socket ou Named Pipe."""
    start_time = time.perf_counter()
    settings = get_settings()
    socket_client = SuricataSocketClient()

    disponivel = socket_client.is_available()
    comandos = socket_client.get_supported_commands() if disponivel else []

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "caminho_configurado": settings.suricata_unix_socket_path or "Nenhum (desabilitado)",
        "acessivel": disponivel,
        "comandos_suportados": comandos,
        "total_comandos": len(comandos),
    }

    record_audit_entry("suricata_consultar_estado_socket", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="socket"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_logs_operacionais(linhas: int = 50) -> dict[str, Any]:
    """8. Consulta os logs operacionais do Suricata (suricata.log) autorizados."""
    start_time = time.perf_counter()
    settings = get_settings()
    log_dir = Path(settings.suricata_log_dir)
    suricata_log = log_dir / "suricata.log"

    conteudo_linhas = []
    if suricata_log.is_file():
        with open(suricata_log, encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
            conteudo_linhas = [line.strip() for line in all_lines[-linhas:]]

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_consultar_logs_operacionais", {"linhas": linhas}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"arquivo": str(suricata_log), "linhas_retornadas": len(conteudo_linhas), "conteudo": conteudo_linhas},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="suricata_log"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_verificar_integridade_sensor() -> dict[str, Any]:
    """9. Verifica saúde geral do sensor, arquivos esperados e integridade de diretórios."""
    start_time = time.perf_counter()
    settings = get_settings()

    itens_verificados = {
        "executavel_presente": bool(
            settings.suricata_executable and (Path(settings.suricata_executable).is_file() or os.name != "nt")
        ),
        "arquivo_configuracao_presente": settings.get_config_path().is_file(),
        "arquivo_eve_presente": settings.get_eve_path().is_file(),
        "diretorio_logs_presente": Path(settings.suricata_log_dir).is_dir(),
        "diretorio_regras_presente": settings.get_rules_dir().is_dir(),
        "diretorio_pcaps_presente": settings.get_pcap_dir().is_dir(),
    }

    saudavel = all(itens_verificados.values())
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_verificar_integridade_sensor", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"saude_geral": "OK" if saudavel else "ATENÇÃO", "detalhes": itens_verificados},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="sistema"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_diagnosticar_sensor() -> dict[str, Any]:
    """10. Consolida diagnósticos de integridade, socket, telemetria e gera diagnóstico fundamentado."""
    start_time = time.perf_counter()
    settings = get_settings()
    avisos = []
    recomendacoes = []

    # Checagem de EVE
    eve_path = settings.get_eve_path()
    if not eve_path.is_file():
        avisos.append("Arquivo eve.json não localizado.")
        recomendacoes.append("Verifique se a seção 'eve-log: enabled: yes' está ativa no suricata.yaml.")
    else:
        size_mb = eve_path.stat().st_size / (1024 * 1024)
        if size_mb > 500:
            avisos.append(f"Arquivo eve.json muito grande ({size_mb:.1f} MB).")
            recomendacoes.append("Configure rotação de logs (logrotate) para evitar degradação de I/O em disco.")

    # Checagem de Regras
    rules_dir = settings.get_rules_dir()
    if not rules_dir.is_dir() or not list(rules_dir.glob("*.rules")):
        avisos.append("Nenhum arquivo de regras (.rules) encontrado no diretório de regras.")
        recomendacoes.append("Execute 'suricata-update' para baixar as assinaturas oficiais da OISF.")

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "status_diagnostico": "saudavel" if not avisos else "requer_atencao",
        "total_anomalias": len(avisos),
        "anomalias_detectadas": avisos,
        "recomendacoes_operacionais": recomendacoes,
    }

    record_audit_entry("suricata_diagnosticar_sensor", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        avisos=avisos,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="diagnostico"),
    ).to_dict()
