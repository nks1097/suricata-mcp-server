"""Categoria H — Configuração e gestão operacional (Ferramentas 71 a 80)."""

import time
from pathlib import Path
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..config import get_settings
from ..config_validator import ConfigValidator
from ..models import MetadataEnvelope, StandardResponseEnvelope
from ..unix_socket_client import SuricataSocketClient


@require_permission("somente_leitura")
def suricata_validar_configuracao() -> dict[str, Any]:
    """71. Executa a validação controlada do suricata.yaml via motor oficial ou parser YAML."""
    start_time = time.perf_counter()
    validator = ConfigValidator()
    cfg_file = validator.get_config_file()
    test_res = validator.test_with_suricata_binary(cfg_file)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_validar_configuracao", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=test_res.get("valido", False),
        dados={"arquivo": str(cfg_file), "resultado": test_res},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="config_validator"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_parametros_configuracao(secao: str | None = None) -> dict[str, Any]:
    """72. Consulta seções específicas de parâmetros do suricata.yaml (redigindo segredos)."""
    start_time = time.perf_counter()
    validator = ConfigValidator()
    cfg = validator.load_config_dict()

    if secao:
        dados_secao = cfg.get(secao, {})
        resultado = {secao: dados_secao}
    else:
        resultado = cfg

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_consultar_parametros_configuracao", {"secao": secao}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"parametros": resultado},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="configuracao"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_previsualizar_configuracao(novo_conteudo_yaml: str) -> dict[str, Any]:
    """73. Exibe o diff unificado entre a configuração atual e a proposta sem aplicá-la."""
    start_time = time.perf_counter()
    validator = ConfigValidator()
    # Valida sintaxe antes de gerar diff
    validator.validate_yaml_syntax(novo_conteudo_yaml)
    diff = validator.preview_config_diff(novo_conteudo_yaml)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "arquivo": str(validator.get_config_file()),
        "diff_proposto": diff,
    }

    record_audit_entry("suricata_previsualizar_configuracao", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="diff"),
    ).to_dict()


@require_permission("administrativo")
def suricata_atualizar_configuracao_autorizada(novo_conteudo_yaml: str) -> dict[str, Any]:
    """74. Aplica alteração no suricata.yaml após validação sintática estrita e geração de backup."""
    start_time = time.perf_counter()
    validator = ConfigValidator()
    res = validator.update_config_safely(novo_conteudo_yaml)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_atualizar_configuracao_autorizada", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=res,
        avisos=["Configuração atualizada com backup prévio criado. Recomenda-se reiniciar o serviço se necessário."],
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="configuracao"),
    ).to_dict()


@require_permission("operacional")
def suricata_reabrir_logs() -> dict[str, Any]:
    """75. Solicita a reabertura de descritores de arquivos de log para rotação (logrotate)."""
    start_time = time.perf_counter()
    socket_client = SuricataSocketClient()

    if socket_client.is_available():
        try:
            resp = socket_client.send_command("reopen-log-files")
            sucesso = resp.get("return") == "OK"
            dados = {"metodo": "unix_socket", "resposta": resp}
            erro = None if sucesso else "Falha ao solicitar reabertura via socket"
        except Exception as e:
            sucesso = False
            dados = {}
            erro = str(e)
    else:
        sucesso = True
        dados = {
            "metodo": "sinal_posix",
            "instrucao": "No Linux, envie 'kill -HUP <pid>' para o processo do Suricata recriar os descritores.",
        }
        erro = None

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_reabrir_logs", {}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="controle"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_estado_recarga() -> dict[str, Any]:
    """76. Consulta evidências e status de recargas recentes de regras registradas no log."""
    start_time = time.perf_counter()
    settings = get_settings()
    log_file = Path(settings.suricata_log_dir) / "suricata.log"

    evidencias = []
    if log_file.is_file():
        with open(log_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if any(w in line.lower() for w in ("reload", "ruleset", "reloaded")):
                    evidencias.append(line.strip())

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "total_registros_recarga": len(evidencias),
        "ultimas_evidencias": evidencias[-10:],
    }

    record_audit_entry("suricata_consultar_estado_recarga", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="suricata_log"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_verificar_arquivos_regras() -> dict[str, Any]:
    """77. Verifica a lista de arquivos de regras (.rules) referenciados na configuração e se existem no disco."""
    start_time = time.perf_counter()
    validator = ConfigValidator()
    cfg = validator.load_config_dict()
    rule_files = cfg.get("rule-files", [])

    settings = get_settings()
    rules_dir = settings.get_rules_dir()

    status_arquivos = []
    for rf in rule_files:
        fpath = Path(rf)
        if not fpath.is_absolute():
            fpath = rules_dir / rf
        status_arquivos.append(
            {
                "referenciado": rf,
                "caminho_completo": str(fpath),
                "existe": fpath.is_file(),
                "tamanho_bytes": fpath.stat().st_size if fpath.is_file() else 0,
            }
        )

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_verificar_arquivos_regras", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"total_arquivos": len(status_arquivos), "arquivos": status_arquivos},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="filesystem"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_verificar_saida_eve() -> dict[str, Any]:
    """78. Inspeciona a integridade, permissões e status de escrita do arquivo eve.json."""
    start_time = time.perf_counter()
    settings = get_settings()
    eve_path = settings.get_eve_path()

    existe = eve_path.is_file()
    tamanho = eve_path.stat().st_size if existe else 0
    mtime = eve_path.stat().st_mtime if existe else 0

    dados = {
        "caminho_eve": str(eve_path),
        "acessivel": existe,
        "tamanho_bytes": tamanho,
        "tamanho_mb": round(tamanho / (1024 * 1024), 2),
        "tempo_desde_ultima_escrita_segundos": int(time.time() - mtime) if existe else None,
        "status_coleta": "Ativo" if existe and (time.time() - mtime) < 300 else "Ocioso ou Inativo",
    }

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_verificar_saida_eve", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="eve_json"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_verificar_retencao_logs() -> dict[str, Any]:
    """79. Verifica o espaço em disco ocupado pela pasta de logs e o espaço livre disponível."""
    start_time = time.perf_counter()
    settings = get_settings()
    log_dir = Path(settings.suricata_log_dir)

    total_bytes = 0
    arquivos_encontrados = []
    if log_dir.is_dir():
        for p in log_dir.glob("*"):
            if p.is_file():
                sz = p.stat().st_size
                total_bytes += sz
                arquivos_encontrados.append({"nome": p.name, "tamanho_mb": round(sz / (1024 * 1024), 2)})

    import shutil

    usage = shutil.disk_usage(str(log_dir if log_dir.exists() else Path.cwd()))

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "diretorio_logs": str(log_dir),
        "total_ocupado_mb": round(total_bytes / (1024 * 1024), 2),
        "espaco_disco_livre_gb": round(usage.free / (1024 * 1024 * 1024), 2),
        "arquivos": arquivos_encontrados[:20],
    }

    record_audit_entry("suricata_verificar_retencao_logs", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="filesystem"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_diagnosticar_configuracao() -> dict[str, Any]:
    """80. Identifica inconsistências em suricata.yaml e propõe ajustes de boas práticas defensivas."""
    start_time = time.perf_counter()
    validator = ConfigValidator()
    cfg = validator.load_config_dict()

    problemas = []
    ajustes = []

    # Verifica saídas EVE
    outputs = cfg.get("outputs", [])
    has_eve = any(isinstance(out, dict) and "eve-log" in out for out in outputs)
    if not has_eve:
        problemas.append("Saída eve-log não identificada na lista de 'outputs'.")
        ajustes.append("Ative 'eve-log' com formato JSON para habilitar análise de telemetria completa.")

    # Verifica modo AF-PACKET
    if "af-packet" not in cfg:
        ajustes.append("Recomenda-se utilizar 'af-packet' em Linux para melhor desempenho de captura multi-threaded.")

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "status": "Inconsistente" if problemas else "Adequado",
        "inconsistencias": problemas,
        "ajustes_sugeridos": ajustes,
    }

    record_audit_entry("suricata_diagnosticar_configuracao", {}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="config_validator"),
    ).to_dict()
