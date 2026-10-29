"""Categoria E — Regras e assinaturas de detecção (Ferramentas 41 a 50)."""

import time
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..models import MetadataEnvelope, StandardResponseEnvelope
from ..rule_manager import RuleManager, validate_rule_syntax
from ..subprocess_runner import run_suricata_command
from ..unix_socket_client import SuricataSocketClient


@require_permission("somente_leitura")
def suricata_listar_regras(limite: int = 100, apenas_ativas: bool = True) -> dict[str, Any]:
    """41. Lista regras de detecção instaladas nos arquivos locais e seus metadados."""
    start_time = time.perf_counter()
    mgr = RuleManager()
    rules = mgr.list_rules(limit=limite, active_only=apenas_ativas)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_listar_regras", {"limite": limite, "apenas_ativas": apenas_ativas}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"regras": rules, "total_retornado": len(rules)},
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(rules), fonte_dados="arquivos_rules"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_consultar_regra(sid: int) -> dict[str, Any]:
    """42. Consulta a definição completa e metadados de uma regra pelo seu Signature ID (SID)."""
    start_time = time.perf_counter()
    mgr = RuleManager()
    rule = mgr.find_rule_by_sid(sid)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_consultar_regra", {"sid": sid}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"regra": rule, "encontrada": bool(rule)},
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="arquivos_rules"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_pesquisar_regras(termo: str, limite: int = 50) -> dict[str, Any]:
    """43. Pesquisa regras por texto na mensagem, classtype ou conteúdo."""
    start_time = time.perf_counter()
    mgr = RuleManager()
    all_rules = mgr.list_rules(limit=2000, active_only=False)

    term_lower = termo.lower()
    matched = [
        r
        for r in all_rules
        if term_lower in str(r.get("mensagem", "")).lower()
        or term_lower in str(r.get("classtype", "")).lower()
        or term_lower in str(r.get("texto_bruto", "")).lower()
    ][:limite]

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_pesquisar_regras", {"termo": termo, "limite": limite}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados={"termo_pesquisado": termo, "regras_encontradas": matched, "total": len(matched)},
        metadados=MetadataEnvelope(duracao_ms=duration, total_encontrado=len(matched), fonte_dados="arquivos_rules"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_validar_regra(regra_texto: str) -> dict[str, Any]:
    """44. Valida a sintaxe, opções e compatibilidade de uma regra proposta antes da inclusão."""
    start_time = time.perf_counter()
    try:
        rule_obj = validate_rule_syntax(regra_texto)
        dados = {
            "valida": True,
            "detalhes": rule_obj.model_dump(),
            "mensagem": "Sintaxe da regra Suricata aprovada com sucesso.",
        }
        sucesso = True
        erro = None
    except Exception as e:
        dados = {"valida": False, "mensagem": str(e)}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_validar_regra", {"regra": regra_texto}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="validador_regras"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_previsualizar_alteracao_regras(nova_regra_texto: str) -> dict[str, Any]:
    """45. Apresenta o diff unificado da alteração que será feita no local.rules."""
    start_time = time.perf_counter()
    mgr = RuleManager()
    validated = validate_rule_syntax(nova_regra_texto)

    local_file = mgr.get_local_rules_file()
    original_content = local_file.read_text(encoding="utf-8")
    new_content = original_content.rstrip() + f"\n{nova_regra_texto.strip()}\n"
    diff = mgr.preview_rule_diff(original_content, new_content, local_file.name)

    duration = (time.perf_counter() - start_time) * 1000
    dados = {
        "arquivo": str(local_file),
        "sid": validated.sid,
        "diff_proposto": diff,
    }

    record_audit_entry("suricata_previsualizar_alteracao_regras", {"sid": validated.sid}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=dados,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="diff"),
    ).to_dict()


@require_permission("administrativo")
def suricata_adicionar_regra_local(regra_texto: str) -> dict[str, Any]:
    """46. Adiciona uma nova regra validada ao arquivo local.rules com backup automático."""
    start_time = time.perf_counter()
    mgr = RuleManager()
    res = mgr.add_local_rule(regra_texto)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_adicionar_regra_local", {"regra": regra_texto}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=res,
        avisos=["Regra adicionada ao arquivo local. Lembre-se de recarregar as regras no motor."],
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="local_rules"),
    ).to_dict()


@require_permission("administrativo")
def suricata_atualizar_regra_local(sid: int, nova_regra_texto: str) -> dict[str, Any]:
    """47. Atualiza uma regra local existente mantendo o SID e gerando backup prévio."""
    start_time = time.perf_counter()
    mgr = RuleManager()
    # Desativa a anterior e adiciona a nova
    mgr.deactivate_rule(sid)
    res = mgr.add_local_rule(nova_regra_texto)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_atualizar_regra_local", {"sid": sid}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=res,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="local_rules"),
    ).to_dict()


@require_permission("administrativo")
def suricata_desativar_regra_local(sid: int) -> dict[str, Any]:
    """48. Desativa (comenta com #) uma regra no arquivo local.rules preservando histórico."""
    start_time = time.perf_counter()
    mgr = RuleManager()
    res = mgr.deactivate_rule(sid)
    duration = (time.perf_counter() - start_time) * 1000

    record_audit_entry("suricata_desativar_regra_local", {"sid": sid}, True, duration)
    return StandardResponseEnvelope(
        sucesso=True,
        dados=res,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="local_rules"),
    ).to_dict()


@require_permission("administrativo")
def suricata_atualizar_conjunto_regras() -> dict[str, Any]:
    """49. Executa 'suricata-update' para baixar as assinaturas oficiais atualizadas."""
    start_time = time.perf_counter()
    try:
        res = run_suricata_command(["update"], custom_executable="suricata-update", timeout_seconds=90)
        dados = {
            "status": "atualizado" if res.get("sucesso") else "falha",
            "saida": res.get("stdout"),
            "erros": res.get("stderr"),
        }
        sucesso = res.get("sucesso", False)
        erro = res.get("stderr") if not sucesso else None
    except Exception as e:
        dados = {"status": "indisponivel", "detalhes": str(e)}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_atualizar_conjunto_regras", {}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="suricata-update"),
    ).to_dict()


@require_permission("operacional")
def suricata_recarregar_regras() -> dict[str, Any]:
    """50. Solicita o recarregamento a quente das regras no motor do Suricata sem reiniciar."""
    start_time = time.perf_counter()
    socket_client = SuricataSocketClient()

    if socket_client.is_available():
        try:
            resp = socket_client.send_command("reload-rules")
            sucesso = resp.get("return") == "OK"
            dados = {"metodo": "unix_socket", "resposta": resp}
            erro = None if sucesso else "Falha ao recarregar via socket"
        except Exception as e:
            sucesso = False
            dados = {"metodo": "unix_socket"}
            erro = str(e)
    else:
        # Informa método alternativo caso o socket esteja inativo
        sucesso = True
        dados = {
            "metodo": "sinal_operacional",
            "status": "socket_inativo",
            "instrucao": "O Unix socket não está ativo. No Linux envie 'kill -USR2 <pid>'. No Windows reinicie o serviço se necessário.",
        }
        erro = None

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_recarregar_regras", {}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="controle"),
    ).to_dict()
