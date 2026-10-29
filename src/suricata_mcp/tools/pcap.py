"""Categoria F — PCAP e análise forense offline (Ferramentas 51 a 60)."""

import time
from typing import Any

from ..audit import record_audit_entry
from ..authorization import require_permission
from ..models import MetadataEnvelope, StandardResponseEnvelope
from ..pcap_analyzer import PCAPAnalyzer


@require_permission("operacional")
def suricata_analisar_pcap(caminho_pcap: str, manter_artefatos: bool = False) -> dict[str, Any]:
    """51. Executa a análise offline de um arquivo PCAP autorizado através do motor do Suricata."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        res = analyzer.analyze_pcap_offline(caminho_pcap, keep_artifacts=manter_artefatos)
        sucesso = True
        erro = None
    except Exception as e:
        res = {}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_pcap", {"pcap": caminho_pcap}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=res,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("somente_leitura")
def suricata_validar_arquivo_pcap(caminho_pcap: str) -> dict[str, Any]:
    """52. Verifica integridade, magic bytes, tamanho e formato de uma captura PCAP/PCAPNG."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        res = analyzer.validate_pcap_file(caminho_pcap)
        sucesso = True
        erro = None
    except Exception as e:
        res = {"valido": False}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_validar_arquivo_pcap", {"pcap": caminho_pcap}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=res,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="arquivo"),
    ).to_dict()


@require_permission("operacional")
def suricata_resumir_pcap(caminho_pcap: str) -> dict[str, Any]:
    """53. Produz um resumo do tráfego observado (alertas, protocolos e fluxos) em uma captura."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        full_res = analyzer.analyze_pcap_offline(caminho_pcap, keep_artifacts=False)
        dados = {
            "pcap": full_res.get("pcap"),
            "resumo": full_res.get("resumo_analise"),
            "total_alertas": full_res.get("total_alertas"),
            "total_fluxos": full_res.get("total_fluxos"),
        }
        sucesso = True
        erro = None
    except Exception as e:
        dados = {}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_resumir_pcap", {"pcap": caminho_pcap}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("operacional")
def suricata_extrair_alertas_pcap(caminho_pcap: str, limite: int = 50) -> dict[str, Any]:
    """54. Extrai exclusivamente a lista de alertas disparados durante a análise do PCAP."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        full_res = analyzer.analyze_pcap_offline(caminho_pcap, keep_artifacts=False)
        alertas = full_res.get("amostra_alertas", [])[:limite]
        sucesso = True
        erro = None
    except Exception as e:
        alertas = []
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_extrair_alertas_pcap", {"pcap": caminho_pcap}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados={"alertas": alertas, "total": len(alertas)},
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("operacional")
def suricata_analisar_protocolos_pcap(caminho_pcap: str) -> dict[str, Any]:
    """55. Resume os protocolos e portas identificados dentro de um arquivo de captura."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        full_res = analyzer.analyze_pcap_offline(caminho_pcap, keep_artifacts=False)
        resumo = full_res.get("resumo_analise", {})
        dados = {
            "protocolos": resumo.get("distribuicao_protocolos", {}),
            "tipos_eventos": resumo.get("distribuicao_tipos", {}),
        }
        sucesso = True
        erro = None
    except Exception as e:
        dados = {}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_protocolos_pcap", {"pcap": caminho_pcap}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("operacional")
def suricata_analisar_fluxos_pcap(caminho_pcap: str) -> dict[str, Any]:
    """56. Resume os fluxos bidirecionais observados na captura (endereços e contagens)."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        full_res = analyzer.analyze_pcap_offline(caminho_pcap, keep_artifacts=False)
        resumo = full_res.get("resumo_analise", {})
        dados = {
            "top_origens": resumo.get("top_ips_origem", {}),
            "top_destinos": resumo.get("top_ips_destino", {}),
            "total_fluxos": full_res.get("total_fluxos", 0),
        }
        sucesso = True
        erro = None
    except Exception as e:
        dados = {}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_analisar_fluxos_pcap", {"pcap": caminho_pcap}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dados,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("operacional")
def suricata_comparar_pcaps(pcap_a: str, pcap_b: str) -> dict[str, Any]:
    """57. Compara eventos e estatísticas geradas entre duas capturas de rede distintas."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        res_a = analyzer.analyze_pcap_offline(pcap_a)
        res_b = analyzer.analyze_pcap_offline(pcap_b)

        comparativo = {
            "pcap_a": {"nome": pcap_a, "alertas": res_a.get("total_alertas"), "eventos": res_a.get("total_eventos")},
            "pcap_b": {"nome": pcap_b, "alertas": res_b.get("total_alertas"), "eventos": res_b.get("total_eventos")},
            "diferenca_alertas": abs(res_a.get("total_alertas", 0) - res_b.get("total_alertas", 0)),
        }
        sucesso = True
        erro = None
    except Exception as e:
        comparativo = {}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_comparar_pcaps", {"a": pcap_a, "b": pcap_b}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=comparativo,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("operacional")
def suricata_pesquisar_eventos_pcap(caminho_pcap: str, termo_busca: str) -> dict[str, Any]:
    """58. Filtra e pesquisa eventos derivados especificamente da execução de uma captura."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        full = analyzer.analyze_pcap_offline(caminho_pcap)
        # Filtra alertas contendo o termo
        matched = [a for a in full.get("amostra_alertas", []) if termo_busca.lower() in str(a).lower()]
        sucesso = True
        erro = None
    except Exception as e:
        matched = []
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry(
        "suricata_pesquisar_eventos_pcap", {"pcap": caminho_pcap, "termo": termo_busca}, sucesso, duration, error=erro
    )
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados={"termo": termo_busca, "eventos_encontrados": matched, "total": len(matched)},
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("operacional")
def suricata_gerar_relatorio_pcap(caminho_pcap: str) -> dict[str, Any]:
    """59. Gera relatório estruturado consolidando as descobertas da análise do PCAP."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        full = analyzer.analyze_pcap_offline(caminho_pcap)
        dossie = {
            "titulo": f"Relatório Forense de Captura PCAP: {caminho_pcap}",
            "resumo": full.get("resumo_analise"),
            "alertas_identificados": full.get("total_alertas"),
            "fluxos_identificados": full.get("total_fluxos"),
            "conclusao_preliminar": "Ameaças identificadas"
            if full.get("total_alertas", 0) > 0
            else "Nenhuma ameaça detectada",
        }
        sucesso = True
        erro = None
    except Exception as e:
        dossie = {}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry("suricata_gerar_relatorio_pcap", {"pcap": caminho_pcap}, sucesso, duration, error=erro)
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=dossie,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="pcap_offline"),
    ).to_dict()


@require_permission("operacional")
def suricata_limpar_artefatos_analise(diretorio_temporario: str) -> dict[str, Any]:
    """60. Remove com segurança artefatos temporários gerados durante análises PCAP anteriores."""
    start_time = time.perf_counter()
    analyzer = PCAPAnalyzer()
    try:
        res = analyzer.clean_analysis_artifacts(diretorio_temporario)
        sucesso = True
        erro = None
    except Exception as e:
        res = {}
        sucesso = False
        erro = str(e)

    duration = (time.perf_counter() - start_time) * 1000
    record_audit_entry(
        "suricata_limpar_artefatos_analise", {"dir": diretorio_temporario}, sucesso, duration, error=erro
    )
    return StandardResponseEnvelope(
        sucesso=sucesso,
        dados=res,
        erro=erro,
        metadados=MetadataEnvelope(duracao_ms=duration, fonte_dados="sistema"),
    ).to_dict()
