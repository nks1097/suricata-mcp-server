"""Ponto de entrada principal do Suricata MCP Server.

Inicializa a instância MCPServer, registra as 100 ferramentas especializadas em português,
configura prompts para agentes de IA e gerencia os transportes STDIO e SSE.
"""

import argparse
import contextlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from mcp.server.mcpserver import MCPServer
except (ImportError, ModuleNotFoundError):
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore

from .config import get_settings
from .tools import ALL_TOOLS

# Configuração de logging estritamente direcionada para stderr para proteger o transporte stdio
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("suricata_mcp.server")


def create_server() -> MCPServer:
    """Cria e configura o servidor MCP registrando todas as 100 ferramentas e prompts analíticos."""
    settings = get_settings()

    server = MCPServer(
        name="suricata-mcp",
        instructions=(
            "Servidor Model Context Protocol (MCP) para Suricata IDS/IPS e Network Security Monitoring (NSM). "
            "Fornece 100 ferramentas em português para monitoramento de sensores, triagem de alertas, pesquisa "
            "de telemetria EVE JSON, análise de PCAP, engenharia de detecção, auditoria e resposta defensiva."
        ),
        version=settings.app_version,
    )

    # 1. Registro automático das 100 ferramentas
    for tool_func in ALL_TOOLS:
        server.add_tool(tool_func)

    logger.info("Registradas %d ferramentas no Suricata MCP Server.", len(ALL_TOOLS))

    # 2. Prompts Especializados para Agentes de IA
    @server.prompt(
        name="investigar_alerta_ameaca",
        description="Conduz o agente de IA através de um fluxo estruturado de investigação de alertas e ameaças.",
    )
    def prompt_investigar_alerta(ip_suspeito: str) -> str:
        return (
            f"Inicie a investigação defensiva detalhada do IP suspeito '{ip_suspeito}':\n"
            f"1. Correlacione toda a atividade do host com 'suricata_investigar_ip'.\n"
            f"2. Verifique se há histórico de alertas com 'suricata_correlacionar_alertas'.\n"
            f"3. Inspecione consultas DNS anômalas com 'suricata_detectar_padroes_dns_suspeitos'.\n"
            f"4. Reconstrua os eventos em ordem cronológica com 'suricata_gerar_linha_tempo_rede'.\n"
            f"5. Classifique a severidade do incidente com 'suricata_classificar_incidente'.\n"
            f"6. Elabore o plano de resposta e contenção defensiva com 'suricata_planejar_resposta_incidente'."
        )

    @server.prompt(
        name="analisar_captura_pcap",
        description="Guia o agente de IA na validação, execução e análise forense de um arquivo PCAP de tráfego de rede.",
    )
    def prompt_analisar_pcap(nome_arquivo_pcap: str) -> str:
        return (
            f"Execute a análise forense offline da captura de rede '{nome_arquivo_pcap}':\n"
            f"1. Valide a integridade do arquivo com 'suricata_validar_arquivo_pcap'.\n"
            f"2. Execute a análise isolada no motor com 'suricata_analisar_pcap'.\n"
            f"3. Extraia e filtre os alertas gerados com 'suricata_extrair_alertas_pcap'.\n"
            f"4. Analise a distribuição de protocolos com 'suricata_analisar_protocolos_pcap'.\n"
            f"5. Gere o relatório técnico conclusivo com 'suricata_gerar_relatorio_pcap'."
        )

    @server.prompt(
        name="auditar_sensor_suricata",
        description="Realiza uma auditoria 360° no sensor Suricata verificando conectividade, EVE JSON, regras e desempenho.",
    )
    def prompt_auditar_sensor() -> str:
        return (
            "Realize uma auditoria completa de saúde no sensor Suricata:\n"
            "1. Teste a conectividade aos recursos com 'suricata_testar_conexao'.\n"
            "2. Verifique a integridade dos diretórios e arquivos com 'suricata_verificar_integridade_sensor'.\n"
            "3. Avalie métricas de pacotes e descarte com 'suricata_monitorar_drops'.\n"
            "4. Verifique a validade da configuração atual com 'suricata_validar_configuracao'.\n"
            "5. Produza o diagnóstico consolidado com 'suricata_diagnosticar_ambiente'."
        )

    @server.prompt(
        name="revisar_regras_falsos_positivos",
        description="Identifica assinaturas hiperativas e orienta o processo seguro de tuning e revisão de regras.",
    )
    def prompt_revisar_regras(min_alertas: int = 30) -> str:
        return (
            f"Execute o procedimento de tuning de regras para mitigar falsos positivos (limiar: {min_alertas} alertas):\n"
            f"1. Identifique assinaturas candidatas com 'suricata_identificar_falsos_positivos_candidatos'.\n"
            f"2. Consulte a definição da regra ruidosa com 'suricata_consultar_regra'.\n"
            f"3. Se confirmada como benigna, prepare o diff de ajuste com 'suricata_previsualizar_alteracao_regras'.\n"
            f"4. Aplique a modificação no conjunto local com aprovação prévia via 'suricata_desativar_regra_local'.\n"
            f"5. Recarregue o conjunto de regras do motor com 'suricata_recarregar_regras'."
        )

    return server


def run_doctor() -> int:
    """Diagnóstico de ambiente para verificar pré-requisitos e gerar configurações prontas para clientes MCP."""
    if hasattr(sys.stdout, "reconfigure"):
        with contextlib.suppress(Exception):
            sys.stdout.reconfigure(encoding="utf-8")

    settings = get_settings()

    print("=" * 72)
    print("[*] SURICATA MCP SERVER - DIAGNOSTICO DE AMBIENTE & CONFIGURACAO")
    print("=" * 72)
    print(f"Sistema Operacional: {platform.system()} {platform.release()} ({os.name})")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    print(f"Versão do Pacote: {settings.app_version}")
    print(f"Modo de Operação RBAC: {settings.mcp_operation_mode}")
    print("-" * 72)

    all_ok = True

    # 1. Executável do Suricata
    suricata_bin = shutil.which(settings.suricata_executable) or (
        settings.suricata_executable if Path(settings.suricata_executable).is_file() else None
    )
    if suricata_bin:
        version_str = "Versão não identificada"
        try:
            res = subprocess.run([suricata_bin, "-V"], capture_output=True, text=True, timeout=5)
            version_str = (res.stdout or res.stderr).strip().splitlines()[0]
        except Exception:
            pass
        print(f"[OK]  Executável Suricata: {suricata_bin} ({version_str})")
    else:
        print(f"[!]   Executável Suricata: '{settings.suricata_executable}' não encontrado no PATH nem no disco.")
        print("      Dica: Defina a variável SURICATA_EXECUTABLE com o caminho correto.")
        all_ok = False

    # 2. Arquivo de Configuração
    config_p = Path(settings.suricata_config_path)
    if config_p.is_file():
        print(f"[OK]  Arquivo suricata.yaml: {config_p.resolve()}")
    else:
        print(f"[!]   Arquivo suricata.yaml: '{settings.suricata_config_path}' não encontrado.")
        print("      Dica: Defina a variável SURICATA_CONFIG_PATH com o caminho do seu suricata.yaml.")
        all_ok = False

    # 3. Log de Eventos EVE JSON
    eve_p = Path(settings.suricata_eve_path)
    if eve_p.is_file():
        size_mb = eve_p.stat().st_size / (1024 * 1024)
        print(f"[OK]  Arquivo EVE JSON: {eve_p.resolve()} ({size_mb:.2f} MB)")
    else:
        print(f"[!]   Arquivo EVE JSON: '{settings.suricata_eve_path}' não encontrado.")
        print("      Dica: Verifique se o Suricata está gravando em eve.json ou ajuste SURICATA_EVE_PATH.")
        all_ok = False

    # 4. Diretório de Regras
    rules_p = Path(settings.suricata_rules_dir)
    if rules_p.is_dir():
        rule_count = len(list(rules_p.glob("*.rules")))
        print(f"[OK]  Diretório de regras: {rules_p.resolve()} ({rule_count} arquivos .rules)")
    else:
        print(f"[INFO] Diretório de regras '{settings.suricata_rules_dir}' não localizado (opcional se não usar gestão local).")

    # 5. Diretório de PCAPs
    pcap_p = Path(settings.suricata_pcap_allowed_dir)
    pcap_p.mkdir(parents=True, exist_ok=True)
    print(f"[OK]  Diretório permitido para PCAPs: {pcap_p.resolve()}")

    # 6. Diretório de Relatórios
    report_p = Path(settings.mcp_report_output_dir)
    report_p.mkdir(parents=True, exist_ok=True)
    print(f"[OK]  Diretório de relatórios gerados: {report_p.resolve()}")

    print("=" * 72)
    print("📋 CONFIGURAÇÃO RECOMENDADA PARA SEU CLIENTE MCP (COPIE E COLE)")
    print("=" * 72)

    # Exemplo Universal com uvx (funciona em qualquer máquina do mundo)
    universal_uvx_config = {
        "mcpServers": {
            "suricata": {
                "command": "uvx",
                "args": [
                    "--from",
                    "git+https://github.com/nks1097/suricata-mcp-server.git",
                    "suricata-mcp",
                ],
                "env": {
                    "SURICATA_CONFIG_PATH": str(config_p).replace("\\", "/"),
                    "SURICATA_EVE_PATH": str(eve_p).replace("\\", "/"),
                    "MCP_OPERATION_MODE": settings.mcp_operation_mode,
                },
            }
        }
    }

    # Exemplo com Python local
    local_python_config = {
        "mcpServers": {
            "suricata": {
                "command": sys.executable.replace("\\", "/"),
                "args": ["-m", "suricata_mcp.server", "--transport", "stdio"],
                "env": {
                    "SURICATA_CONFIG_PATH": str(config_p).replace("\\", "/"),
                    "SURICATA_EVE_PATH": str(eve_p).replace("\\", "/"),
                    "MCP_OPERATION_MODE": settings.mcp_operation_mode,
                },
            }
        }
    }

    print("\nOpção 1: Execução Universal com uvx (Sem clonar, sem instalar nada manualmente):")
    print(json.dumps(universal_uvx_config, indent=2))

    print("\nOpção 2: Execução com o Python atual desta máquina:")
    print(json.dumps(local_python_config, indent=2))

    print("=" * 72)
    return 0 if all_ok else 1


def main() -> None:
    """Função de inicialização via linha de comando."""
    settings = get_settings()

    parser = argparse.ArgumentParser(
        description="Suricata MCP Server - Servidor Model Context Protocol com 100 ferramentas para Suricata IDS/IPS"
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Executa diagnóstico completo de ambiente, verifica Suricata e gera snippets de configuração prontos",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default=settings.mcp_transport,
        help="Tipo de transporte do protocolo MCP (padrão: stdio)",
    )
    parser.add_argument("--host", default=settings.mcp_host, help="Host para escuta em modo SSE")
    parser.add_argument("--port", type=int, default=settings.mcp_port, help="Porta para escuta em modo SSE")
    args = parser.parse_args()

    if args.doctor:
        sys.exit(run_doctor())

    server = create_server()

    if args.transport == "sse":
        logger.info("Iniciando Suricata MCP Server em modo SSE em %s:%d", args.host, args.port)
        server.run(transport="sse", host=args.host, port=args.port)
    else:
        logger.info("Iniciando Suricata MCP Server em modo STDIO...")
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
