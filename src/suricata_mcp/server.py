"""Ponto de entrada principal do Suricata MCP Server.

Inicializa a instância MCPServer, registra as 100 ferramentas especializadas em português,
configura prompts para agentes de IA e gerencia os transportes STDIO e SSE.
"""

import argparse
import logging
import sys

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


def main() -> None:
    """Função de inicialização via linha de comando."""
    settings = get_settings()

    parser = argparse.ArgumentParser(description="Suricata MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default=settings.mcp_transport,
        help="Tipo de transporte do protocolo MCP (padrão: stdio)",
    )
    parser.add_argument("--host", default=settings.mcp_host, help="Host para escuta em modo SSE")
    parser.add_argument("--port", type=int, default=settings.mcp_port, help="Porta para escuta em modo SSE")
    args = parser.parse_args()

    server = create_server()

    if args.transport == "sse":
        logger.info("Iniciando Suricata MCP Server em modo SSE em %s:%d", args.host, args.port)
        server.run(transport="sse", host=args.host, port=args.port)
    else:
        logger.info("Iniciando Suricata MCP Server em modo STDIO...")
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
