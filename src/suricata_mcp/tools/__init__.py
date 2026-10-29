"""Exportação consolidada e inventário canônico das 100 ferramentas do Suricata MCP Server."""

from collections.abc import Callable

# Categoria H — Configuração e gestão operacional (71 a 80)
from .configuracao import (
    suricata_atualizar_configuracao_autorizada,
    suricata_consultar_estado_recarga,
    suricata_consultar_parametros_configuracao,
    suricata_diagnosticar_configuracao,
    suricata_previsualizar_configuracao,
    suricata_reabrir_logs,
    suricata_validar_configuracao,
    suricata_verificar_arquivos_regras,
    suricata_verificar_retencao_logs,
    suricata_verificar_saida_eve,
)

# Categoria G — Estatísticas e desempenho do motor (61 a 70)
from .desempenho import (
    suricata_analisar_captura,
    suricata_analisar_desempenho,
    suricata_analisar_fluxos_ativos,
    suricata_analisar_threads,
    suricata_analisar_uso_memoria,
    suricata_comparar_estatisticas,
    suricata_detectar_degradacao_sensor,
    suricata_gerar_relatorio_desempenho,
    suricata_monitorar_drops,
    suricata_monitorar_volume_eventos,
)

# Categoria D — Alertas e engenharia de detecção (31 a 40)
from .deteccao import (
    suricata_agrupar_alertas_por_assinatura,
    suricata_analisar_frequencia_alertas,
    suricata_classificar_incidente,
    suricata_correlacionar_alertas,
    suricata_detectar_picos_alertas,
    suricata_filtrar_alertas_por_severidade,
    suricata_gerar_relatorio_investigacao,
    suricata_identificar_falsos_positivos_candidatos,
    suricata_investigar_indicador_comprometimento,
    suricata_obter_alerta,
)

# Categoria B — Eventos EVE e pesquisa de telemetria (11 a 20)
from .eventos import (
    suricata_consultar_alertas,
    suricata_consultar_anomalias,
    suricata_consultar_eventos_arquivos,
    suricata_consultar_eventos_dns,
    suricata_consultar_eventos_fluxo,
    suricata_consultar_eventos_http,
    suricata_consultar_eventos_ssh,
    suricata_consultar_eventos_tls,
    suricata_obter_resumo_eventos,
    suricata_pesquisar_eventos,
)

# Categoria F — PCAP e análise forense offline (51 a 60)
from .pcap import (
    suricata_analisar_fluxos_pcap,
    suricata_analisar_pcap,
    suricata_analisar_protocolos_pcap,
    suricata_comparar_pcaps,
    suricata_extrair_alertas_pcap,
    suricata_gerar_relatorio_pcap,
    suricata_limpar_artefatos_analise,
    suricata_pesquisar_eventos_pcap,
    suricata_resumir_pcap,
    suricata_validar_arquivo_pcap,
)

# Categoria C — Análise de rede e conexões (21 a 30)
from .rede import (
    suricata_analisar_conexoes_suspeitas,
    suricata_analisar_protocolos,
    suricata_analisar_sessoes_tls,
    suricata_detectar_padroes_dns_suspeitos,
    suricata_detectar_varreduras_rede,
    suricata_gerar_linha_tempo_rede,
    suricata_identificar_ips_mais_ativos,
    suricata_identificar_portas_mais_ativas,
    suricata_investigar_conexao,
    suricata_investigar_ip,
)

# Categoria E — Regras e assinaturas (41 a 50)
from .regras import (
    suricata_adicionar_regra_local,
    suricata_atualizar_conjunto_regras,
    suricata_atualizar_regra_local,
    suricata_consultar_regra,
    suricata_desativar_regra_local,
    suricata_listar_regras,
    suricata_pesquisar_regras,
    suricata_previsualizar_alteracao_regras,
    suricata_recarregar_regras,
    suricata_validar_regra,
)

# Categoria J — Relatórios, auditoria e automação (91 a 100)
from .relatorios import (
    suricata_consultar_auditoria_mcp,
    suricata_diagnosticar_ambiente,
    suricata_executar_fluxo_aprovado,
    suricata_exportar_eventos_csv_json,
    suricata_exportar_relatorio_excel,
    suricata_exportar_relatorio_pdf,
    suricata_gerar_relatorio_alertas,
    suricata_gerar_relatorio_executivo,
    suricata_gerar_relatorio_incidente,
    suricata_gerar_relatorio_indicadores,
)

# Categoria I — Resposta defensiva e integrações SIEM (81 a 90)
from .resposta import (
    suricata_atualizar_incidente,
    suricata_consultar_reputacao_dominio,
    suricata_consultar_reputacao_ip,
    suricata_enviar_eventos_siem,
    suricata_exportar_indicadores,
    suricata_gerar_pacote_evidencias,
    suricata_notificar_incidente,
    suricata_planejar_resposta_incidente,
    suricata_registrar_incidente,
    suricata_verificar_integracao_siem,
)

# Categoria A — Sensores e estado operacional (01 a 10)
from .sensores import (
    suricata_consultar_configuracao_carregada,
    suricata_consultar_estado_socket,
    suricata_consultar_logs_operacionais,
    suricata_diagnosticar_sensor,
    suricata_listar_interfaces,
    suricata_obter_estado_sensor,
    suricata_obter_estatisticas,
    suricata_obter_versao,
    suricata_testar_conexao,
    suricata_verificar_integridade_sensor,
)

ALL_TOOLS: list[Callable] = [
    # Categoria A (1 a 10)
    suricata_testar_conexao,
    suricata_obter_versao,
    suricata_obter_estado_sensor,
    suricata_listar_interfaces,
    suricata_consultar_configuracao_carregada,
    suricata_obter_estatisticas,
    suricata_consultar_estado_socket,
    suricata_consultar_logs_operacionais,
    suricata_verificar_integridade_sensor,
    suricata_diagnosticar_sensor,
    # Categoria B (11 a 20)
    suricata_pesquisar_eventos,
    suricata_consultar_alertas,
    suricata_consultar_eventos_fluxo,
    suricata_consultar_eventos_dns,
    suricata_consultar_eventos_http,
    suricata_consultar_eventos_tls,
    suricata_consultar_anomalias,
    suricata_consultar_eventos_arquivos,
    suricata_consultar_eventos_ssh,
    suricata_obter_resumo_eventos,
    # Categoria C (21 a 30)
    suricata_investigar_ip,
    suricata_investigar_conexao,
    suricata_identificar_ips_mais_ativos,
    suricata_identificar_portas_mais_ativas,
    suricata_analisar_protocolos,
    suricata_analisar_conexoes_suspeitas,
    suricata_detectar_varreduras_rede,
    suricata_detectar_padroes_dns_suspeitos,
    suricata_analisar_sessoes_tls,
    suricata_gerar_linha_tempo_rede,
    # Categoria D (31 a 40)
    suricata_obter_alerta,
    suricata_filtrar_alertas_por_severidade,
    suricata_agrupar_alertas_por_assinatura,
    suricata_analisar_frequencia_alertas,
    suricata_detectar_picos_alertas,
    suricata_correlacionar_alertas,
    suricata_investigar_indicador_comprometimento,
    suricata_classificar_incidente,
    suricata_identificar_falsos_positivos_candidatos,
    suricata_gerar_relatorio_investigacao,
    # Categoria E (41 a 50)
    suricata_listar_regras,
    suricata_consultar_regra,
    suricata_pesquisar_regras,
    suricata_validar_regra,
    suricata_previsualizar_alteracao_regras,
    suricata_adicionar_regra_local,
    suricata_atualizar_regra_local,
    suricata_desativar_regra_local,
    suricata_atualizar_conjunto_regras,
    suricata_recarregar_regras,
    # Categoria F (51 a 60)
    suricata_analisar_pcap,
    suricata_validar_arquivo_pcap,
    suricata_resumir_pcap,
    suricata_extrair_alertas_pcap,
    suricata_analisar_protocolos_pcap,
    suricata_analisar_fluxos_pcap,
    suricata_comparar_pcaps,
    suricata_pesquisar_eventos_pcap,
    suricata_gerar_relatorio_pcap,
    suricata_limpar_artefatos_analise,
    # Categoria G (61 a 70)
    suricata_analisar_desempenho,
    suricata_monitorar_drops,
    suricata_analisar_captura,
    suricata_analisar_fluxos_ativos,
    suricata_analisar_uso_memoria,
    suricata_analisar_threads,
    suricata_detectar_degradacao_sensor,
    suricata_comparar_estatisticas,
    suricata_monitorar_volume_eventos,
    suricata_gerar_relatorio_desempenho,
    # Categoria H (71 a 80)
    suricata_validar_configuracao,
    suricata_consultar_parametros_configuracao,
    suricata_previsualizar_configuracao,
    suricata_atualizar_configuracao_autorizada,
    suricata_reabrir_logs,
    suricata_consultar_estado_recarga,
    suricata_verificar_arquivos_regras,
    suricata_verificar_saida_eve,
    suricata_verificar_retencao_logs,
    suricata_diagnosticar_configuracao,
    # Categoria I (81 a 90)
    suricata_planejar_resposta_incidente,
    suricata_registrar_incidente,
    suricata_atualizar_incidente,
    suricata_exportar_indicadores,
    suricata_consultar_reputacao_ip,
    suricata_consultar_reputacao_dominio,
    suricata_enviar_eventos_siem,
    suricata_verificar_integracao_siem,
    suricata_notificar_incidente,
    suricata_gerar_pacote_evidencias,
    # Categoria J (91 a 100)
    suricata_gerar_relatorio_executivo,
    suricata_gerar_relatorio_alertas,
    suricata_gerar_relatorio_indicadores,
    suricata_gerar_relatorio_incidente,
    suricata_exportar_relatorio_pdf,
    suricata_exportar_relatorio_excel,
    suricata_exportar_eventos_csv_json,
    suricata_executar_fluxo_aprovado,
    suricata_consultar_auditoria_mcp,
    suricata_diagnosticar_ambiente,
]
