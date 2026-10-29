# Catálogo das 100 Ferramentas MCP do Suricata

O servidor implementa **100 ferramentas em português**, rigorosamente tipadas e com envelopes padronizados de resposta.

---

## Categoria A — Sensores e Estado Operacional (01 a 10)

1. `suricata_testar_conexao`: Verifica conectividade e acesso aos arquivos configurados.
2. `suricata_obter_versao`: Consulta a versão oficial do binário Suricata instalado.
3. `suricata_obter_estado_sensor`: Consulta o estado operacional observável e tempo de atividade.
4. `suricata_listar_interfaces`: Lista interfaces de rede monitoradas no escopo autorizado.
5. `suricata_consultar_configuracao_carregada`: Inspeciona parâmetros permitidos do motor.
6. `suricata_obter_estatisticas`: Recupera contadores e métricas via socket ou EVE JSON.
7. `suricata_consultar_estado_socket`: Verifica disponibilidade do Unix Domain Socket ou Named Pipe.
8. `suricata_consultar_logs_operacionais`: Consulta linhas recentes de `suricata.log`.
9. `suricata_verificar_integridade_sensor`: Verifica saúde de executáveis, pastas e permissões.
10. `suricata_diagnosticar_sensor`: Produz diagnóstico fundamentado e recomendações de otimização.

---

## Categoria B — Eventos EVE e Pesquisa de Telemetria (11 a 20)

11. `suricata_pesquisar_eventos`: Busca eventos no `eve.json` com filtros temporais, IPs e portas.
12. `suricata_consultar_alertas`: Recupera alertas de segurança (tipo: `alert`).
13. `suricata_consultar_eventos_fluxo`: Consulta eventos de fluxo de rede (tipo: `flow`).
14. `suricata_consultar_eventos_dns`: Consulta eventos de resolução DNS (tipo: `dns`).
15. `suricata_consultar_eventos_http`: Consulta transações HTTP (tipo: `http`).
16. `suricata_consultar_eventos_tls`: Consulta sessões criptografadas TLS e certificados (tipo: `tls`).
17. `suricata_consultar_anomalias`: Consulta anomalias de protocolo e pacotes corrompidos (tipo: `anomaly`).
18. `suricata_consultar_eventos_arquivos`: Consulta metadados de arquivos detectados (tipo: `fileinfo`).
19. `suricata_consultar_eventos_ssh`: Consulta conexões e versões de software SSH (tipo: `ssh`).
20. `suricata_obter_resumo_eventos`: Consolida volumetria e distribuições de tipos de evento.

---

## Categoria C — Análise de Rede e Conexões (21 a 30)

21. `suricata_investigar_ip`: Correlaciona todos os eventos e alertas de um IP específico.
22. `suricata_investigar_conexao`: Analisa uma conexão específica por 5-tuple.
23. `suricata_identificar_ips_mais_ativos`: Classifica os principais geradores de tráfego (Top Talkers).
24. `suricata_identificar_portas_mais_ativas`: Analisa ranking de portas TCP/UDP de origem e destino.
25. `suricata_analisar_protocolos`: Analisa a proporção de protocolos de transporte e aplicação.
26. `suricata_analisar_conexoes_suspeitas`: Identifica conexões em portas anômalas ou de trojans conhecidos.
27. `suricata_detectar_varreduras_rede`: Identifica varreduras de portas e hosts (Portscan/Hostscan defensivo).
28. `suricata_detectar_padroes_dns_suspeitos`: Investiga domínios DGA (alta entropia) e tunelamento DNS.
29. `suricata_analisar_sessoes_tls`: Analisa SNIs frequentes e versões de protocolo TLS.
30. `suricata_gerar_linha_tempo_rede`: Organiza eventos em cronologia forense para investigação.

---

## Categoria D — Alertas e Engenharia de Detecção (31 a 40)

31. `suricata_obter_alerta`: Recupera os detalhes completos do alerta mais recente ou por SID.
32. `suricata_filtrar_alertas_por_severidade`: Filtra alertas por nível de severidade (1 a 4).
33. `suricata_agrupar_alertas_por_assinatura`: Agrupa e conta alertas por nome de regra e SID.
34. `suricata_analisar_frequencia_alertas`: Identifica recorrência e frequência de alertas por hora.
35. `suricata_detectar_picos_alertas`: Detecta picos anormais de disparo em janelas de minutos.
36. `suricata_correlacionar_alertas`: Correlaciona alertas disparados pelo mesmo ator ou alvo.
37. `suricata_investigar_indicador_comprometimento`: Pesquisa IoC (IP, domínio, hash) em toda a telemetria.
38. `suricata_classificar_incidente`: Sugere classificação defensiva fundamentada com severidade e confiança.
39. `suricata_identificar_falsos_positivos_candidatos`: Identifica regras hiperativas para revisão de tuning.
40. `suricata_gerar_relatorio_investigacao`: Produz dossiê técnico estruturado sobre um alvo investigado.

---

## Categoria E — Regras e Assinaturas (41 a 50)

41. `suricata_listar_regras`: Lista regras instaladas e seus metadados.
42. `suricata_consultar_regra`: Consulta a definição de uma regra pelo SID.
43. `suricata_pesquisar_regras`: Pesquisa regras por texto, mensagem ou classtype.
44. `suricata_validar_regra`: Valida rigorosamente a sintaxe de uma regra proposta.
45. `suricata_previsualizar_alteracao_regras`: Gera diff antes de gravar em `local.rules`.
46. `suricata_adicionar_regra_local`: Adiciona regra validada com backup automático.
47. `suricata_atualizar_regra_local`: Atualiza regra local existente por SID.
48. `suricata_desativar_regra_local`: Comenta regra no arquivo local mantendo histórico.
49. `suricata_atualizar_conjunto_regras`: Executa `suricata-update` para atualizar assinaturas.
50. `suricata_recarregar_regras`: Solicita recarga a quente no motor sem reiniciar.

---

## Categoria F — PCAP e Análise Forense Offline (51 a 60)

51. `suricata_analisar_pcap`: Executa análise offline de captura PCAP no motor Suricata.
52. `suricata_validar_arquivo_pcap`: Valida magic bytes, integridade e tamanho de arquivo PCAP.
53. `suricata_resumir_pcap`: Produz resumo de alertas e fluxos de uma captura.
54. `suricata_extrair_alertas_pcap`: Extrai lista de alertas de uma análise offline.
55. `suricata_analisar_protocolos_pcap`: Resume protocolos identificados no PCAP.
56. `suricata_analisar_fluxos_pcap`: Resume fluxos bidirecionais observados na captura.
57. `suricata_comparar_pcaps`: Compara estatísticas e alertas entre duas capturas.
58. `suricata_pesquisar_eventos_pcap`: Filtra eventos de uma análise de captura específica.
59. `suricata_gerar_relatorio_pcap`: Gera relatório conclusivo de análise de PCAP.
60. `suricata_limpar_artefatos_analise`: Remove diretórios temporários de análise com segurança.

---

## Categoria G — Estatísticas e Desempenho do Motor (61 a 70)

61. `suricata_analisar_desempenho`: Analisa métricas de pacotes capturados e processamento.
62. `suricata_monitorar_drops`: Monitora taxa de perda e descarte de pacotes no kernel.
63. `suricata_analisar_captura`: Investiga contadores detalhados do módulo de captura.
64. `suricata_analisar_fluxos_ativos`: Analisa contadores de sessão TCP/UDP e timeouts.
65. `suricata_analisar_uso_memoria`: Analisa consumo de memória das tabelas de fluxo e buffers.
66. `suricata_analisar_threads`: Consulta contadores segregados por thread de execução.
67. `suricata_detectar_degradacao_sensor`: Detecta sinais de saturação e degradação operacional.
68. `suricata_comparar_estatisticas`: Compara métricas históricas de pacotes no EVE JSON.
69. `suricata_monitorar_volume_eventos`: Analisa volumetria e taxa de geração de telemetria.
70. `suricata_gerar_relatorio_desempenho`: Gera resumo técnico estruturado do desempenho do sensor.

---

## Categoria H — Configuração e Gestão Operacional (71 a 80)

71. `suricata_validar_configuracao`: Executa validação de sintaxe e estrutura do `suricata.yaml`.
72. `suricata_consultar_parametros_configuracao`: Consulta seções específicas de configuração.
73. `suricata_previsualizar_configuracao`: Exibe o diff de uma alteração proposta no YAML.
74. `suricata_atualizar_configuracao_autorizada`: Aplica nova configuração após teste e backup.
75. `suricata_reabrir_logs`: Solicita reabertura de arquivos de log para rotação (logrotate).
76. `suricata_consultar_estado_recarga`: Consulta evidências de recarga registradas no log.
77. `suricata_verificar_arquivos_regras`: Verifica integridade dos arquivos de regras no disco.
78. `suricata_verificar_saida_eve`: Inspeciona tamanho, atividade e status do `eve.json`.
79. `suricata_verificar_retencao_logs`: Verifica ocupação em disco e espaço livre disponível.
80. `suricata_diagnosticar_configuracao`: Identifica inconsistências e sugere boas práticas.

---

## Categoria I — Resposta Defensiva e Integrações SIEM (81 a 90)

81. `suricata_planejar_resposta_incidente`: Gera plano de ação defensivo sem bloqueios destrutivos.
82. `suricata_registrar_incidente`: Registra um novo incidente no repositório local do MCP.
83. `suricata_atualizar_incidente`: Atualiza o status e adiciona notas de investigação.
84. `suricata_exportar_indicadores`: Exporta IoCs observados em formato estruturado.
85. `suricata_consultar_reputacao_ip`: Avalia o score de risco local de um IP com base em alertas.
86. `suricata_consultar_reputacao_dominio`: Verifica se um domínio foi observado em anomalias ou alertas.
87. `suricata_enviar_eventos_siem`: Encaminha lote de eventos para integração SIEM.
88. `suricata_verificar_integracao_siem`: Verifica disponibilidade de canais SIEM e forwarders.
89. `suricata_notificar_incidente`: Dispara alerta estruturado para canais do SOC.
90. `suricata_gerar_pacote_evidencias`: Gera arquivo forense com hash SHA-256 de integridade.

---

## Categoria J — Relatórios, Auditoria e Automação (91 a 100)

91. `suricata_gerar_relatorio_executivo`: Gera resumo executivo de segurança e postura defensiva.
92. `suricata_gerar_relatorio_alertas`: Gera relatório consolidado de alertas por severidade.
93. `suricata_gerar_relatorio_indicadores`: Consolida IPs, domínios e portas em relatório.
94. `suricata_gerar_relatorio_incidente`: Gera relatório técnico completo para equipes de resposta.
95. `suricata_exportar_relatorio_pdf`: Exporta relatório executivo estilizado em arquivo PDF.
96. `suricata_exportar_relatorio_excel`: Exporta dados em pasta de trabalho Excel (.xlsx) multi-abas.
97. `suricata_exportar_eventos_csv_json`: Exporta eventos recentes em formato CSV ou JSON.
98. `suricata_executar_fluxo_aprovado`: Executa procedimento operacional pré-aprovado.
99. `suricata_consultar_auditoria_mcp`: Consulta o histórico e trilha de auditoria do MCP Server.
100. `suricata_diagnosticar_ambiente`: Produz diagnóstico 360° unificando sensor, regras e integridade.

