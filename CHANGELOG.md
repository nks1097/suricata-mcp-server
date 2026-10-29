# Changelog

Todas as alterações notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [1.0.0] - 2026-10-29

### Adicionado
- Lançamento inicial oficial do **Suricata MCP Server** (`suricata-mcp`).
- Implementação completa de **100 ferramentas MCP** em português divididas em 10 categorias essenciais:
  - Categoria A (1–10): Sensores e estado operacional.
  - Categoria B (11–20): Eventos EVE e pesquisa de telemetria.
  - Categoria C (21–30): Análise de rede, tráfego e conexões.
  - Categoria D (31–40): Alertas e engenharia de detecção de ameaças.
  - Categoria E (41–50): Regras, assinaturas e `suricata-update`.
  - Categoria F (51–60): PCAP e análise forense offline.
  - Categoria G (61–70): Estatísticas, volumetria e desempenho do motor.
  - Categoria H (71–80): Configuração (`suricata.yaml`) e gestão operacional.
  - Categoria I (81–90): Resposta defensiva, SIEM e evidências.
  - Categoria J (91–100): Relatórios executivos (PDF/XLSX/CSV/JSON), auditoria e automação.
- Leitor incremental de alto desempenho para arquivos `eve.json` gigabytes via streaming e backward tailing.
- Suporte a comandos de controle via Unix Domain Socket e Named Pipe com fallback de auto-detecção.
- Validação estrita de sintaxe de regras Suricata e configurações com preservação de backups.
- Motor de relatórios profissionais com suporte a PDF (ReportLab), planilhas XLSX (OpenPyXL), CSV, JSON e Markdown.
- Sistema de controle de acesso baseado em funções (RBAC) com modos `somente_leitura`, `operacional` e `administrativo`.
- Registro e consulta de auditoria estruturada em JSON com redação automática de segredos.
- Execução segura de subprocessos com lista de argumentos, proteção contra injeção e timeouts rigorosos.
- Suporte a transportes MCP STDIO e SSE.
- Cobertura completa de testes unitários com fixtures sintéticas.
- Documentação internacional (Português e Inglês) e guias operacionais de produção.

