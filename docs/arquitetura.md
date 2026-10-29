# Arquitetura do Suricata MCP Server

O **Suricata MCP Server** (`suricata-mcp`) foi desenvolvido seguindo os princípios de computação defensiva, isolamento de privilégios (RBAC), alta performance de processamento incremental e desacoplamento modular.

## Visão Geral da Arquitetura

```
+-------------------------------------------------------------+
|                Agente de IA / Cliente MCP                   |
|       (Claude Desktop, Cursor, Antigravity IDE, etc.)       |
+-------------------------------------------------------------+
                              |
                     [ STDIO / SSE Transport ]
                              v
+-------------------------------------------------------------+
|                     Suricata MCP Server                     |
|                                                             |
|  +-------------------------------------------------------+  |
|  |           Camada de Autorização & RBAC                |  |
|  |  (somente_leitura | operacional | administrativo)     |  |
|  +-------------------------------------------------------+  |
|                             |                               |
|  +-------------------------------------------------------+  |
|  |           Trilha de Auditoria & Redação Segredos      |  |
|  |           (JSON Lines / Sanitização de IoCs)          |  |
|  +-------------------------------------------------------+  |
|                             |                               |
|  +-------------------------------------------------------+  |
|  |                 100 Ferramentas MCP                   |  |
|  |  [A: Sensores] [B: EVE] [C: Rede] [D: Detecção]       |  |
|  |  [E: Regras]   [F: PCAP] [G: Performance]             |  |
|  |  [H: Config]   [I: Resposta] [J: Relatórios]          |  |
|  +-------------------------------------------------------+  |
+-------------------------------------------------------------+
          |                   |                     |
          v                   v                     v
+------------------+ +------------------+ +-------------------+
|  EVE JSON Engine | | Subprocess Runner| | Unix Socket Client|
|  - Tail 64KB seek| | - List args only | | - JSON-RPC        |
|  - Streaming mem | | - Timeout estrito| | - Live reload     |
|  - Time filter   | | - Whitelist bin  | | - Dump counters   |
+------------------+ +------------------+ +-------------------+
          |                   |                     |
          +-------------------+---------------------+
                              v
+-------------------------------------------------------------+
|                       Motor Suricata                        |
|        (suricata.exe / Linux Daemon / EVE JSON / Rules)     |
+-------------------------------------------------------------+
```

## Componentes Fundamentais

### 1. Leitor Incremental de EVE JSON (`eve_reader.py`)
Arquivos `eve.json` em produção frequentemente atingem dezenas de gigabytes por dia. Carregar esses arquivos inteiros em memória causaria exaustão imediata de RAM (OOM).
* **Seek Reverso por Blocos:** Para consultas de alertas e telemetria recentes, o leitor realiza saltos de bloco (chunks de 64 KB) a partir do fim do arquivo, retornando em milissegundos sem ler o histórico antigo.
* **Streaming Sequencial:** Para processamento forense ou exportações em lote, utiliza geradores iterativos (`yield`) com consumo constante de memória (< 50 MB de RAM).

### 2. Validador de Regras e Gestão Local (`rule_manager.py`)
* Decompõe assinaturas em estruturas AST (`action`, `proto`, `src`, `direction`, `dst`, `options`).
* Impede colisão de Signature IDs (SIDs).
* Gera cópias de segurança com timestamp (`.bak`) e diffs unificados antes de qualquer alteração física no disco.

### 3. Analisador Forense de PCAP (`pcap_analyzer.py`)
* Valida magic bytes (`libpcap` e `pcapng`) e limita o tamanho máximo configurado (`SURICATA_MAX_PCAP_SIZE_MB`).
* Isola a execução offline em diretórios temporários descartáveis.

### 4. Motor de Relatórios Multi-Formato (`report_engine.py`)
* Gera relatórios formatados em PDF nativo com tabelas estilizadas (ReportLab).
* Gera planilhas multi-abas formatadas em XLSX (OpenPyXL).
* Exporta telemetria bruta em CSV e JSON estruturado.
