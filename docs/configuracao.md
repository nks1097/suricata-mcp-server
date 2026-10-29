# Guia de Configuração e Parâmetros

O **Suricata MCP Server** é 100% configurável por meio de variáveis de ambiente ou arquivo `.env`.

---

## Matriz Completa de Variáveis de Ambiente

| Variável | Tipo | Padrão | Descrição |
| :--- | :---: | :--- | :--- |
| `SURICATA_CONFIG_PATH` | Caminho | `.../suricata.yaml` | Caminho absoluto para o arquivo de configuração principal |
| `SURICATA_EVE_PATH` | Caminho | `.../log/eve.json` | Caminho do arquivo de eventos EVE JSON do Suricata |
| `SURICATA_LOG_DIR` | Caminho | `.../log` | Diretório onde ficam `suricata.log`, `fast.log`, etc. |
| `SURICATA_UNIX_SOCKET_PATH` | Caminho | `""` | Caminho do Unix Domain Socket (deixe vazio se desabilitado) |
| `SURICATA_EXECUTABLE` | Comando | `suricata` | Binário executável do motor Suricata |
| `SURICATA_UPDATE_EXECUTABLE`| Comando | `suricata-update` | Binário de atualização de regras (opcional) |
| `SURICATA_RULES_DIR` | Caminho | `.../rules` | Diretório contendo os arquivos `.rules` |
| `SURICATA_LOCAL_RULES_PATH` | Caminho | `.../rules/local.rules` | Arquivo para inclusão e gestão de regras locais |
| `SURICATA_PCAP_ALLOWED_DIR` | Caminho | `./pcaps` | Diretório restrito para análise offline de capturas |
| `SURICATA_MAX_PCAP_SIZE_MB` | Inteiro | `100` | Tamanho máximo de arquivo PCAP aceito para processamento |
| `SURICATA_MAX_RESULTS` | Inteiro | `500` | Limite padrão de eventos retornados por consulta |
| `SURICATA_COMMAND_TIMEOUT_SECONDS` | Inteiro | `30` | Timeout máximo para processos locais disparados |
| `SURICATA_VERIFY_CONFIG_BEFORE_WRITE` | Booleano | `true` | Exige validação via motor antes de gravar `suricata.yaml` |
| `MCP_OPERATION_MODE` | Enum | `operacional` | Perfis: `somente_leitura`, `operacional`, `administrativo` |
| `MCP_READ_ONLY` | Booleano | `false` | Força modo somente leitura irrestrito se `true` |
| `MCP_AUDIT_ENABLED` | Booleano | `true` | Habilita trilha de auditoria em arquivo JSON Lines |
| `MCP_AUDIT_LOG_PATH` | Caminho | `./audit.log` | Caminho onde o arquivo de auditoria será gravado |
| `MCP_REPORT_OUTPUT_DIR` | Caminho | `./reports_output` | Diretório para exportação de PDFs, XLSX, CSVs e JSONs |
| `MCP_TRANSPORT` | Enum | `stdio` | Transporte MCP (`stdio` para local, `sse` para web) |
| `MCP_HOST` | String | `127.0.0.1` | Host de escuta em modo SSE |
| `MCP_PORT` | Inteiro | `8080` | Porta de escuta em modo SSE |
| `MCP_LOG_LEVEL` | Enum | `INFO` | Nível de log do servidor (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## Modos de Operação (RBAC)

1. **`somente_leitura` (Read-Only):**
   * Acesso liberado apenas a ferramentas de consulta (Categorias A, B, C, D, G).
   * Qualquer tentativa de modificar regras ou configurações dispara `SuricataPermissionDeniedError`.

2. **`operacional` (Padrão):**
   * Permite consultas completas, execução forense de PCAPs, exportação de relatórios (PDF/XLSX/CSV) e planejamento defensivo.
   * Não permite alteração de arquivos de configuração do sistema ou exclusão de regras sem elevação.

3. **`administrativo`:**
   * Libera todas as 100 ferramentas, incluindo edição e adição de regras em `local.rules`, execução de `suricata-update` e atualização do `suricata.yaml`.

