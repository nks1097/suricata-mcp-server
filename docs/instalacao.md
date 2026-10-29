# Guia de Instalação do Suricata MCP Server

O **Suricata MCP Server** pode ser executado nativamente em ambientes Linux e Windows ou em contêineres Docker.

---

## 1. Requisitos do Sistema

* **Python:** 3.11, 3.12, 3.13 ou 3.14.
* **Suricata:** Versões 6.x, 7.x ou 8.x (testado e homologado no Suricata 8.0.7).
* **Gerenciador de Pacotes:** `uv` (recomendado para máxima velocidade) ou `pip`.

---

## 2. Instalação Local com `uv` (Recomendado)

### Windows (PowerShell):
```powershell
# 1. Navegue até o diretório do projeto
cd "C:\Users\Natanael Krindges\.gemini\antigravity-ide\mcp\suricata"

# 2. Crie o ambiente virtual isolado
uv venv

# 3. Ative o ambiente virtual
.\.venv\Scripts\Activate.ps1

# 4. Instale o pacote e as dependências
uv pip install -e .

# 5. Copie o arquivo de configuração
Copy-Item .env.example .env
```

### Linux / macOS (Bash):
```bash
# 1. Clone ou navegue até o repositório
cd suricata-mcp-server

# 2. Crie e ative o ambiente virtual
uv venv
source .venv/bin/activate

# 3. Instale o pacote
uv pip install -e .

# 4. Copie o arquivo de variáveis de ambiente
cp .env.example .env
```

---

## 3. Instalação e Execução com Docker

O projeto inclui um `Dockerfile` multi-stage otimizado e seguro executando como usuário não-root:

```bash
# Construção da imagem Docker
docker compose build

# Execução em segundo plano com transporte SSE (porta 8080)
docker compose up -d

# Visualização de logs
docker compose logs -f suricata-mcp
```

---

## 4. Configuração do Cliente MCP

### Claude Desktop (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "suricata": {
      "command": "C:\\Users\\Natanael Krindges\\.gemini\\antigravity-ide\\mcp\\suricata\\.venv\\Scripts\\suricata-mcp.exe",
      "args": ["--transport", "stdio"],
      "env": {
        "SURICATA_CONFIG_PATH": "C:/Program Files/Suricata/suricata.yaml",
        "SURICATA_EVE_PATH": "C:/Program Files/Suricata/log/eve.json",
        "SURICATA_LOG_DIR": "C:/Program Files/Suricata/log",
        "MCP_OPERATION_MODE": "operacional"
      }
    }
  }
}
```

### Antigravity IDE (`mcp_config.json`):
```json
{
  "mcpServers": {
    "suricata-mcp": {
      "command": "python",
      "args": ["-m", "suricata_mcp.server", "--transport", "stdio"],
      "cwd": "C:/Users/Natanael Krindges/.gemini/antigravity-ide/mcp/suricata",
      "env": {
        "SURICATA_CONFIG_PATH": "C:/Program Files/Suricata/suricata.yaml",
        "SURICATA_EVE_PATH": "C:/Program Files/Suricata/log/eve.json"
      }
    }
  }
}
```

