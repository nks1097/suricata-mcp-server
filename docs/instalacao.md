# Guia de Instalação e Execução Universal do Suricata MCP Server

O **Suricata MCP Server** foi projetado para operar com zero atrito em qualquer ambiente: servidores Linux de produção (Ubuntu, Debian, RedHat, Rocky, CentOS), contêineres Docker, estações de trabalho Windows ou macOS.

---

## 🚀 Método 1: Zero-Install com `uvx` (Recomendado)

Se você já possui o `uv` instalado, **não é necessário clonar o repositório nem gerenciar ambientes virtuais manualmente**. O `uvx` baixa, isola e executa o servidor instantaneamente a partir do GitHub:

```bash
uvx --from git+https://github.com/nks1097/suricata-mcp-server.git suricata-mcp --doctor
```

### Como instalar o `uv` caso ainda não possua:
* **Windows (PowerShell):**
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  # ATENÇÃO: Recarregue o PATH da sua janela atual:
  $env:Path = "$HOME\.local\bin;$env:Path"
  ```
* **Linux / macOS:**
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  source $HOME/.local/bin/env
  ```

> 💡 **Nota Windows:** Se o comando `uvx` retornar erro de comando não reconhecido, execute `$env:Path = "$HOME\.local\bin;$env:Path"` ou feche e reabra o terminal.

---

## 📦 Método 2: Instalação Direta com `pip` (Sem uv)
Se preferir usar o Python padrão sem instalar o `uv`:

```bash
pip install git+https://github.com/nks1097/suricata-mcp-server.git
python -m suricata_mcp --doctor
```

---

## 🛠️ Método 3: Instalação via Clone Local (Para Desenvolvedores)

### Linux / macOS
```bash
# 1. Clone o repositório oficial
git clone https://github.com/nks1097/suricata-mcp-server.git
cd suricata-mcp-server

# 2. Crie e ative o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# 3. Instale o pacote
pip install -e .

# 4. Copie o modelo de ambiente e ajuste se necessário
cp .env.example .env

# 5. Execute o diagnóstico automático
suricata-mcp --doctor
```

### Windows (PowerShell)
```powershell
# 1. Clone o repositório
git clone https://github.com/nks1097/suricata-mcp-server.git
cd suricata-mcp-server

# 2. Crie e ative o ambiente virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Instale o pacote
pip install -e .

# 4. Copie o arquivo de variáveis
copy .env.example .env

# 5. Execute o diagnóstico de ambiente
suricata-mcp --doctor
```

---

## 🐳 Método 3: Execução em Servidores e Produção com Docker

Para monitorar servidores Linux corporativos onde o Suricata roda no host:

### Docker Run (Modo STDIO):
```bash
docker run -i --rm \
  -v /var/log/suricata:/var/log/suricata:ro \
  -v /etc/suricata:/etc/suricata:ro \
  -v /var/run/suricata:/var/run/suricata:ro \
  -v /var/lib/suricata/rules:/var/lib/suricata/rules:rw \
  ghcr.io/nks1097/suricata-mcp-server:latest
```

### Docker Compose (Modo SSE / Webhook):
```bash
# Construção e inicialização em segundo plano na porta 8080
docker compose up -d

# Visualização dos logs
docker compose logs -f suricata-mcp
```

---

## 🩺 Diagnóstico Automático: `suricata-mcp --doctor`

O comando `suricata-mcp --doctor` verifica automaticamente:
1. Se o binário do Suricata está presente no PATH ou disco.
2. Se o arquivo `suricata.yaml` é legível e válido.
3. Se o log `eve.json` existe e seu tamanho atual.
4. Permissões de escrita nos diretórios de relatórios e auditoria.
5. Gera automaticamente o bloco JSON pronto para copiar e colar no seu cliente MCP.

---

## ⚙️ Configuração Pronta para Clientes MCP

### 1. Claude Desktop (`claude_desktop_config.json`)

#### Linux / macOS:
```json
{
  "mcpServers": {
    "suricata": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/nks1097/suricata-mcp-server.git",
        "suricata-mcp"
      ],
      "env": {
        "SURICATA_CONFIG_PATH": "/etc/suricata/suricata.yaml",
        "SURICATA_EVE_PATH": "/var/log/suricata/eve.json",
        "MCP_OPERATION_MODE": "operacional"
      }
    }
  }
}
```

#### Windows:
```json
{
  "mcpServers": {
    "suricata": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/nks1097/suricata-mcp-server.git",
        "suricata-mcp"
      ],
      "env": {
        "SURICATA_CONFIG_PATH": "C:/Program Files/Suricata/suricata.yaml",
        "SURICATA_EVE_PATH": "C:/Program Files/Suricata/log/eve.json",
        "MCP_OPERATION_MODE": "operacional"
      }
    }
  }
}
```

---

### 2. Cursor IDE (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "suricata": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/nks1097/suricata-mcp-server.git",
        "suricata-mcp"
      ]
    }
  }
}
```

---

### 3. VS Code (Cline / Roo Code / Copilot)
Adicione nas configurações do MCP (`settings.json` ou arquivo de configuração do plugin):
```json
{
  "mcpServers": {
    "suricata-mcp": {
      "command": "suricata-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "MCP_OPERATION_MODE": "operacional"
      }
    }
  }
}
```

---

### 4. Permissões de Leitura no Linux
No Linux, o arquivo `/var/log/suricata/eve.json` geralmente pertence ao usuário `suricata`. Para permitir que o MCP leia os eventos sem precisar de root:

```bash
# Adicione seu usuário ao grupo suricata
sudo usermod -aG suricata $USER

# Ou garanta permissão de leitura aos logs:
sudo chmod o+r /var/log/suricata/eve.json
```
