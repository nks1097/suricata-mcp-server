# Solução de Problemas (Troubleshooting)

Guia de diagnóstico e resolução dos cenários de falha mais comuns ao utilizar o **Suricata MCP Server**.

---

## 1. Erro: "Arquivo EVE JSON não encontrado ou inacessível"

* **Causa:** O caminho configurado em `SURICATA_EVE_PATH` no arquivo `.env` não existe ou o Suricata não está gravando eventos.
* **Resolução:**
  1. Verifique se o Suricata está rodando.
  2. Abra o arquivo `suricata.yaml` e confirme se a seção `eve-log` está habilitada:
     ```yaml
     outputs:
       - eve-log:
           enabled: yes
           filetype: regular
           filename: eve.json
     ```
  3. Ajuste o caminho no `.env` para o local exato onde o arquivo está sendo gerado.

---

## 2. Erro: "Acesso negado: o caminho ... está fora dos limites autorizados"

* **Causa:** A política anti-path traversal bloqueou uma tentativa de abrir arquivo fora da pasta autorizada.
* **Resolução:** Certifique-se de que seus arquivos PCAP estejam localizados dentro do diretório configurado em `SURICATA_PCAP_ALLOWED_DIR` (padrão: `./pcaps`).

---

## 3. Erro: "Privilégio insuficiente: a operação requer nível 'administrativo'"

* **Causa:** O servidor está executando em modo `somente_leitura` ou `operacional` e recebeu uma solicitação para gravar regras ou alterar a configuração.
* **Resolução:**
  1. No arquivo `.env`, altere:
     ```ini
     MCP_OPERATION_MODE="administrativo"
     MCP_READ_ONLY=false
     ```
  2. Reinicie o servidor MCP.

---

## 4. O cliente MCP trava ou corrompe a comunicação via STDIO

* **Causa:** Alguma biblioteca ou módulo gravou mensagens de log diretamente no `stdout` (padrão de saída do sistema), violando o protocolo JSON-RPC do MCP.
* **Resolução:** O Suricata MCP Server direciona todos os seus logs para `stderr`. Verifique se você não adicionou chamadas a `print()` em código customizado.

---

## 5. Erro no Windows: "O termo 'uvx' não é reconhecido como nome de cmdlet"

* **Causa:** O instalador do `uv` colocou os binários em `%USERPROFILE%\.local\bin`, mas a janela do PowerShell atual ainda não recarregou as variáveis de ambiente `$env:Path`.
* **Resolução:**
  * **Opção rápida na mesma janela:** Execute `$env:Path = "$HOME\.local\bin;$env:Path"`.
  * **Opção 2:** Feche a janela atual do PowerShell e abra uma nova janela.
  * **Opção 3:** Chame o binário pelo caminho completo: `& "$HOME\.local\bin\uvx.exe" ...`.
  * **Opção 4 (Alternativa sem uv):** Instale via `pip install git+https://github.com/nks1097/suricata-mcp-server.git`.

---

## 6. Claude Desktop relata erro "Command not found: uvx"

* **Causa:** No Windows, o Claude Desktop é um aplicativo com interface gráfica que nem sempre herda as alterações recentes do PATH do usuário feitas via terminal.
* **Resolução:** No arquivo `claude_desktop_config.json`, configure o caminho absoluto do `uvx.exe`:
  ```json
  "command": "C:\\Users\\SEU_USUARIO\\.local\\bin\\uvx.exe"
  ```
  Ou use o interpretador Python do sistema:
  ```json
  "command": "python",
  "args": ["-m", "suricata_mcp.server", "--transport", "stdio"]
  ```

