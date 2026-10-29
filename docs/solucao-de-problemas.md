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

