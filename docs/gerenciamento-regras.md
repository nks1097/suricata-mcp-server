# Gerenciamento Seguro de Regras e Assinaturas

O **Suricata MCP Server** permite consultar, validar e gerenciar regras de detecção de forma controlada, garantindo integridade e conformidade operacional.

---

## Estrutura Canônica de uma Regra

```
[ação] [protocolo] [origem_ip] [origem_porta] [direção] [destino_ip] [destino_porta] ([opções])
```

**Exemplo:**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)"; flow:established,to_server; content:"${jndi:"; nocase; classtype:attempted-admin; sid:2100498; rev:7;)
```

---

## Ciclo de Vida Seguro de Regras no MCP

1. **Validação Prévia:** Antes de qualquer gravação, a regra é inspecionada pela ferramenta `suricata_validar_regra` para certificar balanceamento de parênteses, ação válida e presença obrigatória de `msg` e `sid`.
2. **Previsão de Alteração (Diff):** A ferramenta `suricata_previsualizar_alteracao_regras` exibe exatamente o que será alterado no arquivo `local.rules`.
3. **Backup Automático:** Toda operação de escrita cria previamente uma cópia do arquivo no formato `local.rules.<YYYYMMDD_HHMMSS>.bak`.
4. **Aplicação com Privilégio Administrativo:** Requer que o MCP esteja configurado em `MCP_OPERATION_MODE=administrativo`.
5. **Recarga a Quente (Hot Reload):** Após alterar a regra, invoque `suricata_recarregar_regras` para carregar o novo conjunto sem interromper a inspeção de pacotes.

