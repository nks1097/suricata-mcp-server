# Diretrizes de Segurança e Governança

O **Suricata MCP Server** foi projetado para ambientes de missão crítica em SOC e DevSecOps.

---

## 1. Princípio do Menor Privilégio (Least Privilege)

Por padrão, o servidor inicializa no modo `operacional` (ou `somente_leitura` se configurado). Operações que modifiquem arquivos do sistema ou regras exigem perfil `administrativo`.

| Operação | Nível Mínimo Requerido |
| :--- | :--- |
| Consultar eventos, alertas, stats e métricas | `somente_leitura` |
| Analisar capturas PCAP e gerar relatórios | `operacional` |
| Recarregar regras e reabrir logs | `operacional` |
| Adicionar, alterar ou desativar regras locais | `administrativo` |
| Atualizar o arquivo `suricata.yaml` | `administrativo` |
| Executar `suricata-update` | `administrativo` |

---

## 2. Proteção contra Injeção de Comandos (Subprocess Whitelisting)

* Não são utilizados shells (`shell=False`).
* Todos os comandos são montados como listas tipadas de strings.
* Apenas binários explicitamente presentes na lista permitida (`suricata`, `suricata.exe`, `suricata-update`) podem ser invocados.
* Timeouts rigorosos impedem que processos zumbis ou travas congelem o servidor.

---

## 3. Redação Automática de Segredos

Antes de gravar qualquer registro na trilha de auditoria ou retornar respostas a clientes de IA, o módulo `policies.py` analisa recursivamente os dados mascarando automaticamente:
* Tokens e chaves de API (`api_key`, `token`, `bearer`).
* Senhas e credenciais (`password`, `secret`, `passwd`).
* Chaves privadas RSA/ECDSA/OpenSSH (`-----BEGIN ... PRIVATE KEY-----`).

