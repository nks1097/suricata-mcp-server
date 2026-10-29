# Política de Segurança (Security Policy)

## Versões Suportadas

Atualmente, apenas a versão mais recente recebe atualizações e correções de segurança.

| Versão | Suportada          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Relatando uma Vulnerabilidade

A equipe do **Suricata MCP Server** leva a segurança do software muito a sério.
Se você descobrir uma vulnerabilidade de segurança, solicitamos que nos informe de forma responsável antes de qualquer divulgação pública.

### Como Reportar

Por favor, **NÃO** abra uma issue pública no GitHub para relatar vulnerabilidades de segurança.

Em vez disso:
1. Envie um e-mail para: **natanael1097@gmail.com**
2. Inclua no assunto: `[VULNERABILITY] Suricata MCP Server - Descrição Breve`
3. Forneça detalhes suficientes para reprodução:
   - Versão do Suricata MCP Server e versão do Suricata.
   - Sistema operacional e arquitetura.
   - Passos passo-a-passo para reproduzir o problema ou prova de conceito (PoC).
   - Impacto potencial estimado.

### Nosso Compromisso

- Responderemos ao seu relatório em até 48 horas úteis confirmando o recebimento.
- Manteremos você informado sobre a triagem e o progresso da correção.
- Um patch de segurança será desenvolvido e lançado em uma versão pontual.
- Você receberá os devidos créditos de agradecimento nas notas de versão (caso deseje).

## Princípios de Segurança do Projeto

1. **Menor Privilégio por Padrão:** O servidor inicia em modo `somente_leitura` ou `operacional`, exigindo autorização administrativa explícita para modificações de regras ou configurações.
2. **Sem Injeção de Comandos:** Todos os comandos de sistema são disparados com `subprocess` em listas de argumentos estritas, sem interpolação de shell (`shell=False`).
3. **Proteção contra Path Traversal:** Nenhum caminho arbitrário fora das pastas autorizadas (`rules`, `pcaps`, `log`) pode ser lido ou modificado.
4. **Redação de Segredos:** Tokens, chaves e credenciais sensíveis são automaticamente mascarados nas saídas de log e auditoria.

