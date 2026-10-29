# Guia de Contribuição (Contributing Guide)

Obrigado pelo seu interesse em contribuir com o **Suricata MCP Server**! Este projeto é desenvolvido em código aberto e visa fornecer a melhor ponte de IA para ambientes de monitoramento de segurança com Suricata.

## Como Contribuir

1. **Abra uma Issue:** Se você encontrou um bug ou tem uma sugestão de melhoria, abra uma issue detalhando o comportamento observado ou desejado.
2. **Faça um Fork:** Crie uma branch para a sua funcionalidade (`git checkout -b feature/minha-melhoria`).
3. **Mantenha os Padrões de Código:**
   - Formate e valide com `ruff`: `ruff check .` e `ruff format .`
   - Valide tipagem com `mypy`: `mypy src`
   - Garanta que todos os testes passem: `pytest`
4. **Envie um Pull Request:** Descreva com clareza as modificações implementadas e adicione testes correspondentes.

## Diretrizes de Implementação

- Todas as ferramentas MCP devem ter nomes canônicos em português no formato `suricata_<verbo>_<objeto>`.
- Todas as ferramentas devem retornar o envelope padronizado (`StandardResponseEnvelope`).
- Nunca execute comandos de shell diretos com interpolação de strings. Use sempre o módulo `subprocess_runner`.
- Preserve o princípio do menor privilégio: operações administrativas exigem decorators de autorização explícita.
- Adicione testes sintéticos para quaisquer novas funcionalidades sem incluir PCAPs proprietários ou logs com dados reais de empresas.

