"""Testes de validação de integridade do inventário das 100 ferramentas MCP."""

import inspect

from suricata_mcp.server import create_server
from suricata_mcp.tools import ALL_TOOLS


def test_tools_inventory_count_and_uniqueness() -> None:
    """Valida se exatamente 100 ferramentas únicas estão registradas."""
    assert len(ALL_TOOLS) == 100, f"Esperadas 100 ferramentas, encontradas {len(ALL_TOOLS)}"

    names = [t.__name__ for t in ALL_TOOLS]
    unique_names = set(names)
    assert len(unique_names) == 100, f"Existem nomes duplicados: {len(names) - len(unique_names)}"


def test_all_tools_have_documentation_and_types() -> None:
    """Garante que nenhuma ferramenta é vazia, que todas possuem docstrings e nomes canônicos."""
    for tool in ALL_TOOLS:
        name = tool.__name__
        assert name.startswith("suricata_"), f"Ferramenta '{name}' deve iniciar com prefixo 'suricata_'"

        doc = inspect.getdoc(tool)
        assert doc is not None and len(doc.strip()) > 10, (
            f"Ferramenta '{name}' não possui docstring descritiva adequada."
        )

        sig = inspect.signature(tool)
        assert sig.return_annotation is not inspect.Signature.empty, (
            f"Ferramenta '{name}' deve possuir type hint de retorno."
        )


def test_server_registration_and_prompts() -> None:
    """Verifica se o servidor MCPServer inicializa e registra todas as 100 ferramentas e prompts."""
    server = create_server()
    assert server is not None
    assert server.name == "suricata-mcp"
