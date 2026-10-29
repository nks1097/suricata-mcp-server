"""Testes de integração opcionais contra o ambiente local do Suricata (se instalado)."""

import pytest

from suricata_mcp.tools.sensores import suricata_obter_versao, suricata_testar_conexao


@pytest.mark.integration
def test_live_suricata_binary_or_skip() -> None:
    """Executa verificação da versão real caso o binário do Suricata esteja presente."""
    res = suricata_obter_versao()
    assert res["sucesso"] in (True, False)
    if res["sucesso"]:
        assert "Suricata" in str(res["dados"])


@pytest.mark.integration
def test_live_testar_conexao() -> None:
    """Verifica chamada de conectividade ao vivo."""
    res = suricata_testar_conexao()
    assert res["sucesso"] is True
    assert "status_geral" in res["dados"]
