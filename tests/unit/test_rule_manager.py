"""Testes unitários para o gerenciador e validador de regras de detecção."""

import pytest

from suricata_mcp.exceptions import SuricataRuleSyntaxError
from suricata_mcp.rule_manager import (
    RuleManager,
    parse_rule_line,
    validate_rule_syntax,
)


def test_parse_rule_line_valid() -> None:
    """Verifica parsing de regra Suricata válida."""
    rule_str = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ET TEST Rule"; sid:9000001; rev:1; classtype:bad-unknown;)'
    )
    rule = parse_rule_line(rule_str)
    assert rule is not None
    assert rule.acao == "alert"
    assert rule.protocolo == "tcp"
    assert rule.sid == 9000001
    assert rule.rev == 1
    assert rule.mensagem == "ET TEST Rule"
    assert rule.ativo is True


def test_validate_rule_syntax_invalid() -> None:
    """Garante que regras malformadas são rejeitadas com erro apropriado."""
    with pytest.raises(SuricataRuleSyntaxError):
        validate_rule_syntax("alert tcp (msg: missing parenthesis")

    with pytest.raises(SuricataRuleSyntaxError):
        validate_rule_syntax('alert tcp any any -> any any (msg:"Missing SID";)')


def test_rule_manager_crud() -> None:
    """Testa o ciclo de adição, consulta e desativação de regras locais."""
    mgr = RuleManager()

    # 1. Adição
    new_rule = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"TEST Local Rule"; sid:9999001; rev:1;)'
    add_res = mgr.add_local_rule(new_rule)
    assert add_res["regra"]["sid"] == 9999001
    assert "diff" in add_res

    # 2. Busca por SID
    found = mgr.find_rule_by_sid(9999001)
    assert found is not None
    assert found["mensagem"] == "TEST Local Rule"

    # 3. Desativação
    deact_res = mgr.deactivate_rule(9999001)
    assert deact_res["status"] == "desativada"

    # 4. Confirma desativação
    updated = mgr.find_rule_by_sid(9999001)
    assert updated is not None
    assert updated["ativo"] is False
