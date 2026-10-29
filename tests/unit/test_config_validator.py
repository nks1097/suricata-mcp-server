"""Testes unitários para o validador de configurações suricata.yaml."""

import pytest

from suricata_mcp.config_validator import ConfigValidator
from suricata_mcp.exceptions import SuricataConfigValidationError


def test_load_config_and_sections() -> None:
    """Verifica carregamento e leitura de seções do suricata.yaml."""
    validator = ConfigValidator()
    cfg = validator.load_config_dict()
    assert "outputs" in cfg
    assert "suricata-version" in cfg


def test_validate_yaml_syntax() -> None:
    """Verifica validação de sintaxe de strings YAML."""
    validator = ConfigValidator()
    valid_yaml = "vars:\n  HOME_NET: '192.168.0.0/16'\n"
    parsed = validator.validate_yaml_syntax(valid_yaml)
    assert parsed["vars"]["HOME_NET"] == "192.168.0.0/16"

    with pytest.raises(SuricataConfigValidationError):
        validator.validate_yaml_syntax("invalid: [broken yaml")


def test_preview_config_diff() -> None:
    """Verifica geração de diff de configuração."""
    validator = ConfigValidator()
    new_yaml = "suricata-version: '8.1'\n"
    diff = validator.preview_config_diff(new_yaml)
    assert "suricata-version" in diff
