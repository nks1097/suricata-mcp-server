"""Configurações globais e fixtures compartilhadas do Pytest."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def configure_test_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Configura o ambiente de teste com arquivos temporários e fixtures sintéticas."""
    eve_file = FIXTURES_DIR / "eve_sample.json"
    cfg_file = FIXTURES_DIR / "test_config.yaml"
    rules_file = FIXTURES_DIR / "sample_rules.rules"

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    pcaps_dir = tmp_path / "pcaps"
    pcaps_dir.mkdir(parents=True, exist_ok=True)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    # Copia regra de teste para pasta temporária de regras
    local_rules = rules_dir / "local.rules"
    local_rules.write_text(rules_file.read_text(encoding="utf-8"), encoding="utf-8")

    # Copia config de teste para pasta temporária para isolar alterações
    tmp_config = tmp_path / "suricata.yaml"
    tmp_config.write_text(cfg_file.read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setenv("SURICATA_EVE_PATH", str(eve_file))
    monkeypatch.setenv("SURICATA_CONFIG_PATH", str(tmp_config))
    monkeypatch.setenv("SURICATA_RULES_DIR", str(rules_dir))
    monkeypatch.setenv("SURICATA_LOCAL_RULES_PATH", str(local_rules))
    monkeypatch.setenv("SURICATA_PCAP_ALLOWED_DIR", str(pcaps_dir))
    monkeypatch.setenv("MCP_REPORT_OUTPUT_DIR", str(reports_dir))
    monkeypatch.setenv("MCP_OPERATION_MODE", "administrativo")
    monkeypatch.setenv("MCP_READ_ONLY", "false")
    monkeypatch.setenv("MCP_AUDIT_ENABLED", "false")

    # Limpa cache de configurações para carregar novos caminhos
    from suricata_mcp.config import get_settings

    get_settings.cache_clear()

    # Em testes unitários rápidos, mockamos a execução de comandos subprocess externos
    import subprocess
    from unittest.mock import MagicMock

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Suricata 8.0.7 RELEASE (mock test output)"
    mock_proc.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=mock_proc))
