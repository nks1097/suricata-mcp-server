"""Testes de segurança, autorização (RBAC), proteção de caminhos e segredos."""

from pathlib import Path

import pytest

from suricata_mcp.audit import get_audit_history, record_audit_entry
from suricata_mcp.authorization import check_permission
from suricata_mcp.config import get_settings
from suricata_mcp.exceptions import SuricataPathTraversalError, SuricataPermissionDeniedError
from suricata_mcp.policies import redact_secrets, validate_safe_path


def test_rbac_hierarchy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Valida permissões por perfil."""
    monkeypatch.setenv("MCP_OPERATION_MODE", "somente_leitura")
    monkeypatch.setenv("MCP_READ_ONLY", "false")
    get_settings.cache_clear()

    # Leitura deve passar
    check_permission("somente_leitura")

    # Operacional e administrativo devem falhar
    with pytest.raises(SuricataPermissionDeniedError):
        check_permission("operacional")

    with pytest.raises(SuricataPermissionDeniedError):
        check_permission("administrativo")


def test_mcp_read_only_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    """Valida bloqueio absoluto quando MCP_READ_ONLY=true."""
    monkeypatch.setenv("MCP_OPERATION_MODE", "administrativo")
    monkeypatch.setenv("MCP_READ_ONLY", "true")
    get_settings.cache_clear()

    check_permission("somente_leitura")

    with pytest.raises(SuricataPermissionDeniedError):
        check_permission("administrativo")


def test_path_traversal_blocking(tmp_path: Path) -> None:
    """Garante que caminhos fora da base autorizada são rejeitados."""
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    secret_file = secret_dir / "passwords.txt"
    secret_file.write_text("secret_data")

    # Caminho válido dentro da pasta autorizada
    valid_file = allowed_dir / "test.pcap"
    valid_file.write_text("pcap_dummy")
    assert validate_safe_path(valid_file, allowed_dir) == valid_file.resolve()

    # Tentativa de traversal usando ..
    with pytest.raises(SuricataPathTraversalError):
        validate_safe_path(allowed_dir / ".." / "secret" / "passwords.txt", allowed_dir)


def test_redact_secrets() -> None:
    """Verifica se chaves e senhas sensíveis são mascaradas."""
    sensitive = {
        "api_key": "secret_key_123456",
        "normal_field": "public_data",
        "nested": {"password": "mypassword99"},
    }
    redacted = redact_secrets(sensitive)
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["normal_field"] == "public_data"
    assert redacted["nested"]["password"] == "[REDACTED]"


def test_audit_recording() -> None:
    """Verifica registro e consulta do histórico de auditoria."""
    record_audit_entry("suricata_teste_auditoria", {"param1": "val1"}, True, 15.5)
    history = get_audit_history(limit=10, tool_filter="suricata_teste_auditoria")
    assert len(history) >= 1
    assert history[-1]["tool_name"] == "suricata_teste_auditoria"
    assert history[-1]["success"] is True
