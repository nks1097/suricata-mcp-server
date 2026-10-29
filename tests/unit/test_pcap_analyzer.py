"""Testes unitários para o analisador de arquivos PCAP."""

from pathlib import Path

import pytest

from suricata_mcp.exceptions import SuricataPCAPError
from suricata_mcp.pcap_analyzer import PCAPAnalyzer


def test_validate_pcap_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifica a validação de cabeçalho e magic bytes de PCAP."""
    pcaps_dir = tmp_path / "pcaps"
    pcaps_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SURICATA_PCAP_ALLOWED_DIR", str(pcaps_dir))

    # Cria arquivo PCAP sintético com cabeçalho válido (0xd4c3b2a1)
    valid_pcap = pcaps_dir / "valid_sample.pcap"
    header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    valid_pcap.write_bytes(header)

    analyzer = PCAPAnalyzer()
    res = analyzer.validate_pcap_file(valid_pcap)
    assert res["valido"] is True
    assert "PCAP" in res["formato"]

    # Cria arquivo corrompido
    corrupt_file = pcaps_dir / "corrupt.pcap"
    corrupt_file.write_bytes(b"invalid_header_content_1234567890")

    with pytest.raises(SuricataPCAPError):
        analyzer.validate_pcap_file(corrupt_file)
