"""Analisador forense offline de arquivos PCAP com isolamento e extração de telemetria."""

import shutil
import tempfile
from pathlib import Path
from typing import Any

from .config import get_settings
from .eve_parser import summarize_events
from .eve_reader import stream_eve_events
from .exceptions import SuricataPCAPError
from .policies import validate_pcap_path
from .subprocess_runner import run_suricata_command


class PCAPAnalyzer:
    """Orquestra a execução offline do Suricata contra capturas PCAP em ambiente isolado."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def validate_pcap_file(self, file_path: str | Path) -> dict[str, Any]:
        """Verifica o arquivo PCAP quanto a magic bytes, tamanho e integridade."""
        path = validate_pcap_path(file_path)
        size_bytes = path.stat().st_size

        if size_bytes < 24:
            raise SuricataPCAPError("Arquivo PCAP muito pequeno ou corrompido (menos de 24 bytes).")

        # Valida cabeçalho (magic bytes de libpcap ou pcapng)
        with open(path, "rb") as f:
            magic = f.read(4)

        format_detected = "desconhecido"
        # 0xa1b2c3d4 ou 0xd4c3b2a1 (PCAP padrão)
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
            format_detected = "PCAP (Standard)"
        # 0x0a0d0d0a (PCAPNG)
        elif magic == b"\x0a\x0d\x0d\x0a":
            format_detected = "PCAPNG (Next Generation)"
        else:
            raise SuricataPCAPError(
                f"Formato de arquivo inválido. Magic bytes não reconhecidos como PCAP: {magic.hex()}"
            )

        return {
            "arquivo": str(path.name),
            "caminho_absoluto": str(path),
            "formato": format_detected,
            "tamanho_bytes": size_bytes,
            "tamanho_mb": round(size_bytes / (1024 * 1024), 2),
            "valido": True,
        }

    def analyze_pcap_offline(self, file_path: str | Path, keep_artifacts: bool = False) -> dict[str, Any]:
        """Executa 'suricata -r <pcap> -l <temp_dir>' e extrai eventos e estatísticas consolidadas."""
        path = validate_pcap_path(file_path)
        temp_dir = Path(tempfile.mkdtemp(prefix="suricata_pcap_analysis_"))

        try:
            # Argumentos para análise offline
            args = [
                "-r",
                str(path),
                "-l",
                str(temp_dir),
                "--runmode",
                "single",
            ]

            # Executa com timeout
            proc_res = run_suricata_command(args, timeout_seconds=60)

            # Verifica se o arquivo eve.json foi gerado
            eve_file = temp_dir / "eve.json"
            if not eve_file.exists():
                raise SuricataPCAPError(
                    f"Suricata concluiu a análise, mas nenhum 'eve.json' foi gerado. Detalhes: {proc_res.get('stderr')}"
                )

            events = list(stream_eve_events(eve_file))
            summary = summarize_events(events)

            alerts = [e for e in events if e.get("event_type") == "alert"]
            flows = [e for e in events if e.get("event_type") == "flow"]

            result = {
                "pcap": str(path.name),
                "total_eventos": len(events),
                "total_alertas": len(alerts),
                "total_fluxos": len(flows),
                "resumo_analise": summary,
                "amostra_alertas": alerts[:10],
                "diretorio_artefatos": str(temp_dir) if keep_artifacts else None,
            }

            return result

        finally:
            if not keep_artifacts and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    def clean_analysis_artifacts(self, artifact_dir: str | Path) -> dict[str, Any]:
        """Remove com segurança pastas temporárias de análise criadas pelo MCP."""
        p = Path(artifact_dir).resolve()
        # Garante que só remove diretórios com prefixo específico no temp
        if not p.name.startswith("suricata_pcap_analysis_") or not p.is_dir():
            raise SuricataPCAPError(
                f"Diretório '{p}' não é um artefato temporário de análise reconhecido para exclusão segura."
            )

        shutil.rmtree(p, ignore_errors=True)
        return {"diretorio_removido": str(p), "status": "removido_com_sucesso"}
