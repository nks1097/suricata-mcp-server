"""Executor seguro de subprocessos com lista de argumentos e proteção contra injeção."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .config import get_settings
from .exceptions import SuricataSubprocessError

# Lista permitida de binários que podem ser executados
ALLOWED_EXECUTABLE_BASENAMES = {
    "suricata",
    "suricata.exe",
    "suricata-update",
    "suricata-update.exe",
}


def resolve_executable(executable_path: str) -> str:
    """Valida se o executável pertence à lista autorizada e resolve o caminho no sistema."""
    if not executable_path:
        raise SuricataSubprocessError("Caminho do executável não informado.")

    path_obj = Path(executable_path)
    base_name = path_obj.name.lower()

    if base_name not in ALLOWED_EXECUTABLE_BASENAMES:
        raise SuricataSubprocessError(
            f"Executável '{base_name}' não permitido. Permitidos apenas: {ALLOWED_EXECUTABLE_BASENAMES}"
        )

    # Se for um caminho absoluto ou relativo explícito
    if path_obj.is_file():
        return str(path_obj.resolve())

    # Caso contrário, busca no PATH do sistema
    found = shutil.which(executable_path)
    if found:
        return str(Path(found).resolve())

    raise SuricataSubprocessError(f"Executável não encontrado no sistema: {executable_path}")


def run_suricata_command(
    args: list[str],
    custom_executable: str | None = None,
    timeout_seconds: int | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Executa um comando autorizado do Suricata via subprocess sem shell."""
    settings = get_settings()
    exe = custom_executable or settings.suricata_executable
    resolved_exe = resolve_executable(exe)
    timeout = timeout_seconds or settings.suricata_command_timeout_seconds

    cmd = [resolved_exe] + args

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(cwd) if cwd else None,
            env=os.environ.copy(),
            check=False,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "sucesso": proc.returncode == 0,
            "cmd": cmd,
        }
    except subprocess.TimeoutExpired as e:
        raise SuricataSubprocessError(
            f"Comando excedeu o tempo limite de {timeout} segundos.",
            returncode=-1,
            stdout=e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout or ""),
            stderr=e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr or ""),
        ) from e
    except Exception as e:
        raise SuricataSubprocessError(f"Erro ao executar processo do Suricata: {e}") from e
