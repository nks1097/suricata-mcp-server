"""Políticas de segurança, proteção contra path traversal e redação de segredos."""

import re
from pathlib import Path
from typing import Any

from .config import get_settings
from .exceptions import SuricataPathTraversalError

# Padrões regex para detecção e mascaramento de segredos
SECRET_KEY_PATTERN = re.compile(
    r"((?:api[_-]?key|secret|password|token|bearer|passwd)[\s]*[:=][\s]*['\"]?)([a-zA-Z0-9_\-\.\+/=]{6,})(['\"]?)",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----"
)
BEARER_PATTERN = re.compile(
    r"((?:Authorization:\s*Bearer\s+))[A-Za-z0-9_\-\.~+/]+=*",
    re.IGNORECASE,
)


def redact_secrets(data: Any) -> Any:
    """Mascara recursivamente strings e chaves contendo credenciais ou dados sensíveis."""
    if isinstance(data, str):
        result = SECRET_KEY_PATTERN.sub(r"\1[REDACTED]\3", data)
        result = PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", result)
        result = BEARER_PATTERN.sub(r"\1[REDACTED]", result)
        return result
    if isinstance(data, dict):
        redacted_dict = {}
        for k, v in data.items():
            if any(s in str(k).lower() for s in ("password", "secret", "token", "auth", "api_key", "apikey")):
                redacted_dict[k] = "[REDACTED]"
            else:
                redacted_dict[k] = redact_secrets(v)
        return redacted_dict
    if isinstance(data, list):
        return [redact_secrets(item) for item in data]
    return data


def validate_safe_path(target_path: str | Path, allowed_base: str | Path | list[str | Path]) -> Path:
    """Garante que o caminho de destino esteja estritamente contido dentro de diretórios autorizados."""
    resolved_target = Path(target_path).resolve()
    bases = [Path(b).resolve() for b in (allowed_base if isinstance(allowed_base, list) else [allowed_base])]

    for base in bases:
        try:
            # Verifica se target é subcaminho ou igual a base
            if resolved_target == base or base in resolved_target.parents:
                return resolved_target
        except ValueError:
            continue

    raise SuricataPathTraversalError(
        f"Acesso negado: o caminho '{resolved_target}' está fora dos limites autorizados ({[str(b) for b in bases]})."
    )


def validate_pcap_path(pcap_path: str | Path) -> Path:
    """Valida se o caminho do PCAP está dentro da pasta autorizada e cumpre as regras de extensão e tamanho."""
    settings = get_settings()
    allowed_dir = settings.get_pcap_dir()
    path = validate_safe_path(pcap_path, allowed_dir)

    if not path.is_file():
        raise SuricataPathTraversalError(f"O arquivo PCAP especificado não existe: {path}")

    if path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        raise SuricataPathTraversalError(f"Extensão de arquivo inválida para captura de rede: {path.suffix}")

    file_size_mb = path.stat().st_size / (1024 * 1024)
    if file_size_mb > settings.suricata_max_pcap_size_mb:
        raise SuricataPathTraversalError(
            f"Arquivo PCAP ({file_size_mb:.2f} MB) excede o limite máximo permitido de {settings.suricata_max_pcap_size_mb} MB."
        )

    return path
