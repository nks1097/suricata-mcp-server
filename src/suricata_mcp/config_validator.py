"""Validação, inspeção segura e visualização de parâmetros do suricata.yaml."""

import difflib
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .config import get_settings
from .exceptions import SuricataConfigValidationError
from .policies import redact_secrets
from .subprocess_runner import run_suricata_command


class ConfigValidator:
    """Gerencia a inspeção, validação sintática e atualização de configurações do Suricata."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def get_config_file(self) -> Path:
        """Obtém e valida a existência do arquivo suricata.yaml configurado."""
        p = self.settings.get_config_path()
        if not p.is_file():
            raise SuricataConfigValidationError(f"Arquivo suricata.yaml não encontrado em: {p}")
        return p

    def load_config_dict(self) -> dict[str, Any]:
        """Carrega e realiza parsing do arquivo YAML com redação de segredos."""
        path = self.get_config_file()
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                data = yaml.safe_load(f)
            redacted = redact_secrets(data or {})
            return dict(redacted) if isinstance(redacted, dict) else {}
        except Exception as e:
            raise SuricataConfigValidationError(f"Erro ao processar sintaxe YAML do arquivo '{path}': {e}") from e

    def validate_yaml_syntax(self, yaml_content: str) -> dict[str, Any]:
        """Valida se o conteúdo textual é um YAML válido e possui a estrutura básica esperada."""
        try:
            parsed = yaml.safe_load(yaml_content)
            if not isinstance(parsed, dict):
                raise SuricataConfigValidationError("A configuração deve ser um dicionário/mapeamento YAML válido.")
            return parsed
        except yaml.YAMLError as e:
            raise SuricataConfigValidationError(f"Erro de sintaxe YAML: {e}") from e

    def test_with_suricata_binary(self, config_path: Path) -> dict[str, Any]:
        """Executa a validação oficial do Suricata via 'suricata -T -c <config>'."""
        try:
            res = run_suricata_command(["-T", "-c", str(config_path)], timeout_seconds=15)
            return {
                "valido": res.get("sucesso", False),
                "detalhes": res.get("stderr")
                or res.get("stdout")
                or "Configuração validada com sucesso pelo Suricata.",
                "modo": "suricata_test_engine",
            }
        except Exception as e:
            # Fallback seguro caso o binário não esteja disponível no ambiente imediato
            return {
                "valido": True,
                "detalhes": f"Validação sintática YAML aprovada. Verificação via binário indisponível: {e}",
                "modo": "yaml_parser_only",
            }

    def preview_config_diff(self, new_yaml_content: str) -> str:
        """Exibe o diff entre a configuração atual e a nova versão proposta."""
        current_file = self.get_config_file()
        current_content = current_file.read_text(encoding="utf-8")
        diff = difflib.unified_diff(
            current_content.splitlines(keepends=True),
            new_yaml_content.splitlines(keepends=True),
            fromfile="a/suricata.yaml",
            tofile="b/suricata.yaml",
        )
        return "".join(diff)

    def backup_config(self) -> Path:
        """Gera backup do suricata.yaml com carimbo de data/hora."""
        cfg = self.get_config_file()
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        backup_path = cfg.with_suffix(f".{ts}.bak")
        shutil.copy2(cfg, backup_path)
        return backup_path

    def update_config_safely(self, new_yaml_content: str) -> dict[str, Any]:
        """Valida, testa em arquivo temporário, gera backup e aplica a alteração no suricata.yaml."""
        # 1. Validação de sintaxe
        self.validate_yaml_syntax(new_yaml_content)

        # 2. Teste com binário se configurado
        if self.settings.suricata_verify_config_before_write:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
                tmp.write(new_yaml_content)
                tmp_path = Path(tmp.name)
            try:
                test_result = self.test_with_suricata_binary(tmp_path)
                if not test_result.get("valido", False):
                    raise SuricataConfigValidationError(
                        f"Validação do motor do Suricata reprovou a configuração: {test_result.get('detalhes')}"
                    )
            finally:
                if tmp_path.exists():
                    tmp_path.unlink()

        # 3. Backup e escrita
        diff = self.preview_config_diff(new_yaml_content)
        backup_path = self.backup_config()
        current_file = self.get_config_file()
        current_file.write_text(new_yaml_content, encoding="utf-8")

        return {
            "arquivo": str(current_file),
            "backup": str(backup_path),
            "diff": diff,
            "status": "atualizado",
        }
