"""Gerenciador, validador de sintaxe e manipulador de regras de detecção do Suricata."""

import difflib
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import get_settings
from .exceptions import SuricataRuleSyntaxError
from .models import RuleDefinition

# Regex para decomposição de regra canônica do Suricata
RULE_REGEX = re.compile(
    r"^\s*(#)?\s*(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+"
    r"([a-zA-Z0-9_-]+)\s+"
    r"(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$"
)

# Regex para extração de opções dentro dos parênteses
MSG_REGEX = re.compile(r'msg\s*:\s*"([^"]+)"')
SID_REGEX = re.compile(r"sid\s*:\s*(\d+)")
REV_REGEX = re.compile(r"rev\s*:\s*(\d+)")
CLASSTYPE_REGEX = re.compile(r"classtype\s*:\s*([a-zA-Z0-9_-]+)")


def parse_rule_line(line: str) -> RuleDefinition | None:
    """Realiza o parsing de uma linha de arquivo .rules em um objeto RuleDefinition."""
    stripped = line.strip()
    if not stripped or (
        stripped.startswith("#") and not stripped.lstrip("#").strip().startswith(("alert", "drop", "pass", "reject"))
    ):
        return None

    match = RULE_REGEX.match(stripped)
    if not match:
        return None

    commented, action, proto, src_ip, src_port, direction, dst_ip, dst_port, options_str = match.groups()

    sid_match = SID_REGEX.search(options_str)
    if not sid_match:
        return None
    sid = int(sid_match.group(1))

    msg_match = MSG_REGEX.search(options_str)
    msg = msg_match.group(1) if msg_match else "Sem descrição"

    rev_match = REV_REGEX.search(options_str)
    rev = int(rev_match.group(1)) if rev_match else 1

    classtype_match = CLASSTYPE_REGEX.search(options_str)
    classtype = classtype_match.group(1) if classtype_match else None

    # Extrai opções individuais separadas por ponto-e-vírgula
    raw_options = [opt.strip() for opt in options_str.split(";") if opt.strip()]

    return RuleDefinition(
        acao=action,
        protocolo=proto,
        origem_ip=src_ip,
        origem_porta=src_port,
        direcao=direction,
        destino_ip=dst_ip,
        destino_porta=dst_port,
        mensagem=msg,
        sid=sid,
        rev=rev,
        classtype=classtype,
        opcoes=raw_options,
        ativo=commented is None,
        texto_bruto=stripped,
    )


def validate_rule_syntax(rule_text: str) -> RuleDefinition:
    """Valida rigorosamente a sintaxe de uma regra proposta antes da aplicação."""
    stripped = rule_text.strip()
    if not stripped:
        raise SuricataRuleSyntaxError("Texto da regra não pode ser vazio.", rule_text=rule_text)

    # Verifica balanceamento de parênteses
    if stripped.count("(") != stripped.count(")"):
        raise SuricataRuleSyntaxError("Parênteses desbalanceados na definição da regra.", rule_text=rule_text)

    rule = parse_rule_line(stripped)
    if not rule:
        raise SuricataRuleSyntaxError(
            'Formato de regra inválido. Padrão esperado: ação proto src_ip src_port -> dst_ip dst_port (msg:"..."; sid:...; rev:...;)',
            rule_text=rule_text,
        )

    if rule.sid <= 0:
        raise SuricataRuleSyntaxError("O SID da regra deve ser um número inteiro positivo.", rule_text=rule_text)

    return rule


class RuleManager:
    """Gerencia leitura, indexação, edição e backups de regras de detecção."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def get_local_rules_file(self) -> Path:
        """Garante a existência e retorna o caminho para o arquivo de regras locais."""
        path = Path(self.settings.suricata_local_rules_path).resolve()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text("# Regras locais customizadas gerenciadas pelo Suricata MCP Server\n", encoding="utf-8")
        except (PermissionError, OSError):
            pass
        return path

    def backup_rules_file(self, file_path: Path) -> Path:
        """Cria uma cópia de segurança com timestamp antes de qualquer alteração."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        backup_path = file_path.with_suffix(f".{timestamp}.bak")
        shutil.copy2(file_path, backup_path)
        return backup_path

    def preview_rule_diff(self, original_content: str, new_content: str, filename: str = "local.rules") -> str:
        """Gera uma visualização unificada (unified diff) da alteração proposta."""
        diff = difflib.unified_diff(
            original_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff)

    def list_rules(self, limit: int = 100, active_only: bool = False) -> list[dict[str, Any]]:
        """Lista regras disponíveis no diretório de regras e no arquivo local."""
        rules = []
        try:
            local_file = self.get_local_rules_file()
            files_to_scan = [local_file] if local_file.is_file() else []
        except Exception:
            local_file = None
            files_to_scan = []

        rules_dir = self.settings.get_rules_dir()
        if rules_dir.is_dir():
            for p in rules_dir.glob("*.rules"):
                if (local_file is None or p != local_file) and p.is_file():
                    files_to_scan.append(p)

        for fpath in files_to_scan:
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        rule = parse_rule_line(line)
                        if rule:
                            if active_only and not rule.ativo:
                                continue
                            item = rule.model_dump()
                            item["arquivo"] = str(fpath.name)
                            item["linha"] = line_num
                            rules.append(item)
                            if len(rules) >= limit:
                                return rules
            except Exception:
                continue
        return rules

    def find_rule_by_sid(self, sid: int) -> dict[str, Any] | None:
        """Busca uma regra específica pelo seu Signature ID (SID)."""
        sid_pattern = re.compile(rf"\bsid\s*:\s*{sid}\b")
        try:
            local_file = self.get_local_rules_file()
            files_to_scan = [local_file] if local_file.is_file() else []
        except Exception:
            local_file = None
            files_to_scan = []

        rules_dir = self.settings.get_rules_dir()
        if rules_dir.is_dir():
            for p in rules_dir.glob("*.rules"):
                if (local_file is None or p != local_file) and p.is_file():
                    files_to_scan.append(p)

        for fpath in files_to_scan:
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        if str(sid) in line and sid_pattern.search(line):
                            rule = parse_rule_line(line)
                            if rule and rule.sid == sid:
                                item = rule.model_dump()
                                item["arquivo"] = str(fpath.name)
                                item["linha"] = line_num
                                return item
            except Exception:
                continue
        return None

    def add_local_rule(self, rule_text: str) -> dict[str, Any]:
        """Valida e anexa uma nova regra ao arquivo local.rules."""
        validated_rule = validate_rule_syntax(rule_text)

        # Verifica se SID já está em uso em alguma regra ativa
        active_rules = self.list_rules(limit=5000, active_only=True)
        existing = next((r for r in active_rules if r.get("sid") == validated_rule.sid), None)
        if existing:
            raise SuricataRuleSyntaxError(
                f"O SID {validated_rule.sid} já está em uso na regra ativa: '{existing.get('mensagem')}' ({existing.get('arquivo')}).",
                rule_text=rule_text,
            )

        local_file = self.get_local_rules_file()
        original_content = local_file.read_text(encoding="utf-8")
        backup_path = self.backup_rules_file(local_file)

        new_content = original_content
        if not new_content.endswith("\n"):
            new_content += "\n"
        new_content += f"{rule_text.strip()}\n"

        diff = self.preview_rule_diff(original_content, new_content, local_file.name)
        local_file.write_text(new_content, encoding="utf-8")

        return {
            "regra": validated_rule.model_dump(),
            "arquivo": str(local_file),
            "backup": str(backup_path),
            "diff": diff,
        }

    def deactivate_rule(self, sid: int) -> dict[str, Any]:
        """Comenta (#) uma regra no arquivo local.rules pelo SID."""
        local_file = self.get_local_rules_file()
        original_content = local_file.read_text(encoding="utf-8")
        lines = original_content.splitlines()

        found = False
        new_lines = []
        for line in lines:
            rule = parse_rule_line(line)
            if rule and rule.sid == sid and rule.ativo:
                new_lines.append(f"# {line.strip()}")
                found = True
            else:
                new_lines.append(line)

        if not found:
            raise SuricataRuleSyntaxError(f"Regra ativa com SID {sid} não encontrada no arquivo local.rules.")

        new_content = "\n".join(new_lines) + "\n"
        backup_path = self.backup_rules_file(local_file)
        diff = self.preview_rule_diff(original_content, new_content, local_file.name)
        local_file.write_text(new_content, encoding="utf-8")

        return {
            "sid": sid,
            "status": "desativada",
            "backup": str(backup_path),
            "diff": diff,
        }
