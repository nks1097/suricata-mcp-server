"""Exceções canônicas do Suricata MCP Server."""


class SuricataMCPError(Exception):
    """Exceção base para todos os erros do Suricata MCP Server."""

    def __init__(self, message: str, code: str = "SURICATA_ERROR", details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class SuricataPermissionDeniedError(SuricataMCPError):
    """Disparada quando uma operação não é permitida pelo perfil de segurança atual."""

    def __init__(self, message: str = "Acesso negado pela política de menor privilégio.") -> None:
        super().__init__(message, code="PERMISSION_DENIED")


class SuricataPathTraversalError(SuricataMCPError):
    """Disparada quando uma tentativa de acesso a caminho fora do escopo autorizado é detectada."""

    def __init__(self, message: str = "Caminho não autorizado ou tentativa de path traversal detectada.") -> None:
        super().__init__(message, code="PATH_TRAVERSAL_BLOCKED")


class SuricataEveNotFoundError(SuricataMCPError):
    """Disparada quando o arquivo eve.json não é encontrado ou não pode ser lido."""

    def __init__(self, path: str) -> None:
        super().__init__(f"Arquivo EVE JSON não encontrado ou inacessível: {path}", code="EVE_NOT_FOUND")


class SuricataSocketError(SuricataMCPError):
    """Disparada em falhas de comunicação com o Unix Domain Socket / Named Pipe do Suricata."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="SOCKET_ERROR")


class SuricataSubprocessError(SuricataMCPError):
    """Disparada quando a execução controlada de um comando do Suricata falha."""

    def __init__(self, message: str, returncode: int | None = None, stdout: str = "", stderr: str = "") -> None:
        super().__init__(
            message,
            code="SUBPROCESS_FAILED",
            details={"returncode": returncode, "stdout": stdout, "stderr": stderr},
        )


class SuricataConfigValidationError(SuricataMCPError):
    """Disparada quando um arquivo suricata.yaml falha na validação de sintaxe."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message, code="CONFIG_VALIDATION_ERROR", details={"errors": errors or []})


class SuricataRuleSyntaxError(SuricataMCPError):
    """Disparada quando uma regra do Suricata possui erro de sintaxe."""

    def __init__(self, message: str, rule_text: str = "", line: int | None = None) -> None:
        super().__init__(
            message,
            code="RULE_SYNTAX_ERROR",
            details={"rule_text": rule_text, "line": line},
        )


class SuricataPCAPError(SuricataMCPError):
    """Disparada em erros de análise, tamanho ou validação de arquivo PCAP."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="PCAP_ERROR")


class SuricataReportError(SuricataMCPError):
    """Disparada em falhas na geração de relatórios (PDF, XLSX, CSV)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="REPORT_ERROR")
