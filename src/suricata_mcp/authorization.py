"""Sistema de autorização e controle de acesso baseado em funções (RBAC)."""

from collections.abc import Callable
from functools import wraps
from typing import Any, Literal

from .config import get_settings
from .exceptions import SuricataPermissionDeniedError

PermissionLevel = Literal["somente_leitura", "operacional", "administrativo"]

PERMISSION_HIERARCHY: dict[str, int] = {
    "somente_leitura": 1,
    "operacional": 2,
    "administrativo": 3,
}


def check_permission(required_level: PermissionLevel) -> None:
    """Verifica se o modo operacional configurado possui privilégio suficiente."""
    settings = get_settings()

    # Se modo somente leitura estiver forçado, bloqueia qualquer ação operacional ou administrativa
    if settings.mcp_read_only and required_level != "somente_leitura":
        raise SuricataPermissionDeniedError(
            "Operação bloqueada: o servidor MCP está configurado com 'MCP_READ_ONLY=true'."
        )

    current_level = settings.mcp_operation_mode
    current_weight = PERMISSION_HIERARCHY.get(current_level, 1)
    required_weight = PERMISSION_HIERARCHY.get(required_level, 1)

    if current_weight < required_weight:
        raise SuricataPermissionDeniedError(
            f"Privilégio insuficiente: a operação requer nível '{required_level}', "
            f"mas o servidor está em modo '{current_level}'."
        )


def require_permission(level: PermissionLevel) -> Callable:
    """Decorator para proteger ferramentas MCP com validação de menor privilégio."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            check_permission(level)
            return func(*args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            check_permission(level)
            return await func(*args, **kwargs)

        import inspect

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
