"""Suricata MCP Server.

Servidor Model Context Protocol (MCP) universal para Suricata IDS/IPS, NSM e segurança de rede.
Fornece 100 ferramentas em português para monitoramento, triagem, engenharia de detecção e relatórios.
"""

__version__ = "1.0.0"
__author__ = "Natanael Krindges"
__license__ = "MIT"

from .config import Settings, get_settings
from .models import StandardResponseEnvelope

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "Settings",
    "get_settings",
    "StandardResponseEnvelope",
]
