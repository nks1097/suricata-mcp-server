"""Configurações globais e gerenciamento de ambiente do Suricata MCP Server."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações do servidor com suporte a variáveis de ambiente e arquivo .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Identificação do Servidor
    app_name: str = "suricata-mcp-server"
    app_version: str = "1.0.0"

    # Caminhos do Suricata
    suricata_config_path: str = Field(
        default="C:/Program Files/Suricata/suricata.yaml" if os.name == "nt" else "/etc/suricata/suricata.yaml",
        description="Caminho completo para o arquivo suricata.yaml",
    )
    suricata_eve_path: str = Field(
        default="C:/Program Files/Suricata/log/eve.json" if os.name == "nt" else "/var/log/suricata/eve.json",
        description="Caminho completo para o arquivo eve.json",
    )
    suricata_log_dir: str = Field(
        default="C:/Program Files/Suricata/log" if os.name == "nt" else "/var/log/suricata",
        description="Diretório onde logs operacionais e estatísticas são gravados",
    )
    suricata_unix_socket_path: str = Field(
        default="",
        description="Caminho para o Unix Domain Socket de controle do Suricata (vazio se desabilitado)",
    )
    suricata_executable: str = Field(
        default="C:/Program Files/Suricata/suricata.exe" if os.name == "nt" else "suricata",
        description="Comando ou caminho completo para o executável do Suricata",
    )
    suricata_update_executable: str = Field(
        default="",
        description="Comando ou caminho completo para o executável suricata-update",
    )
    suricata_rules_dir: str = Field(
        default="C:/Program Files/Suricata/rules" if os.name == "nt" else "/var/lib/suricata/rules",
        description="Diretório de regras de detecção",
    )
    suricata_local_rules_path: str = Field(
        default="C:/Program Files/Suricata/rules/local.rules"
        if os.name == "nt"
        else "/var/lib/suricata/rules/local.rules",
        description="Caminho do arquivo de regras locais gerenciadas",
    )
    suricata_pcap_allowed_dir: str = Field(
        default="./pcaps",
        description="Diretório restrito permitido para ingestão e leitura de arquivos PCAP",
    )

    # Limites Operacionais e de Segurança
    suricata_max_pcap_size_mb: int = Field(default=100, description="Tamanho máximo de PCAP em MB")
    suricata_max_results: int = Field(default=500, description="Limite máximo de eventos retornados por consulta")
    suricata_command_timeout_seconds: int = Field(default=30, description="Timeout máximo para comandos locais")
    suricata_max_concurrent_tasks: int = Field(default=4, description="Número máximo de análises concorrentes")
    suricata_verify_config_before_write: bool = Field(default=True, description="Exigir validação antes de gravar")

    # Controle de Acesso e Modo de Operação
    mcp_operation_mode: Literal["somente_leitura", "operacional", "administrativo"] = Field(
        default="operacional",
        description="Nível de permissão global (somente_leitura, operacional ou administrativo)",
    )
    mcp_read_only: bool = Field(
        default=False,
        description="Forçar modo somente leitura estrito independente do perfil",
    )

    # Auditoria e Relatórios
    mcp_audit_enabled: bool = Field(default=True, description="Habilitar trilha de auditoria em JSON estruturado")
    mcp_audit_log_path: str = Field(default="./audit.log", description="Caminho para o log de auditoria")
    mcp_report_output_dir: str = Field(
        default="./reports_output", description="Diretório para salvar relatórios gerados"
    )

    # Transporte MCP
    mcp_transport: Literal["stdio", "sse"] = Field(default="stdio", description="Protocolo de transporte MCP")
    mcp_host: str = Field(default="127.0.0.1", description="Host para transporte SSE")
    mcp_port: int = Field(default=8080, description="Porta para transporte SSE")
    mcp_log_level: str = Field(default="INFO", description="Nível de log interno (DEBUG, INFO, WARNING, ERROR)")

    def get_eve_path(self) -> Path:
        """Retorna o caminho do arquivo EVE normalizado."""
        return Path(self.suricata_eve_path).resolve()

    def get_config_path(self) -> Path:
        """Retorna o caminho do arquivo suricata.yaml normalizado."""
        return Path(self.suricata_config_path).resolve()

    def get_rules_dir(self) -> Path:
        """Retorna o diretório de regras normalizado."""
        return Path(self.suricata_rules_dir).resolve()

    def get_reports_dir(self) -> Path:
        """Retorna o diretório de relatórios garantindo que ele exista."""
        p = Path(self.mcp_report_output_dir).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_pcap_dir(self) -> Path:
        """Retorna o diretório autorizado para PCAPs garantindo que ele exista."""
        p = Path(self.suricata_pcap_allowed_dir).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache
def get_settings() -> Settings:
    """Retorna instância singleton cacheada das configurações."""
    return Settings()
