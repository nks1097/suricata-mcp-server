"""Modelos Pydantic para requisições, respostas padronizadas e entidades do Suricata."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class MetadataEnvelope(BaseModel):
    """Metadados de telemetria da execução da ferramenta."""

    duracao_ms: float = Field(default=0.0, description="Duração da execução em milissegundos")
    truncado: bool = Field(default=False, description="Indica se os resultados foram limitados pelo teto configurado")
    total_encontrado: int = Field(default=0, description="Total de itens correspondentes antes do truncamento")
    fonte_dados: str = Field(default="eve_json", description="Origem dos dados (eve_json, socket, processo, arquivo)")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Timestamp ISO8601 da resposta",
    )


class StandardResponseEnvelope(BaseModel):
    """Envelope padrão para respostas das 100 ferramentas do Suricata MCP Server."""

    sucesso: bool = Field(default=True, description="Indica se a operação foi executada com sucesso")
    dados: Any = Field(default=None, description="Carga útil estruturada contendo o resultado")
    erro: str | None = Field(default=None, description="Mensagem de erro amigável caso a operação tenha falhado")
    codigo_erro: str | None = Field(default=None, description="Código de erro canônico")
    avisos: list[str] = Field(default_factory=list, description="Lista de advertências ou observações operacionais")
    id_requisicao: str = Field(
        default_factory=lambda: str(uuid.uuid4())[:8],
        description="Identificador único para correlação e auditoria",
    )
    metadados: MetadataEnvelope = Field(
        default_factory=MetadataEnvelope,
        description="Metadados de execução da requisição",
    )

    def to_dict(self) -> dict[str, Any]:
        """Converte o envelope para um dicionário serializável."""
        return self.model_dump()


class EventQueryFilter(BaseModel):
    """Filtros para busca em eventos do EVE JSON."""

    tipo_evento: str | None = Field(default=None, description="Tipo do evento EVE (alert, flow, dns, http, tls, etc.)")
    ip_origem: str | None = Field(default=None, description="Endereço IP de origem (IPv4 ou IPv6)")
    ip_destino: str | None = Field(default=None, description="Endereço IP de destino (IPv4 ou IPv6)")
    porta_origem: int | None = Field(default=None, description="Porta TCP/UDP de origem")
    porta_destino: int | None = Field(default=None, description="Porta TCP/UDP de destino")
    protocolo: str | None = Field(default=None, description="Protocolo da camada de transporte (TCP, UDP, ICMP)")
    severidade_max: int | None = Field(
        default=None, description="Severidade máxima do alerta (1=Crítico, 2=Alto, 3=Médio, 4=Info)"
    )
    sid: int | None = Field(default=None, description="Signature ID específico da regra do Suricata")
    termo_busca: str | None = Field(
        default=None, description="Texto livre para busca em payloads, mensagens ou SNI/Host"
    )
    data_inicio: str | None = Field(default=None, description="Filtro de data/hora inicial (ISO 8601 ou YYYY-MM-DD)")
    data_fim: str | None = Field(default=None, description="Filtro de data/hora final (ISO 8601 ou YYYY-MM-DD)")
    limite: int = Field(default=100, description="Número máximo de eventos retornados")


class RuleDefinition(BaseModel):
    """Modelo representativo de uma regra de detecção do Suricata."""

    acao: str = Field(default="alert", description="Ação da regra (alert, drop, pass, reject)")
    protocolo: str = Field(default="ip", description="Protocolo (tcp, udp, icmp, ip, http, tls, dns)")
    origem_ip: str = Field(default="$HOME_NET", description="IP ou variável de origem")
    origem_porta: str = Field(default="any", description="Porta de origem")
    direcao: str = Field(default="->", description="Direção do fluxo (-> ou <>)")
    destino_ip: str = Field(default="$EXTERNAL_NET", description="IP ou variável de destino")
    destino_porta: str = Field(default="any", description="Porta de destino")
    mensagem: str = Field(description='Mensagem descritiva do alerta (msg:"...")')
    sid: int = Field(description="Signature ID numérico único")
    rev: int = Field(default=1, description="Número de revisão da regra")
    classtype: str | None = Field(default=None, description="Classificação da ameaça")
    opcoes: list[str] = Field(default_factory=list, description="Opções adicionais (content, pcre, flow, etc.)")
    ativo: bool = Field(default=True, description="Se a regra está ativa ou comentada com #")
    texto_bruto: str = Field(default="", description="Linha completa da regra formatada")


class IncidentRecord(BaseModel):
    """Registro de incidente defensivo derivado da telemetria do Suricata."""

    id_incidente: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:6].upper()}")
    titulo: str = Field(description="Título objetivo do incidente")
    descricao: str = Field(description="Detalhamento técnico do incidente e escopo observado")
    severidade: str = Field(default="Alta", description="Severidade (Crítica, Alta, Média, Baixa)")
    status: str = Field(default="Novo", description="Status (Novo, Em Análise, Mitigado, Falso Positivo, Fechado)")
    ips_impactados: list[str] = Field(default_factory=list, description="Lista de IPs suspeitos ou vítimas")
    sids_alertas: list[int] = Field(default_factory=list, description="Assinaturas de alertas vinculadas")
    data_criacao: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    plano_acao_sugerido: list[str] = Field(default_factory=list, description="Recomendações defensivas")
