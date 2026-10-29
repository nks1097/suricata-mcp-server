"""Testes de execução de fumaça (smoke test) para cada uma das 100 ferramentas."""

import inspect
from pathlib import Path

import pytest

from suricata_mcp.config import get_settings
from suricata_mcp.tools import ALL_TOOLS


@pytest.mark.parametrize("tool_func", ALL_TOOLS, ids=lambda f: f.__name__)
def test_tool_execution_returns_valid_envelope(tool_func) -> None:
    """Executa cada ferramenta com parâmetros adequados à sua assinatura e valida o envelope de resposta."""
    name = tool_func.__name__
    sig = inspect.signature(tool_func)
    params = sig.parameters

    kwargs = {}

    # Configuração de arquivos necessários para os testes
    settings = get_settings()
    dummy_pcap = settings.get_pcap_dir() / "dummy.pcap"
    if not dummy_pcap.exists():
        dummy_pcap.write_bytes(
            b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
        )

    # Mapeamento dinâmico baseado no nome exato do parâmetro
    for param_name, param in params.items():
        if param.default is not inspect.Parameter.empty:
            continue  # Possui valor default, não precisa passar

        if param_name in ("ip", "ip_origem", "ip_alvo", "ip_suspeito", "ip_investigado"):
            kwargs[param_name] = "192.168.1.50"
        elif param_name == "ip_destino":
            kwargs[param_name] = "93.184.216.34"
        elif param_name == "severidade":
            kwargs[param_name] = 1
        elif param_name == "ioc_valor":
            kwargs[param_name] = "192.168.1.50"
        elif param_name in ("termo", "termo_busca"):
            kwargs[param_name] = "log4j"
        elif param_name == "sid":
            kwargs[param_name] = 2100498
        elif param_name in ("regra_texto", "nova_regra_texto"):
            kwargs[param_name] = 'alert tcp any any -> any any (msg:"Dynamic Test Rule"; sid:9998001; rev:1;)'
        elif param_name == "novo_conteudo_yaml":
            kwargs[param_name] = "suricata-version: '8.0'\n"
        elif param_name == "caminho_pcap" or param_name in ("pcap_a", "pcap_b"):
            kwargs[param_name] = str(dummy_pcap)
        elif param_name == "diretorio_temporario":
            import tempfile

            d = Path(tempfile.mkdtemp(prefix="suricata_pcap_analysis_test"))
            kwargs[param_name] = str(d)
        elif param_name == "titulo":
            kwargs[param_name] = "Incidente de Teste"
        elif param_name == "descricao":
            kwargs[param_name] = "Descrição técnica de teste"
        elif param_name == "ips_impactados":
            kwargs[param_name] = ["192.168.1.50"]
        elif param_name == "id_incidente":
            kwargs[param_name] = "INC-TEST-001"
        elif param_name == "novo_status":
            kwargs[param_name] = "Em Análise"
        elif param_name == "dominio":
            kwargs[param_name] = "example.com"
        elif param_name == "nome_fluxo":
            kwargs[param_name] = "triagem_rapida"

    # Para suricata_desativar_regra_local, garantir que exista a regra local antes
    if name == "suricata_desativar_regra_local":
        import contextlib

        from suricata_mcp.rule_manager import RuleManager

        mgr = RuleManager()
        with contextlib.suppress(Exception):
            mgr.add_local_rule('alert tcp any any -> any any (msg:"Rule to Deactivate"; sid:9998002; rev:1;)')
        kwargs["sid"] = 9998002

    # Para suricata_atualizar_regra_local
    if name == "suricata_atualizar_regra_local":
        import contextlib

        from suricata_mcp.rule_manager import RuleManager

        mgr = RuleManager()
        with contextlib.suppress(Exception):
            mgr.add_local_rule('alert tcp any any -> any any (msg:"Rule to Update"; sid:9998003; rev:1;)')
        kwargs["sid"] = 9998003
        kwargs["nova_regra_texto"] = 'alert tcp any any -> any any (msg:"Rule Updated"; sid:9998003; rev:2;)'

    # Executa a ferramenta
    try:
        response = tool_func(**kwargs)
    except Exception as e:
        pytest.fail(f"A ferramenta '{name}' disparou exceção não tratada com kwargs {kwargs}: {e}")

    # Valida estrutura do StandardResponseEnvelope
    assert isinstance(response, dict), f"A ferramenta '{name}' não retornou um dicionário."
    for field in ("sucesso", "dados", "erro", "avisos", "id_requisicao", "metadados"):
        assert field in response, f"A ferramenta '{name}' omitiu o campo obrigatório '{field}' no envelope."

    assert isinstance(response["metadados"], dict)
    assert "duracao_ms" in response["metadados"]
    assert "fonte_dados" in response["metadados"]
