"""Testes unitários para o motor de geração e exportação de relatórios."""

from pathlib import Path

from suricata_mcp.report_engine import ReportEngine


def test_export_csv(tmp_path: Path) -> None:
    """Verifica exportação de CSV."""
    engine = ReportEngine()
    rows = [
        {"ip": "192.168.1.10", "alertas": 5, "status": "Suspeito"},
        {"ip": "10.0.0.5", "alertas": 1, "status": "Normal"},
    ]
    csv_path = engine.export_csv(rows, prefix="test_export")
    p = Path(csv_path)
    assert p.is_file()
    assert p.stat().st_size > 0
    content = p.read_text(encoding="utf-8")
    assert "192.168.1.10" in content


def test_export_json() -> None:
    """Verifica exportação de JSON."""
    engine = ReportEngine()
    data = {"sensor": "suricata-01", "eventos": [1, 2, 3]}
    json_path = engine.export_json(data, prefix="test_export")
    p = Path(json_path)
    assert p.is_file()
    assert p.stat().st_size > 0


def test_export_xlsx() -> None:
    """Verifica exportação de planilha Excel com abas."""
    engine = ReportEngine()
    sheets = {
        "Alertas": [{"sid": 2100498, "msg": "Log4j"}],
        "Resumo": [{"total": 1}],
    }
    xlsx_path = engine.export_xlsx(sheets, prefix="test_export")
    p = Path(xlsx_path)
    assert p.is_file()
    assert p.stat().st_size > 0


def test_export_pdf() -> None:
    """Verifica geração de documento PDF via ReportLab."""
    engine = ReportEngine()
    sections = [
        {"titulo": "Resumo de Segurança", "conteudo": "Sensor operando em condições estáveis."},
        {"titulo": "Tabela de Alertas", "conteudo": [{"sid": "2100498", "severidade": "1"}]},
    ]
    pdf_path = engine.export_pdf("Relatório de Teste", sections, prefix="test_export")
    p = Path(pdf_path)
    assert p.is_file()
    assert p.stat().st_size > 0
