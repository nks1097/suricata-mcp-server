"""Motor de geração de relatórios técnicos e executivos nos formatos PDF, XLSX, CSV, JSON e Markdown."""

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import get_settings
from .exceptions import SuricataReportError


class ReportEngine:
    """Gera relatórios consolidados de segurança a partir de evidências do Suricata."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def _generate_filename(self, prefix: str, extension: str) -> Path:
        """Cria um caminho de arquivo de relatório seguro dentro do diretório de relatórios."""
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{ts}.{extension}"
        return self.settings.get_reports_dir() / filename

    def export_csv(self, rows: list[dict[str, Any]], prefix: str = "relatorio_suricata") -> str:
        """Exporta lista de dicionários para arquivo CSV."""
        if not rows:
            raise SuricataReportError("Não há dados para exportar em CSV.")

        target = self._generate_filename(prefix, "csv")
        headers = list(rows[0].keys())

        with open(target, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                # Serializa valores complexos em JSON
                cleaned_row = {
                    k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v) for k, v in row.items()
                }
                writer.writerow(cleaned_row)

        return str(target)

    def export_json(self, data: Any, prefix: str = "relatorio_suricata") -> str:
        """Exporta estrutura de dados para arquivo JSON identado."""
        target = self._generate_filename(prefix, "json")
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return str(target)

    def export_xlsx(self, sheets_data: dict[str, list[dict[str, Any]]], prefix: str = "relatorio_suricata") -> str:
        """Exporta dados para uma pasta de trabalho Excel (.xlsx) com múltiplas abas."""
        try:
            from openpyxl import Workbook
            from openpyxl.styles import Font, PatternFill
        except ImportError as e:
            raise SuricataReportError("Biblioteca 'openpyxl' não disponível para exportação XLSX.") from e

        wb = Workbook()
        # Remove a aba padrão inicial
        wb.remove(wb.active)

        for sheet_name, rows in sheets_data.items():
            ws = wb.create_sheet(title=sheet_name[:31])  # Excel limita título a 31 chars
            if not rows:
                ws.append(["Sem registros"])
                continue

            headers = list(rows[0].keys())
            ws.append(headers)

            # Estilização do cabeçalho
            header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
            header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
            for cell in ws[1]:
                cell.font = header_font
                cell.fill = header_fill

            for r in rows:
                ws.append(
                    [(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v) for v in r.values()]
                )

        target = self._generate_filename(prefix, "xlsx")
        wb.save(target)
        return str(target)

    def export_pdf(self, title: str, sections: list[dict[str, Any]], prefix: str = "relatorio_suricata") -> str:
        """Gera um relatório profissional formatado em PDF via ReportLab."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        except ImportError as e:
            raise SuricataReportError("Biblioteca 'reportlab' não disponível para exportação PDF.") from e

        target = self._generate_filename(prefix, "pdf")
        doc = SimpleDocTemplate(
            str(target), pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#1F4E78"),
            spaceAfter=12,
        )
        h2_style = ParagraphStyle(
            "ReportH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#2C3E50"),
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = styles["Normal"]

        story = []
        # Cabeçalho do Relatório
        story.append(Paragraph(title, title_style))
        ts_str = datetime.now(UTC).strftime("%d/%m/%Y %H:%M:%S UTC")
        story.append(Paragraph(f"<b>Gerado por:</b> Suricata MCP Server | <b>Data:</b> {ts_str}", body_style))
        story.append(Spacer(1, 14))

        # Adiciona seções
        for sec in sections:
            story.append(Paragraph(sec.get("titulo", "Seção"), h2_style))
            conteudo = sec.get("conteudo")
            if isinstance(conteudo, str):
                story.append(Paragraph(conteudo.replace("\n", "<br/>"), body_style))
            elif isinstance(conteudo, list) and conteudo and isinstance(conteudo[0], dict):
                # Converte lista de dicts em tabela PDF
                table_headers = list(conteudo[0].keys())[:5]  # Limita colunas para caber na página
                table_data = [table_headers]
                for item in conteudo[:15]:  # Amostra de linhas
                    table_data.append([str(item.get(k, ""))[:30] for k in table_headers])

                t = Table(table_data)
                t.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ]
                    )
                )
                story.append(t)
            story.append(Spacer(1, 10))

        doc.build(story)
        return str(target)
