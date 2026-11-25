"""Build the stage-one DOCX from the versioned Russian report."""

import re
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE
from docx.shared import Cm, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/stage1-report.md"
OUTPUT = ROOT / "docs/stage1-report.docx"


def inline(paragraph, text):
    for part in re.split(r"(\[[^\]]+\]\(https?://[^)]+\))", text):
        match = re.fullmatch(r"\[([^\]]+)\]\((https?://[^)]+)\)", part)
        if match is None:
            paragraph.add_run(part)
            continue
        label, url = match.groups()
        link = OxmlElement("w:hyperlink")
        link.set(qn("r:id"), paragraph.part.relate_to(
            url, RELATIONSHIP_TYPE.HYPERLINK, is_external=True
        ))
        run = OxmlElement("w:r")
        properties = OxmlElement("w:rPr")
        color = OxmlElement("w:color")
        color.set(qn("w:val"), "254B72")
        properties.append(color)
        run.append(properties)
        content = OxmlElement("w:t")
        content.text = label
        run.append(content)
        link.append(run)
        paragraph._p.append(link)


def table(doc, rows):
    records = [[c.strip() for c in row.strip("|").split("|")] for row in rows]
    records.pop(1)
    table = doc.add_table(rows=1, cols=len(records[0]))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    widths = {
        4: [3.2, 3.3, 5.8, 4.7],
        5: [4.4, 3.4, 3.0, 3.6, 2.6],
        3: [4.0, 6.5, 6.5],
    }[len(records[0])]
    if len(records[0]) == 4 and "Типов на API" in records[0]:
        widths = [3.4, 2.5, 2.6, 8.5]
    if len(records[0]) == 4 and "schema-only" in records[0]:
        widths = [7.0, 2.0, 4.0, 4.0]
    for column, width in zip(table.columns, widths):
        column.width = Cm(width)
    for row_index, record in enumerate(records):
        cells = table.rows[0].cells if row_index == 0 else table.add_row().cells
        for cell, text, width in zip(cells, record, widths):
            cell.width = Cm(width)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_after = Pt(3)
            paragraph.paragraph_format.space_before = Pt(3)
            paragraph.paragraph_format.line_spacing = 1.03
            run = paragraph.add_run(text)
            run.font.size = Pt(9)
            run.bold = row_index == 0
            properties = cell._tc.get_or_add_tcPr()
            shade = OxmlElement("w:shd")
            shade.set(qn("w:fill"), "E9EFF4" if row_index == 0 else "FFFFFF")
            properties.append(shade)
            margins = OxmlElement("w:tcMar")
            for side in ("top", "left", "bottom", "right"):
                item = OxmlElement("w:" + side)
                item.set(qn("w:w"), "80")
                item.set(qn("w:type"), "dxa")
                margins.append(item)
            properties.append(margins)
        row_props = table.rows[row_index]._tr.get_or_add_trPr()
        row_props.append(OxmlElement("w:cantSplit"))
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        item = OxmlElement("w:" + edge)
        for key, value in {"val": "single", "sz": "4", "color": "D9D9D9"}.items():
            item.set(qn("w:" + key), value)
        borders.append(item)
    table._tbl.tblPr.append(borders)
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.space_after = Pt(0)
    paragraph.paragraph_format.space_before = Pt(0)
    paragraph.paragraph_format.line_spacing = Pt(2)
    paragraph.add_run().font.size = Pt(2)


def main():
    doc = Document()
    section = doc.sections[0]
    section.page_width, section.page_height = Cm(21), Cm(29.7)
    section.top_margin = section.bottom_margin = Cm(1.8)
    section.left_margin = section.right_margin = Cm(2)
    for name, size in (("Normal", 10.5), ("Title", 24), ("Heading 1", 14)):
        style = doc.styles[name]
        style.font.name = "Calibri"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.line_spacing = 1.08
        style.paragraph_format.space_after = Pt(6)
        properties = style.element.get_or_add_rPr()
        language = OxmlElement("w:lang")
        language.set(qn("w:val"), "ru-RU")
        properties.append(language)
        for color in properties.findall(qn("w:color")):
            color.attrib.pop(qn("w:themeColor"), None)
        for border in style.element.xpath("./w:pPr/w:pBdr"):
            border.getparent().remove(border)
    doc.styles["Title"].font.bold = True
    doc.styles["Title"].paragraph_format.space_after = Pt(12)
    doc.styles["Heading 1"].font.bold = True
    doc.styles["Heading 1"].paragraph_format.space_before = Pt(9)
    doc.styles["Heading 1"].paragraph_format.keep_with_next = True

    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("|"):
            block = []
            while index < len(lines) and lines[index].startswith("|"):
                block.append(lines[index])
                index += 1
            table(doc, block)
            continue
        if line == "<!-- pagebreak -->":
            doc.add_page_break()
        elif line.startswith("# "):
            inline(doc.add_paragraph(style="Title"), line[2:])
        elif line.startswith("## "):
            inline(doc.add_paragraph(style="Heading 1"), line[3:])
        elif line:
            inline(doc.add_paragraph(), line)
        index += 1
    footer = section.footer.paragraphs[0]
    footer.alignment = 2
    page = OxmlElement("w:fldSimple")
    page.set(qn("w:instr"), "PAGE")
    footer._p.append(page)
    doc.core_properties.title = "Контроль вызовов API у ИИ агентов"
    doc.core_properties.subject = "Этап 1 исследования"
    doc.core_properties.author = "Команда Innopolis University"
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
