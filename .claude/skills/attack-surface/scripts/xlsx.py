"""Excel ブック（.xlsx）を書き出す最小限の部品。標準ライブラリのみ。

使い方:
    book = Workbook()
    sh = book.sheet("対象一覧", widths=[10, 8, 40], freeze=True, autofilter=True)
    sh.row(["ID", "Method", "パス"], style="head")
    sh.row([Link("AS-0001", "リクエスト", 2), "POST", "/x"])
    book.save(path)

スタイル: head（見出し）/ text（折り返し）/ alt（折り返し・薄い地色）/ mono（等幅・折り返し）/ link / link_alt / title / note
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

CELL_MAX = 32000  # Excel の 1 セルの上限は 32,767 字
_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
STYLES = {"text": 0, "head": 1, "alt": 2, "mono": 3, "link": 4, "link_alt": 5, "title": 6, "note": 7}


class Link:
    """同じブック内の別シートのセルへのリンク。"""

    def __init__(self, text: str, sheet: str, row: int, col: str = "A") -> None:
        self.text, self.sheet, self.row, self.col = str(text), sheet, row, col


def col_name(i: int) -> str:
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def _clean(v) -> str:
    s = _ILLEGAL.sub("", "" if v is None else str(v))
    return s if len(s) <= CELL_MAX else s[:CELL_MAX] + "\n…（長いため省略。全文は attack-surface.json）"


class Sheet:
    def __init__(self, name: str, widths: list[float] | None, freeze: bool, autofilter: bool) -> None:
        self.name = name[:31]
        self.widths, self.freeze, self.autofilter = widths or [], freeze, autofilter
        self.rows: list[tuple[list, str | list[str]]] = []

    def row(self, values: list, style: str | list[str] = "text") -> int:
        """1 行足して、その行番号（1 始まり）を返す。style は行全体に 1 つ、または列ごとのリスト。"""
        self.rows.append((list(values), style))
        return len(self.rows)

    def xml(self) -> str:
        out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">']
        ncols = max((len(v) for v, _ in self.rows), default=1)
        if self.freeze:
            out.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
        if self.widths:
            out.append("<cols>" + "".join(f'<col min="{i + 1}" max="{i + 1}" width="{w}" customWidth="1"/>' for i, w in enumerate(self.widths)) + "</cols>")
        out.append("<sheetData>")
        links: list[tuple[str, Link]] = []
        for r, (values, style) in enumerate(self.rows, 1):
            cells = []
            for c, v in enumerate(values):
                ref = f"{col_name(c)}{r}"
                st = style[c] if isinstance(style, list) else style
                if isinstance(v, Link):
                    links.append((ref, v))
                    st = "link_alt" if st in ("alt", "link_alt") else "link"
                    v = v.text
                s = STYLES.get(st, 0)
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    cells.append(f'<c r="{ref}" s="{s}"><v>{v}</v></c>')
                else:
                    text = _clean(v)
                    cells.append(f'<c r="{ref}" s="{s}" t="inlineStr"><is><t xml:space="preserve">{escape(text)}</t></is></c>' if text else f'<c r="{ref}" s="{s}"/>')
            out.append(f'<row r="{r}">' + "".join(cells) + "</row>")
        out.append("</sheetData>")
        if self.autofilter and self.rows:
            out.append(f'<autoFilter ref="A1:{col_name(ncols - 1)}{len(self.rows)}"/>')
        if links:
            # display を必ず付ける（省くと、Google スプレッドシートで表示が #gid=… に置き換わる）
            out.append("<hyperlinks>" + "".join(
                f'<hyperlink ref="{ref}" location="{escape(chr(39) + ln.sheet[:31] + chr(39) + "!" + ln.col + str(ln.row), {chr(34): "&quot;"})}" '
                f'display="{escape(_clean(ln.text), {chr(34): "&quot;"})}"/>' for ref, ln in links) + "</hyperlinks>")
        out.append("</worksheet>")
        return "".join(out)


class Workbook:
    def __init__(self) -> None:
        self.sheets: list[Sheet] = []

    def sheet(self, name: str, widths: list[float] | None = None, freeze: bool = True, autofilter: bool = True) -> Sheet:
        sh = Sheet(name, widths, freeze, autofilter)
        self.sheets.append(sh)
        return sh

    def save(self, path: Path) -> None:
        n = len(self.sheets)
        q = {'"': "&quot;"}
        files = {
            "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, n + 1))
            + "</Types>",
            "_rels/.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            "xl/workbook.xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
            + "".join(f'<sheet name="{escape(s.name, q)}" sheetId="{i}" r:id="rId{i}"/>' for i, s in enumerate(self.sheets, 1)) + "</sheets></workbook>",
            "xl/_rels/workbook.xml.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, n + 1))
            + f'<Relationship Id="rId{n + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>',
            "xl/styles.xml": _STYLES_XML,
        }
        for i, s in enumerate(self.sheets, 1):
            files[f"xl/worksheets/sheet{i}.xml"] = s.xml()
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                z.writestr(name, data)


_WRAP = '<alignment vertical="top" wrapText="1"/>'
_STYLES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="6">'
    '<font><sz val="10"/><name val="Meiryo UI"/></font>'
    '<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Meiryo UI"/></font>'
    '<font><sz val="9"/><name val="Consolas"/></font>'
    '<font><u/><sz val="10"/><color rgb="FF0563C1"/><name val="Meiryo UI"/></font>'
    '<font><b/><sz val="14"/><name val="Meiryo UI"/></font>'
    '<font><sz val="10"/><color rgb="FF595959"/><name val="Meiryo UI"/></font>'
    "</fonts>"
    '<fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF1F3864"/><bgColor indexed="64"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFEAF3FA"/><bgColor indexed="64"/></patternFill></fill></fills>'
    '<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>'
    '<border><left style="thin"><color rgb="FFD0D7DE"/></left><right style="thin"><color rgb="FFD0D7DE"/></right>'
    '<top style="thin"><color rgb="FFD0D7DE"/></top><bottom style="thin"><color rgb="FFD0D7DE"/></bottom><diagonal/></border></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="8">'
    f'<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1">{_WRAP}</xf>'
    '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf>'
    f'<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1">{_WRAP}</xf>'
    f'<xf numFmtId="0" fontId="2" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1">{_WRAP}</xf>'
    f'<xf numFmtId="0" fontId="3" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1">{_WRAP}</xf>'
    f'<xf numFmtId="0" fontId="3" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">{_WRAP}</xf>'
    '<xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
    f'<xf numFmtId="0" fontId="5" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1">{_WRAP}</xf>'
    '</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'
)
