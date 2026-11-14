#!/usr/bin/env python3
"""読み手・探し手への依頼文を組み立てて、RUN/work/briefs/ に書く。解析はしない。

references/briefs.md のひな形に、ユニット ID・RUN・観点（references/hiding-places.md の該当する節の全文）を埋める。
取りまとめ役は、依頼文を自分で書き起こす代わりに「<RUN>/work/briefs/<名前>.md を読み、そのとおりに進めてください」とだけ伝えればよい。
（ひな形と節を毎回書き写すと、小さい入力でも数万トークンを使う）

使い方:
  python make_briefs.py RUN                       # パス 1（全ユニット）とパス 2（規模に応じた組み分け）
  python make_briefs.py RUN --groups "entry+authz,implicit+leftover,intake,parsers"   # パス 2 の組み分けを指定
  python make_briefs.py RUN --pass1-self          # パス 1 を取りまとめ役が自分で読む場合（パス 1 の依頼文を作らない）

背景（全体像）は依頼文に貼らず、RUN/work/orientation.md を読ませる。先に orientation.md を書いておくこと。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
from _common import load_run, utf8_stdout  # noqa: E402

REF = Path(__file__).parent.parent / "references"
SMALL = ["entry+implicit+client+infra+nonhttp+leftover+authz", "intake+parsers", "assumptions+open"]
MEDIUM = ["entry+authz", "implicit+leftover", "client+infra+nonhttp", "intake", "parsers", "assumptions+open"]
LARGE = ["entry", "implicit", "client", "infra", "nonhttp", "leftover", "authz", "intake", "parsers", "assumptions", "open"]
OPEN_TEXT = ("常識的な一覧には載らなさそうな入口を中心に、このシステムに外部から入力を届ける方法を自由に探してください。\n"
             "観点は指定しません。このコードを書いた人が「ここは外からは来ない」と思い込んでいそうな箇所を疑ってください。")


def template(text: str, heading: str) -> str:
    """briefs.md の、見出しの直後にある最初のコードブロック。"""
    i = text.index(heading)
    m = re.search(r"```\n(.*?)\n```", text[i:], re.S)
    if not m:
        sys.exit(f"ERROR: briefs.md の「{heading}」の下にひな形が見つかりません")
    return m.group(1)


def lens_sections(text: str) -> dict[str, str]:
    """hiding-places.md の「## N. `lens` — …」ごとの節。"""
    out: dict[str, str] = {}
    parts = re.split(r"(?m)^## \d+\. `([a-z]+)`", text)
    for i in range(1, len(parts) - 1, 2):
        body = parts[i + 1]
        body = re.split(r"(?m)^## ", body)[0].rstrip()
        out[parts[i]] = f"`{parts[i]}`{body}"
    return out


def conditional(text: str, lenses: list[str]) -> str:
    """「<X レンズのときだけ追加:>」の行と、それに続く行を、該当するときだけ残す。"""
    out, keep = [], True
    for line in text.split("\n"):
        m = re.match(r"^<(.+?) レンズのときだけ追加:>$", line)
        if m:
            wanted = re.findall(r"[a-z]+", m.group(1))
            keep = any(w in lenses for w in wanted)
            continue
        if line.startswith("■"):
            keep = True
        if keep:
            out.append(line)
    return "\n".join(out)


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    ap.add_argument("--groups", default="", help="パス 2 の組み分け。観点を + でつなぎ、組を , で区切る")
    ap.add_argument("--pass1-self", action="store_true")
    args = ap.parse_args()
    run = Path(args.run)
    inventory, unitdata = load_run(run)
    units = unitdata.get("units", [])
    work = run / "work"
    out = work / "briefs"
    out.mkdir(exist_ok=True)
    run_s, sk = run.as_posix(), Path(__file__).parent.parent.as_posix()
    if not (work / "orientation.md").exists():
        print("WARNING: orientation.md がまだありません。依頼文は orientation.md を読ませる形なので、先に書いてください。")

    briefs = (REF / "briefs.md").read_text(encoding="utf-8")
    sections = lens_sections((REF / "hiding-places.md").read_text(encoding="utf-8"))
    background = (f"{run_s}/work/orientation.md を最初に読んでください。このシステムの全体像、技術とバージョン、ソース間の関係の仮説、読むときの注意、"
                  "どの担当者も参照してよい共通のファイル（ルート表など）が書いてあります。")

    def fill(t: str) -> str:
        return t.replace("<RUN>", run_s).replace("<SK>", sk).replace("<INPUT_ROOT>", str(inventory.get("input_root", "")))

    written: list[str] = []
    if not args.pass1_self:
        p1 = template(briefs, "## パス 1")
        p1 = re.sub(r"(?m)^<orientation\.md の要点[^\n]*>$", lambda _m: background, p1)
        for u in units:
            path = out / f"pass1-{u['id']}.md"
            path.write_text(fill(p1.replace("<UNIT_ID>", u["id"])) + "\n", encoding="utf-8")
            written.append(path.name)

    total = sum(u.get("est_tokens", 0) for u in units)
    groups = [g.strip() for g in args.groups.split(",") if g.strip()] or (SMALL if total < 60_000 else MEDIUM if total < 600_000 else LARGE)
    p2 = template(briefs, "## パス 2")
    p2 = re.sub(r"(?m)^<orientation\.md の全文[^\n]*>$", lambda _m: background, p2)
    used: list[str] = []
    for g in groups:
        lenses = [x for x in g.split("+") if x]
        unknown = [x for x in lenses if x not in sections]
        if unknown:
            sys.exit(f"ERROR: 知らない観点: {', '.join(unknown)}（使えるもの: {' '.join(sections)}）")
        used += lenses
        name = lenses[0] if len(lenses) == 1 else "-".join(lenses) if len(lenses) <= 3 else f"{lenses[0]}-group"
        parts = [OPEN_TEXT if x == "open" and len(lenses) == 1 else
                 (sections[x] if x != "open" else "`open` — 自由枠\n\n上の観点とは別に、次も行ってください。\n" + OPEN_TEXT) for x in lenses]
        body = "\n\n".join(parts)
        if len(lenses) > 1:
            body = (f"次の {len(lenses)} つの観点を、順に全部行ってください（{' / '.join(lenses)}）。"
                    "各検出項目の found_by には、実際にその項目を見つけた観点の名前を書きます（例 \"pass2:" + lenses[0] + "\"）。\n\n") + body
        text = conditional(p2, lenses)
        text = re.sub(r"(?m)^<LENS_ID>: <hiding-places\.md[^\n]*>$", lambda _m: body, text)
        text = text.replace('found_by は "pass2:<LENS_ID>"', 'found_by は "pass2:<観点の名前>"' if len(lenses) > 1 else f'found_by は "pass2:{lenses[0]}"')
        path = out / f"pass2-{name}.md"
        path.write_text(fill(text.replace("<LENS_ID>", name)) + "\n", encoding="utf-8")
        written.append(path.name)

    missing = [x for x in sections if x not in used]
    print(f"briefs={len(written)} dir={out.as_posix()} pass2_groups={len(groups)}")
    for w in written:
        print(f"  {w}")
    if missing:
        print(f"WARNING: どの組にも入っていない観点: {' '.join(missing)}")
    print("依頼の言い方: 「<上のファイルのパス> を読み、書かれているとおりに調査を進めてください。」（依頼文の中身を書き写さない）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
