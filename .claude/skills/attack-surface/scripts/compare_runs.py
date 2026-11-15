#!/usr/bin/env python3
"""同じ入力に対する以前の実行と、項目単位で突き合わせる。解析はしない。

読み手・探し手が何を項目にするかは、実行ごとに少し揺れる。同じ入力の以前の実行が残っていれば、その確定版と今回の統合結果を比べ、
片方にしか無い項目を挙げる。以前の実行にしか無い項目は、取りまとめ役が根拠を確かめたうえで、今回の実行に持ち込める。

  1. 以前の実行（work/final.findings.jsonl）と、今回の統合結果（work/merged.findings.jsonl）を読む
  2. 同じ対象かどうかを、統合と同じ規則で判定する。当たらなかったものは「層と種別が同じで、根拠 1 件目が同じファイルの近い行」で補う
  3. work/compare.jsonl（任意）: 人が確かめた対応と、持ち込まない項目
  4. work/check/compare.md と compare.json に書く（書いた対応が、自動で付くはずだった別の対応を外したときは、その組も挙げる）
  5. --carry を付けると、以前の実行にしか無い項目を work/carryover/<以前の実行名>.findings.jsonl に書く（consolidate.py が読む）

work/compare.jsonl の書式（1 行 1 件の JSON。無ければ何もしない）:
  {"old": "<以前の実行の key か識別子>", "new": "<今回の key か識別子>"}   … 書き方も根拠の行も違うが、読んで同じ対象と確かめたもの
  {"old": "<以前の実行の key か識別子>", "new": "<今回の key か識別子>", "same": false}   … 自動で対応づけられたが、別の対象だったもの
  {"old": "<以前の実行の key か識別子>", "skip": "理由"}                    … 持ち込まない（今回の別の項目に含まれる、今の入力では成り立たない、誤りだった）
  {"old": "<以前の実行の key か識別子>", "carry": "確かめたこと"}            … 根拠を確かめたうえで持ち込む（何も書かなくても持ち込まれるが、判断の記録として書く）

使い方:
  python compare_runs.py RUN                  # 同じソースを対象にした直近の実行を、RUN と同じ場所から探して比べる。無ければ何もしない
  python compare_runs.py RUN --old OLD_RUN    # 比べる相手を指定する
  python compare_runs.py RUN --carry          # 比べたうえで、持ち込む項目を書き出す（何度実行しても同じ結果になる）
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
from _common import (  # noqa: E402
    Index, anchor, category_of, first_evidence, kind_of, layer_of, load_jsonl, load_run, norm_file, prepare, role_of, squash, stable_key, utf8_stdout,
)

NEAR = 3  # 根拠の行がこの幅に入っていれば「同じ箇所」（check.py が根拠を照合する幅と同じ）
DERIVED = ("id", "key", "layer", "also_hosts", "reaches", "priority", "priority_reason")  # 統合や出力のときに付くもの。持ち込むときは落とす


def label(it: dict) -> str:
    return f"{it.get('method', '') or ''} {it.get('path', '')}".strip()


def cell(s, n: int = 0) -> str:
    s = squash(s).replace("|", "¦").replace("`", "'")
    return s[: n - 1] + "…" if n and len(s) > n else s


def where(it: dict) -> str:
    f, line, _q = first_evidence(it)
    return f"{f}:{line}" if f else "-"


def pure_carry(it: dict) -> bool:
    """以前の実行から持ち込んだだけの項目か（今回の読み手・探し手は挙げていない）。"""
    parts = [x for x in str(it.get("found_by", "")).split("+") if x]
    return bool(parts) and all(x.startswith("carryover:") for x in parts)


def find_previous(run: Path, sources: set[str]) -> Path | None:
    """RUN と同じ場所にある、同じソースを対象にした確定済みの実行のうち、いちばん新しいもの。"""
    best: tuple[str, Path] | None = None
    for d in run.resolve().parent.iterdir():
        if not d.is_dir() or d.resolve() == run.resolve() or not (d / "work" / "final.findings.jsonl").exists():
            continue
        try:
            inv = json.loads((d / "work" / "inventory.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if {str(s.get("name", "")).lower() for s in inv.get("sources", [])} != sources:
            continue
        stamp = str(inv.get("created", "")) or d.name
        if best is None or stamp > best[0]:
            best = (stamp, d)
    return best[1] if best else None


def load_items(run: Path, name: str) -> list[dict]:
    """確定版・統合結果を読み、照合用に整える。各項目に _k（鍵）と _raw（元の行）を付ける。"""
    rows, _errs = load_jsonl(run / "work" / name)
    ids = {}
    out_path = run / "attack-surface.json"
    if out_path.exists():
        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
            ids = {str(it.get("key", "")): str(it.get("id", "")) for it in (data.get("items") if isinstance(data, dict) else data) or []}
        except (OSError, ValueError):
            ids = {}
    items, used = [], Counter()
    for r in rows:
        p = prepare(r)
        key = str(r.get("key") or stable_key(p))
        used[key] += 1
        p["_k"] = key if used[key] == 1 else f"{key}-{used[key]}"
        p["_id"] = ids.get(p["_k"], "")
        p["_raw"] = {k: v for k, v in r.items() if not k.startswith("_")}
        items.append(p)
    return items


def resolve_ref(ref: str, items: list[dict]) -> dict | None:
    """compare.jsonl の指し方（key、または識別子、または「メソッド 識別子」）から項目を 1 つ決める。決まらなければ None。"""
    ref = squash(ref)
    hit = [it for it in items if it["_k"] == ref]
    if not hit:
        hit = [it for it in items if squash(it.get("path", "")) == ref or label(it) == ref]
    return hit[0] if len(hit) == 1 else None


def spots(items: list[dict]) -> dict[tuple, list[dict]]:
    out: dict[tuple, list[dict]] = defaultdict(list)
    for it in items:
        for e in it.get("evidence") or []:
            if isinstance(e, dict) and e.get("file") and isinstance(e.get("line"), int):
                out[(norm_file(e["file"]), e["line"])].append(it)
    return out


def covering(it: dict, other: dict[tuple, list[dict]]) -> list[dict]:
    """この項目の根拠 1 件目の場所を、相手側で根拠にしている項目（粒度や層の分け方が違うだけで、同じ箇所は見ている）。"""
    f, line, _q = first_evidence(it)
    seen: dict[int, dict] = {}
    if f and line:
        for d in range(-NEAR, NEAR + 1):
            for x in other.get((f, line + d), []):
                seen.setdefault(id(x), x)
    return list(seen.values())


def auto_match(old: list[dict], new: list[dict], pair: dict[str, str], how: dict[str, str], differ: set) -> list[tuple[dict, dict]]:
    """すでに pair にある対応を除いて、統合と同じ規則 → 根拠の位置、の順に対応を付ける（pair と how を書き換える）。根拠の位置で付けた組を返す。"""
    index = Index()
    for it in old:
        if it["_k"] not in pair:
            index.add(it)
    taken = set(pair.values())
    rest: list[dict] = []
    for it in new:
        if it["_k"] in taken:
            continue
        hit = index.find(it)
        if hit is not None and hit["_k"] not in pair and (hit["_k"], it["_k"]) not in differ:
            pair[hit["_k"]], how[hit["_k"]] = it["_k"], "規則"
        else:
            rest.append(it)
    by_position: list[tuple[dict, dict]] = []
    for it in rest:
        f, line, _q = first_evidence(it)
        if not f or not line:
            continue
        cands = [o for o in old if o["_k"] not in pair and (o["_k"], it["_k"]) not in differ
                 and layer_of(o) == layer_of(it) and kind_of(o) == kind_of(it) and role_of(o) == role_of(it)
                 and first_evidence(o)[0] == f and first_evidence(o)[1] and abs(first_evidence(o)[1] - line) <= NEAR
                 and not (anchor(it) is not None and category_of(o) and category_of(it) and category_of(o) != category_of(it))]
        if len(cands) == 1:
            pair[cands[0]["_k"]], how[cands[0]["_k"]] = it["_k"], "根拠の位置"
            by_position.append((cands[0], it))
    return by_position


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    ap.add_argument("--old", default="", help="比べる相手の実行ディレクトリ（省略時は、同じソースを対象にした直近の実行を探す）")
    ap.add_argument("--carry", action="store_true", help="以前の実行にしか無い項目を work/carryover/ に書き出す")
    args = ap.parse_args()
    run = Path(args.run)
    inventory, _units = load_run(run)
    work = run / "work"
    (work / "check").mkdir(exist_ok=True)
    if not (work / "merged.findings.jsonl").exists():
        sys.exit(f"ERROR: {work / 'merged.findings.jsonl'} がありません。先に consolidate.py を実行してください。")

    sources = {str(s.get("name", "")).lower() for s in inventory.get("sources", [])}
    old_run = Path(args.old) if args.old else find_previous(run, sources)
    if old_run is None:
        print("previous=none（同じソースを対象にした以前の実行はありません。何もしません）")
        return 0
    if old_run.resolve() == run.resolve():
        sys.exit("ERROR: 比べる相手が今回の実行と同じです。")
    old_name = "final.findings.jsonl"
    if not (old_run / "work" / old_name).exists():
        sys.exit(f"ERROR: {old_run / 'work' / old_name} がありません（確定していない実行とは比べられません）。")

    old = load_items(old_run, old_name)
    new_all = load_items(run, "merged.findings.jsonl")
    new = [it for it in new_all if not pure_carry(it)]
    carried_before = len(new_all) - len(new)

    # ---- 入力の違い（同じ入力でなければ、持ち込む項目の根拠が今の入力に無いことがある）
    try:
        old_inv = json.loads((old_run / "work" / "inventory.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old_inv = {}
    fa = {norm_file(f.get("path", "")): f.get("size") for f in old_inv.get("files", [])}
    fb = {norm_file(f.get("path", "")): f.get("size") for f in inventory.get("files", [])}
    added, removed = sorted(set(fb) - set(fa)), sorted(set(fa) - set(fb))
    changed = sorted(p for p in set(fa) & set(fb) if fa[p] != fb[p])

    # ---- 対応づけ（人が確かめた判断 → 統合と同じ規則 → 根拠の位置、の順。先に付いた対応が優先される）
    pair: dict[str, str] = {}          # 以前の鍵 → 今回の鍵
    how: dict[str, str] = {}
    differ: set[tuple[str, str]] = set()   # 人が「別の対象」と確かめた組
    judgments, _errs = load_jsonl(work / "compare.jsonl") if (work / "compare.jsonl").exists() else ([], [])
    skip: dict[str, str] = {}          # 持ち込まないと決めた項目 → 理由
    keep: dict[str, str] = {}          # 確かめたうえで持ち込むと決めた項目 → 理由
    unresolved: list[str] = []
    for j in judgments:
        o = resolve_ref(str(j.get("old", "")), old)
        if o is None:
            unresolved.append(f"{j.get('_src', '')}: old `{j.get('old', '')}` が 1 件に決まらない")
            continue
        if "skip" in j:
            skip[o["_k"]] = str(j["skip"])
        elif "carry" in j:
            keep[o["_k"]] = str(j["carry"])
        elif j.get("new"):
            n = resolve_ref(str(j["new"]), new)
            if n is None:
                unresolved.append(f"{j.get('_src', '')}: new `{j.get('new', '')}` が 1 件に決まらない")
            elif j.get("same") is False:
                differ.add((o["_k"], n["_k"]))
            elif o["_k"] in pair or n["_k"] in pair.values():
                unresolved.append(f"{j.get('_src', '')}: `{j.get('old', '')}` か `{j.get('new', '')}` は、すでに別の行で対応を書いている")
            else:
                pair[o["_k"]], how[o["_k"]] = n["_k"], "人が確認"

    manual = dict(pair)
    by_position = auto_match(old, new, pair, how, differ)
    # 人の判断が無かったら自動で付いていた対応（人が書いた対応が、正しい自動の対応を外していないかを確かめるため）
    auto_only: dict[str, str] = {}
    auto_match(old, new, auto_only, {}, differ)
    displaced = []  # (人が書いた以前の鍵, 人が書いた今回の鍵, 外れた以前の鍵 / 外れた今回の鍵)
    auto_by_new = {n: o for o, n in auto_only.items()}
    for o, n in manual.items():
        o2 = auto_by_new.get(n)
        if o2 and o2 != o and o2 not in pair:
            displaced.append((o, n, f"以前の `{o2}` と今回の `{n}` の自動の対応が外れ、以前の `{o2}` は「以前の実行にしか無い」に回った"))
        n2 = auto_only.get(o)
        if n2 and n2 != n and n2 not in pair.values():
            displaced.append((o, n, f"以前の `{o}` と今回の `{n2}` の自動の対応が外れ、今回の `{n2}` は「今回にしか無い」に回った"))

    matched_new = set(pair.values())
    old_only = [it for it in old if it["_k"] not in pair]
    new_only = [it for it in new if it["_k"] not in matched_new]
    new_spots, old_spots = spots(new), spots(old)
    for it in old_only:
        it["_cover"] = covering(it, new_spots)
    for it in new_only:
        it["_cover"] = covering(it, old_spots)
    carry = [it for it in old_only if it["_k"] not in skip]
    # 今回も同じ箇所を根拠にする項目があるのに、判断が書かれていないもの（同じ対象の書き方違いを、別件として持ち込むおそれがある）
    undecided = [it for it in carry if it["_cover"] and it["_k"] not in keep]

    # ---- 持ち込み
    carry_path = work / "carryover" / f"{old_run.name}.findings.jsonl"
    if args.carry:
        rows = []
        for it in carry:
            r = {k: v for k, v in it["_raw"].items() if k not in DERIVED}
            if r.get("internal_path"):  # 公開パスへの付け替えは、今回の prefixes.jsonl がやり直す
                r["path"] = r["internal_path"]
            r.pop("internal_path", None)
            r["found_by"] = f"carryover:{old_run.name}"
            note = f"以前の実行（{old_run.name}、発見元 {it['_raw'].get('found_by', '')}）から持ち込んだ項目。今回の読み手・探し手は挙げていない"
            r["notes"] = (str(r.get("notes", "") or "") + " / " + note).strip(" /")
            rows.append(r)
        if rows:
            carry_path.parent.mkdir(exist_ok=True)
            carry_path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
        elif carry_path.exists():
            carry_path.unlink()

    # ---- 報告
    hows = Counter(how.values())
    no_cover_old = [it for it in old_only if not it["_cover"]]
    no_cover_new = [it for it in new_only if not it["_cover"]]
    same_input = not (added or removed or changed)
    md = ["# 以前の実行との突き合わせ", "",
          f"- 以前の実行: `{old_run.as_posix()}`（{len(old)} 件） / 今回: `{run.as_posix()}`（{len(new)} 件"
          + (f"。以前の実行から持ち込み済みの {carried_before} 件は除く" if carried_before else "") + "）",
          "- 入力のファイル: " + (f"同じ（{len(fb)} 件）" if same_input else
                             f"**違いがある**（追加 {len(added)} / 削除 {len(removed)} / サイズ違い {len(changed)}）。持ち込む項目の根拠が、今の入力でも成り立つかを確かめる"),
          f"- 対応が付いた項目: {len(pair)} 件（統合と同じ規則 {hows['規則']}、根拠の位置 {hows['根拠の位置']}、人が確認 {hows['人が確認']}）",
          f"- **以前の実行にしか無い: {len(old_only)} 件**（うち、今回どの項目も根拠にしていない箇所のもの {len(no_cover_old)} 件）",
          f"- **今回にしか無い: {len(new_only)} 件**（うち、以前の実行がどの項目も根拠にしていなかった箇所のもの {len(no_cover_new)} 件）",
          f"- 持ち込む項目: {len(carry)} 件（うち、今回も同じ箇所を根拠にする項目があるのに判断が書かれていないもの **{len(undecided)} 件**）"
          f" / 持ち込まないと決めた項目: {len(old_only) - len(carry)} 件"
          + (f"（`{carry_path.relative_to(run).as_posix()}` に書いた。`consolidate.py` をもう一度実行する）" if args.carry else "（書き出すには --carry）"), ""]
    if not same_input:
        md += [f"  - {name}: {'、'.join('`' + p + '`' for p in ps[:8])}{' ほか' if len(ps) > 8 else ''}"
               for name, ps in (("追加", added), ("削除", removed), ("サイズ違い", changed)) if ps] + [""]

    md += ["## 以前の実行にしか無い項目", "",
           "同じ入力でも、何を項目にするかは実行ごとに揺れる。ここにあるのは、以前の読み手・探し手が挙げ、今回は誰も挙げなかったもの。"
           "**根拠のファイルを開いて、今の入力でも成り立つかを確かめ、1 件ずつ `work/compare.jsonl` に判断を書く**（鍵の代わりに識別子でも指せる）。", "",
           "- 今回の項目と同じ対象（書き方や根拠の行が違うだけ）→ `{\"old\": \"<鍵>\", \"new\": \"<今回の鍵>\"}`。持ち込まれない",
           "- 今回の別の項目に含まれる、今の入力では成り立たない、誤りだった → `{\"old\": \"<鍵>\", \"skip\": \"理由\"}`。持ち込まれない",
           "- 今回の一覧に無い対象で、根拠も成り立つ → `{\"old\": \"<鍵>\", \"carry\": \"確かめたこと\"}`。持ち込まれる",
           "- 何も書かなければ持ち込まれる（取りこぼしを避ける側に倒してある）。今回も同じ箇所を根拠にする項目があるものは、同じ対象の書き方違いの見込みが高いので、"
           "判断を書かずに持ち込まない（表の「未判断」）", ""]

    def table(items: list[dict], with_cover: bool, with_action: bool) -> list[str]:
        head = ["鍵", "ID", "層", "種別", "識別子", "根拠", "発見元"] + (["相手側で同じ箇所を根拠にしている項目"] if with_cover else []) + (["扱い"] if with_action else [])
        out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        for it in items:
            row = [it["_k"], it["_id"] or "-", layer_of(it), kind_of(it), f"`{cell(label(it), 80)}`", f"`{cell(where(it))}`", cell(it.get("found_by", ""), 50)]
            if with_cover:
                row.append("<br>".join(f"`{cell(label(x), 60)}`（{x['_k']}）" for x in it["_cover"][:4]) + (" ほか" if len(it["_cover"]) > 4 else ""))
            if with_action:
                row.append(f"持ち込まない: {cell(skip[it['_k']], 80)}" if it["_k"] in skip else f"持ち込む: {cell(keep[it['_k']], 80)}" if it["_k"] in keep
                           else "**未判断**（このままなら持ち込む）" if it["_cover"] else "持ち込む")
            out.append("| " + " | ".join(row) + " |")
        return out + [""]

    for title, items, with_cover in (("### 今回、どの項目も根拠にしていない箇所のもの", no_cover_old, False),
                                     ("### 今回も、同じ箇所を根拠にする項目があるもの（粒度や層の分け方の違いの見込み）", [it for it in old_only if it["_cover"]], True)):
        md += [f"{title}: {len(items)} 件", ""] + (table(items, with_cover, True) if items else [])
    md += ["## 今回にしか無い項目", "",
           "今回の読み手・探し手が挙げ、以前の実行には無かったもの。そのまま残る。以前の実行の網羅状況を見直す材料になる。", ""]
    for title, items, with_cover in (("### 以前の実行が、どの項目も根拠にしていなかった箇所のもの", no_cover_new, False),
                                     ("### 以前の実行にも、同じ箇所を根拠にする項目があったもの", [it for it in new_only if it["_cover"]], True)):
        md += [f"{title}: {len(items)} 件", ""] + (table(items, with_cover, False) if items else [])
    if by_position:
        md += [f"## 根拠の位置で対応づけたもの: {len(by_position)} 組", "",
               "識別子は違うが、層と種別が同じで、根拠 1 件目が同じファイルの近い行を指すもの。別の対象だったら、`work/compare.jsonl` に "
               "`{\"old\": \"<鍵>\", \"new\": \"<今回の鍵>\", \"same\": false}` と書く（以前の項目は「以前の実行にしか無い項目」に戻る）。", "",
               "| 以前の実行（鍵） | 今回（鍵） | 根拠 |", "|---|---|---|"]
        md += [f"| `{cell(label(o), 70)}`（{o['_k']}） | `{cell(label(n), 70)}`（{n['_k']}） | `{cell(where(n))}` |" for o, n in by_position] + [""]
    if displaced:
        md += [f"## 人が書いた対応が外した、自動の対応: {len(displaced)} 件", "",
               "`work/compare.jsonl` に書いた `new` の対応が、統合と同じ規則か根拠の位置で付いていた別の対応を外した。"
               "外れた側が本当に別の対象かを確かめる。書いた対応が誤りなら直す（同じ今回の項目に以前の項目が 2 つ当たるなら、片方は `skip`（今回の項目に含まれる）にする）。", "",
               "| 人が書いた対応（以前 → 今回） | 外れたもの |", "|---|---|"]
        md += [f"| `{o}` → `{n}` | {what} |" for o, n, what in displaced] + [""]
    if unresolved:
        md += [f"## work/compare.jsonl のうち、当たらなかった行: {len(unresolved)}", ""] + [f"- {u}" for u in unresolved] + [""]
    (work / "check" / "compare.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    def brief(it: dict) -> dict:
        return {"key": it["_k"], "id": it["_id"], "layer": layer_of(it), "kind": kind_of(it), "method": it.get("method", ""), "path": it.get("path", ""),
                "evidence": where(it), "found_by": it.get("found_by", ""), "covered_by": [x["_k"] for x in it["_cover"]],
                "skip": skip.get(it["_k"], ""), "carry": keep.get(it["_k"], "")}

    (work / "check" / "compare.json").write_text(json.dumps({
        "old_run": old_run.name, "new_run": run.name, "same_input": same_input,
        "old_total": len(old), "new_total": len(new), "matched": len(pair), "matched_how": dict(hows), "pairs": pair,
        "old_only": [brief(it) for it in old_only], "new_only": [brief(it) for it in new_only], "carried": [it["_k"] for it in carry] if args.carry else [],
    }, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"previous={old_run.as_posix()} same_input={same_input} old={len(old)} new={len(new)} matched={len(pair)} "
          f"old_only={len(old_only)} (no_evidence_in_new={len(no_cover_old)}) new_only={len(new_only)} (no_evidence_in_old={len(no_cover_new)}) "
          f"skip={len(old_only) - len(carry)} undecided={len(undecided)} displaced={len(displaced)} unresolved_judgments={len(unresolved)}"
          + (f" carried={len(carry)}" if args.carry else ""))
    print(f"report={(work / 'check' / 'compare.md').as_posix()}")
    if displaced:
        print(f"WARNING: work/compare.jsonl に書いた対応が、自動で付いていた対応を {len(displaced)} 件外しました。compare.md の「人が書いた対応が外した、自動の対応」を見てください。")
    if args.carry and undecided:
        print(f"WARNING: 今回も同じ箇所を根拠にする項目があるのに、判断が書かれていない項目を {len(undecided)} 件持ち込みました。"
              "同じ対象の書き方違いなら別件として重なります。compare.md の「未判断」を見て、work/compare.jsonl に new / skip / carry を書いてください。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
