#!/usr/bin/env python3
"""final.findings.jsonl から最終成果物（JSON / CSV / 表 / 集計）を作る。解析はしない。

  - 同じ対象が残っていれば 1 件に統合する（consolidate.py と同じ照合）
  - 引用が別の行に 1 か所だけ見つかる場合は行番号を直す
  - 秘密情報らしき値を伏せる
  - ID (AS-0001…) を振り、targets.csv / targets.md / attack-surface.json / stats.json を書く
  - 出力フォルダの親に LATEST.txt（最新の実行フォルダ名）を書く

使い方:
  python build_output.py RUN
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
from _common import (  # noqa: E402
    KIND_GROUP, as_list, host_of, is_url_item, layer_of, load_jsonl, load_run, mask_obj, merge_rows, norm_file, norm_path, read_text, resolve,
    short_file, squash, utf8_stdout,
)
from check import find_quote, quote_in  # noqa: E402

PRIO_JA = {"high": "高", "medium": "中", "low": "低", "": "-"}
AUTH_JA = {"required": "あり", "none": "なし", "unknown": "不明（証跡なし）", "n/a": "該当なし"}
CONF_JA = {"high": "高", "medium": "中", "low": "低"}
REACH_JA = {"direct": "直接", "indirect": "保存・中継の後", "unknown": "不明"}
KIND_ORDER = ["http", "page", "static", "proxy", "websocket", "graphql", "grpc", "rpc", "event", "job", "file-input", "port", "cloud", "host",
              "cli", "ipc", "other", "input-channel", "parser"]
LAYER_ORDER = {"入口": 0, "受け口": 1, "解釈点": 2}
UNINTENDED = ("UNINTENDED_INTAKE", "SECOND_ORDER", "REACH_UNKNOWN", "PRE_AUTH")


def fix_lines(items: list[dict], base_dir: str) -> int:
    cache: dict[str, list[str] | None] = {}
    fixed = 0
    for it in items:
        for e in it["evidence"]:
            file = norm_file(e.get("file", ""))
            e["file"] = file
            quote = squash(e.get("quote", ""))
            if not file or not quote:
                continue
            if file not in cache:
                p = resolve(base_dir, file)
                try:
                    cache[file] = read_text(p).splitlines() if p.is_file() else None
                except OSError:
                    cache[file] = None
            lines = cache[file]
            if lines is None:
                continue
            line = e.get("line")
            if isinstance(line, int) and 1 <= line <= len(lines):
                lo, hi = max(0, line - 4), min(len(lines), line + 3)
                if quote_in(squash(" ".join(lines[lo:hi])), quote):
                    continue
            hits = find_quote(lines, quote)
            if len(hits) == 1:
                e["line"] = hits[0]
                fixed += 1
    return fixed


def sort_key(it: dict) -> tuple:
    """ソース → 層 → （URL で表せる入口はホスト・パス・メソッド順。同じパスの画面と API が並ぶ）→ 種別。"""
    kind = it["kind"]
    url = is_url_item(it)
    return (
        str(it.get("source", "")).lower(), LAYER_ORDER.get(layer_of(it), 9), 0 if url else 1,
        host_of(it) if url else "", norm_path(it.get("path", "")) if url else "",
        KIND_ORDER.index(kind) if kind in KIND_ORDER else len(KIND_ORDER) - 3, str(it.get("path", "")).lower(), it.get("method", ""),
    )


PARAM_ORDER = ["path", "query", "header", "cookie", "body", "form", "file"]


def params_text(it: dict, sep: str = "\n") -> str:
    """`path: id*` / `body: email*, password` の形。* は必須、? は必須かどうか不明、(型) は分かるときだけ。"""
    groups: dict[str, list[str]] = {}
    for p in it["params"]:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        req = p.get("required")
        mark = "*" if req is True else "" if req is False else "?"
        typ = f"({p['type']})" if p.get("type") else ""
        groups.setdefault(str(p.get("in", "") or "other"), []).append(f"{p['name']}{mark}{typ}")
    order = [k for k in PARAM_ORDER if k in groups] + [k for k in groups if k not in PARAM_ORDER]
    return sep.join(f"{k}: {', '.join(groups[k])}" for k in order)


def cell(s) -> str:
    return squash(s).replace("|", "\\|")


def joined(v, sep: str = " / ") -> str:
    return sep.join(squash(x) for x in as_list(v))


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    args = ap.parse_args()
    run = Path(args.run)
    inventory, _units = load_run(run)
    final = run / "work" / "final.findings.jsonl"
    if not final.exists():
        print(f"ERROR: {final.as_posix()} がありません。`consolidate.py RUN --final` で作ってから実行してください。")
        return 2
    rows, errors = load_jsonl(final)
    if errors:
        print(f"WARNING: 読めない行が {len(errors)} 件あります（check.py --verify で確認）: {errors[0]}")
    items = merge_rows(rows)
    fixed = fix_lines(items, inventory["base_dir"])
    items = [{k: v for k, v in it.items() if not k.startswith("_")} for it in items]
    items, masked = mask_obj(items)
    items.sort(key=sort_key)
    for i, it in enumerate(items, 1):
        it["id"] = f"AS-{i:04d}"
        it["layer"] = layer_of(it)
        it.setdefault("priority", "")
        it.setdefault("confidence", "medium")
        it.setdefault("auth", "unknown")

    def ev_text(it: dict, limit: int = 3) -> str:
        parts = [f"{short_file(e.get('file', ''), inventory)}:{e.get('line', '')}" for e in it["evidence"][:limit]]
        more = len(it["evidence"]) - limit
        return " ; ".join(parts) + (f" ほか{more}" if more > 0 else "")

    # ---- 集計
    def count(fn) -> dict:
        c: Counter = Counter()
        for it in items:
            for v in as_list(fn(it)):
                c[str(v) or "-"] += 1
        return dict(c.most_common())

    def passes(it: dict) -> str:
        fb = str(it.get("found_by", ""))
        p1, later = "pass1" in fb, any(p in fb for p in ("pass2", "pass3", "pass4"))
        if p1:
            return "パス1とパス2以降の両方" if later else "パス1のみ"
        if not later:
            return "その他"
        # パス 1 は暗黙の仕組みを挙げない決まりなので、取りこぼしと呼べるのは定義のあるものだけ
        return "パス2以降のみ（暗黙の仕組み。パス1の対象外）" if str(it.get("origin", "")).lower() == "implicit" else "パス2以降のみ（定義あり。パス1の取りこぼし）"

    stats = {
        "run": inventory.get("run", run.name),
        "input_root": inventory.get("input_root", ""),
        "sources": [{"name": s["name"], "files": s["files"],
                     "入口": sum(1 for it in items if it.get("source") == s["name"] and it["layer"] == "入口"),
                     "受け口": sum(1 for it in items if it.get("source") == s["name"] and it["layer"] == "受け口"),
                     "解釈点": sum(1 for it in items if it.get("source") == s["name"] and it["layer"] == "解釈点")} for s in inventory["sources"]],
        "total": len(items),
        "by_layer": count(lambda it: it["layer"]),
        "by_source": count(lambda it: it.get("source", "")),
        "by_kind": count(lambda it: it["kind"]),
        "by_priority": count(lambda it: it.get("priority", "")),
        "by_auth": count(lambda it: it.get("auth", "")),
        "by_confidence": count(lambda it: it.get("confidence", "")),
        "by_origin": count(lambda it: it.get("origin", "")),
        "by_flag": count(lambda it: it["flags"]),
        "by_tag": count(lambda it: it["tags"]),
        "by_pass": count(passes),
        "by_reach": count(lambda it: it.get("reach", "") if it["kind"] == "parser" else []),
        "http_like": sum(1 for it in items if KIND_GROUP.get(it["kind"], it["kind"]) == "http"),
        "unauthenticated_state_changing": sum(1 for it in items if it.get("auth") != "required" and it.get("method") in ("POST", "PUT", "PATCH", "DELETE")),
        "merged_from": len(rows), "line_numbers_fixed": fixed, "secrets_masked": masked,
    }
    (run / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=1), encoding="utf-8")
    (run / "attack-surface.json").write_text(json.dumps({"meta": stats, "items": items}, ensure_ascii=False, indent=1), encoding="utf-8")

    # ---- CSV（Excel で開けるよう BOM 付き）
    header = ["ID", "層", "優先度", "ソース", "種別", "メソッド", "パス / 識別子", "ホスト", "ソース内のパス", "概要", "認証", "認証の根拠", "パラメータ",
              "受け取るもの・解釈するもの", "掛かる範囲", "部品（バージョン）", "届く入口", "届き方", "届く解釈点",
              "フラグ", "タグ", "確度", "由来", "根拠（ファイル:行）", "備考", "優先度の理由", "発見元"]
    with open(run / "targets.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for it in items:
            w.writerow([
                it["id"], it["layer"], PRIO_JA.get(it.get("priority", ""), it.get("priority", "")), it.get("source", ""), it["kind"], it.get("method", ""),
                it.get("path", ""), " / ".join([h for h in [it.get("host", ""), *as_list(it.get("also_hosts"))] if h]), it.get("internal_path", ""),
                squash(it.get("summary", "")),
                AUTH_JA.get(it.get("auth", ""), it.get("auth", "")), squash(it.get("auth_evidence", "")), params_text(it),
                squash(it.get("parses", "")) or joined(it.get("consumes")), squash(it.get("scope", "")), squash(it.get("component", "")),
                joined(it.get("fed_by")), REACH_JA.get(it.get("reach", ""), it.get("reach", "") or ""), joined(it.get("reaches")),
                " ".join(it["flags"]), " ".join(it["tags"]), CONF_JA.get(it.get("confidence", ""), it.get("confidence", "")), it.get("origin", ""),
                ev_text(it, 5), squash(it.get("notes", "")), squash(it.get("priority_reason", "")), it.get("found_by", ""),
            ])

    # ---- Markdown の表
    def target(it: dict) -> str:
        host = f"{it['host']} " if it.get("host") else ""
        return cell(f"{host}{it.get('method', '')} {it.get('path', '')}".strip())

    lay = stats["by_layer"]
    md = ["# 診断対象一覧", "",
          f"全 {len(items)} 件（入口 {lay.get('入口', 0)} / 受け口 {lay.get('受け口', 0)} / 解釈点 {lay.get('解釈点', 0)}）。"
          "列の意味とフラグは `targets.csv` と同じ。詳細（根拠の引用・パラメータ）は `attack-surface.json`。", ""]
    high = [it for it in items if it.get("priority") == "high"]
    if high:
        md += [f"## 優先度: 高（{len(high)} 件）", "", "| ID | 層 | ソース | 対象 | 認証 | フラグ | 理由 |", "|---|---|---|---|---|---|---|"]
        md += [f"| {it['id']} | {it['layer']} | {cell(it.get('source'))} | `{target(it)}` | "
               f"{AUTH_JA.get(it.get('auth', ''), '')} | {' '.join(it['flags'])} | {cell(it.get('priority_reason') or it.get('summary'))} |" for it in high]
        md.append("")
    outside = [it for it in items if any(f in it["flags"] for f in UNINTENDED) or (it["layer"] != "入口" and "IMPLICIT" in it["flags"])]
    if outside:
        md += [f"## 開発者の意図の外にある受け口・解釈点（{len(outside)} 件）", "",
               "基盤が勝手に受け取っているもの、保存・中継の後で解釈されるもの、届く経路が未確定のもの、認証より前に動くもの。", "",
               "| ID | 層 | ソース | 識別子 | 概要 | 部品 | フラグ | 認証 |", "|---|---|---|---|---|---|---|---|"]
        md += [f"| {it['id']} | {it['layer']} | {cell(it.get('source'))} | `{cell(it.get('path', ''))}` | {cell(it.get('summary', ''))} | {cell(it.get('component', ''))} | "
               f"{' '.join(it['flags'])} | {AUTH_JA.get(it.get('auth', ''), '')} |" for it in outside]
        md.append("")
    intake = [it for it in items if it["kind"] == "input-channel"]
    if intake:
        md += [f"## 受け口（{len(intake)} 件）", "", "| ID | ソース | 識別子 | 掛かる範囲 | 受け取るもの | 部品 | フラグ | 根拠 |", "|---|---|---|---|---|---|---|---|"]
        md += [f"| {it['id']} | {cell(it.get('source'))} | `{cell(it.get('path', ''))}` | {cell(it.get('scope', ''))} | {cell(joined(it.get('consumes'), '、') or it.get('summary', ''))} | "
               f"{cell(it.get('component', ''))} | {' '.join(it['flags'])} | {cell(ev_text(it, 1))} |" for it in intake]
        md.append("")
    parsers = [it for it in items if it["kind"] == "parser"]
    if parsers:
        md += [f"## 解釈点と、届く入口（{len(parsers)} 件）", "",
               "| ID | ソース | 解釈点 | 何を解釈するか | 部品 | 届く入口 | 届き方 | 認証 | フラグ | 根拠 |", "|---|---|---|---|---|---|---|---|---|---|"]
        md += [f"| {it['id']} | {cell(it.get('source'))} | `{cell(it.get('path', ''))}` | {cell(it.get('parses') or it.get('summary', ''))} | {cell(it.get('component', ''))} | "
               f"{cell(joined(it.get('fed_by'), '<br>')) or '**未特定**'} | {REACH_JA.get(it.get('reach', ''), '-')} | {AUTH_JA.get(it.get('auth', ''), '')} | {' '.join(it['flags'])} | {cell(ev_text(it, 1))} |"
               for it in parsers]
        md.append("")
    md += ["# 入口（ソース別）", ""]
    for source in dict.fromkeys(it.get("source", "") for it in items):
        group = [it for it in items if it.get("source", "") == source and it["layer"] == "入口"]
        if not group:
            continue
        with_host = any(it.get("host") for it in group)
        head = "| ID | 優先 | 種別 | " + ("ホスト | " if with_host else "") + "メソッド | パス / 識別子 | パラメータ | 概要 | 認証 | フラグ | 確度 | 根拠 |"
        md += [f"## {source}（{len(group)} 件）", "", head, "|" + "---|" * (head.count("|") - 1)]
        for it in group:
            host = f"{cell('<br>'.join([h for h in [it.get('host', ''), *as_list(it.get('also_hosts'))] if h]))} | " if with_host else ""
            md.append(
                f"| {it['id']} | {PRIO_JA.get(it.get('priority', ''), '-')} | {it['kind']} | {host}{it.get('method', '')} | `{cell(it.get('path', ''))}` | {params_text(it, '<br>').replace('|', '¦')} | {cell(it.get('summary', ''))} | "
                f"{AUTH_JA.get(it.get('auth', ''), '')} | {' '.join(it['flags'])} | {CONF_JA.get(it.get('confidence', ''), '')} | {cell(ev_text(it, 2))} |"
            )
        md.append("")
    (run / "targets.md").write_text("\n".join(md), encoding="utf-8")
    try:
        (run.parent / "LATEST.txt").write_text(run.name + "\n", encoding="utf-8")
    except OSError:
        pass

    print(f"targets={len(items)} entries={lay.get('入口', 0)} intake={lay.get('受け口', 0)} parsers={lay.get('解釈点', 0)} "
          f"merged_from={len(rows)} line_fixed={fixed} secrets_masked={masked} high={len(high)}")
    print(f"out={run.as_posix()} (attack-surface.json targets.csv targets.md stats.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
