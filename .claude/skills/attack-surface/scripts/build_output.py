#!/usr/bin/env python3
"""final.findings.jsonl から最終成果物（JSON / CSV / 表 / 集計）を作る。解析はしない。

  - 同じ対象が残っていれば 1 件に統合する（consolidate.py と同じ照合）
  - 引用が別の行に 1 か所だけ見つかる場合は行番号を直す
  - 秘密情報らしき値を伏せる
  - ID (AS-0001…) を振り、attack-surface.xlsx（主たる成果物）/ targets.csv / targets.md / requests.http / attack-surface.json / stats.json を書く
  - 出力フォルダの親に LATEST.txt（最新の実行フォルダ名）を書く

使い方:
  python build_output.py RUN
"""
from __future__ import annotations

import argparse
import csv
import json
import re
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
from xlsx import Link, Workbook  # noqa: E402

LEGEND = [
    ("認証", "その項目に届く前に、利用者の認証・認可を実際に通るか。「なし」には、ガードが付いているが中身が何も確かめていないものを含む"),
    ("パラメータ", "種類ごとに 1 行。* は必須、? は必須かどうかがコードから分からなかったもの。名前が * の項目は、本文が丸ごと別の処理に渡っていることを表す"),
    ("由来", "その項目を何から見つけたか。コードの定義 / 設定 / 仕様書 / 呼ぶ側のコードにだけある / フレームワーク等が生やす（コードに定義なし）/ 文書 / 状況からの推定。"
             "「フレームワーク等が生やす」「推定」は、実在を確かめてから見る"),
    ("調査メモ", "調査の担当者が残した観察と、未検証の仮説。別シートに分けてある。判定を先に行い、後から突き合わせる使い方を想定"),
    ("根拠", "ファイルと行。引用の全文は attack-surface.json にある"),
    ("IMPLICIT", "コードに定義が無く、フレームワーク・ライブラリ・イメージが生やしている"),
    ("UNREFERENCED", "定義はあるが、入力内のどのクライアントからも呼ばれていない"),
    ("TESTS_ONLY", "テストコードからしか呼ばれていない"),
    ("UNDOCUMENTED", "API 仕様書・コレクションに載っていない"),
    ("SPEC_ONLY", "仕様・文書にはあるが、実装が入力内に無い"),
    ("SHADOW", "呼び出されているが、受け側の定義が入力内に無い（渡されていないリポジトリがある可能性）"),
    ("LEGACY_VERSION", "新しい版が別にある旧 API"),
    ("DEV_ONLY", "条件付きで有効（デバッグフラグ、環境変数、開発用設定）"),
    ("EXPOSED_INFRA", "インフラ定義上、外部に露出している"),
    ("PREFIX_UNRESOLVED", "公開パスの接頭辞を確定できていない"),
    ("UNINTENDED_INTAKE", "開発者のコードが読んでいないのに、基盤が受け取っている"),
    ("SECOND_ORDER", "受け取った場所とは別の場所・別の時点で解釈される"),
    ("REACH_UNKNOWN", "解釈処理はあるが、外部の値が届く経路を確定できていない"),
    ("CONFIG_GATED", "設定で有効にしたときだけ動く本番機能（既定では無効）"),
    ("PRE_AUTH", "認証・認可より前に動く"),
    ("AUTH_CONFLICT", "認証の判断が担当者の間で食い違った（要確認）"),
]

PRIO_JA = {"high": "高", "medium": "中", "low": "低", "": "-"}
AUTH_JA = {"required": "あり", "none": "なし", "unknown": "不明（証跡なし）", "n/a": "該当なし"}
CONF_JA = {"high": "高", "medium": "中", "low": "低"}
ORIGIN_JA = {"code": "コードの定義", "config": "設定", "spec": "仕様書", "client": "呼ぶ側にだけある", "implicit": "フレームワーク等が生やす",
             "doc": "文書", "inferred": "推定"}


def origin_ja(it: dict) -> str:
    o = str(it.get("origin", "") or "")
    return ORIGIN_JA.get(o, o)
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


_SAMPLE = {"string": "string", "str": "string", "int": 0, "integer": 0, "number": 0, "float": 0.0, "bool": False, "boolean": False,
           "array": [], "object": {}, "file": "(file)"}


def _sample(p: dict):
    t = str(p.get("type", "") or "").lower()
    if t.startswith("enum(") and t.endswith(")"):
        return t[5:-1].split("|")[0]
    return _SAMPLE.get(t, f"<{p.get('name', '')}>")


def _put(obj: dict, name: str, value) -> None:
    """`address.zip` `items[].sku` を入れ子にして置く。"""
    parts = [x for x in str(name).split(".") if x]
    cur = obj
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        is_list = part.endswith("[]")
        key = part[:-2] if is_list else part
        if last:
            cur[key] = [value] if is_list else value
        elif is_list:
            if not (isinstance(cur.get(key), list) and cur[key] and isinstance(cur[key][0], dict)):
                cur[key] = [{}]
            cur = cur[key][0]
        else:
            if not isinstance(cur.get(key), dict):
                cur[key] = {}
            cur = cur[key]


def request_template(it: dict) -> str:
    """入口 1 件ぶんの、送信の出発点になるリクエスト（REST Client 形式）。値は仮で、コードから読めた項目名と場所だけを反映する。"""
    ps_all = [p for p in it["params"] if isinstance(p, dict) and p.get("name")]
    # 名前が説明文になっているもの（「設定で指定された名前のヘッダ」など）は、リクエストの行にせずコメントにする
    plain = lambda p: bool(re.fullmatch(r"[A-Za-z0-9_.\-\[\]*]+", str(p["name"])))  # noqa: E731
    ps = [p for p in ps_all if plain(p)]
    described = [p for p in ps_all if not plain(p)]
    by = lambda where: [p for p in ps if p.get("in") == where]  # noqa: E731
    method = str(it.get("method", "") or "GET").upper()
    method = "GET" if method in ("ANY", "") else method
    url = (f"https://{it['host']}" if it.get("host") else "{{base}}") + str(it.get("path", ""))
    q = [p for p in by("query") if p["name"] != "*"]
    if q:
        url += "?" + "&".join(f"{p['name']}={{{{{p['name']}}}}}" for p in q)
    lines = [f"# {p.get('in', '')}: {squash(p['name'])[:120]}" for p in described] + [f"{method} {url}"]
    lines += [f"{p['name']}: {{{{{p['name']}}}}}" for p in by("header")]
    if by("cookie"):
        lines.append("Cookie: " + "; ".join(f"{p['name']}={{{{{p['name']}}}}}" for p in by("cookie")))
    body, form, files = by("body"), by("form"), by("file")
    if files:
        lines += ["Content-Type: multipart/form-data; boundary=----x", ""]
        for p in files:
            lines += ["------x", f'Content-Disposition: form-data; name="{p["name"]}"; filename="sample.bin"', "", "(ファイルの中身)"]
        for p in [*form, *body]:
            if p["name"] != "*":
                lines += ["------x", f'Content-Disposition: form-data; name="{p["name"]}"', "", str(_sample(p))]
        lines.append("------x--")
    elif form:
        lines += ["Content-Type: application/x-www-form-urlencoded", "", "&".join(f"{p['name']}={_sample(p)}" for p in form if p["name"] != "*")]
    elif body:
        obj: dict = {}
        for p in body:
            if p["name"] != "*":
                _put(obj, p["name"], _sample(p))
        lines += ["Content-Type: application/json", "", json.dumps(obj, ensure_ascii=False, indent=2)]
    return "\n".join(lines)


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
            return "以前の実行からの持ち込み" if "carryover:" in fb else "その他"
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
    # 観察した事実だけを載せる。判断（優先度・確度）、工程の記録（発見元）、仮説を含む備考は attack-surface.json にだけ残す
    header = ["ID", "層", "ソース", "種別", "メソッド", "パス / 識別子", "ホスト", "ソース内のパス", "概要", "認証", "認証の根拠", "パラメータ",
              "受け取るもの・解釈するもの", "掛かる範囲", "部品（バージョン）", "届く入口", "届き方", "届く解釈点",
              "フラグ", "タグ", "由来", "根拠（ファイル:行）", "呼び出す API（画面）"]
    with open(run / "targets.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for it in items:
            w.writerow([
                it["id"], it["layer"], it.get("source", ""), it["kind"], it.get("method", ""),
                it.get("path", ""), " / ".join([h for h in [it.get("host", ""), *as_list(it.get("also_hosts"))] if h]), it.get("internal_path", ""),
                squash(it.get("summary", "")),
                AUTH_JA.get(it.get("auth", ""), it.get("auth", "")), squash(it.get("auth_evidence", "")), params_text(it),
                squash(it.get("parses", "")) or joined(it.get("consumes")), squash(it.get("scope", "")), squash(it.get("component", "")),
                joined(it.get("fed_by")), REACH_JA.get(it.get("reach", ""), it.get("reach", "") or ""), joined(it.get("reaches")),
                " ".join(it["flags"]), " ".join(it["tags"]), origin_ja(it), ev_text(it, 5), joined(it.get("calls")),
            ])

    # ---- Markdown の表
    def target(it: dict) -> str:
        host = f"{it['host']} " if it.get("host") else ""
        return cell(f"{host}{it.get('method', '')} {it.get('path', '')}".strip())

    lay = stats["by_layer"]
    md = ["# 診断対象一覧", "",
          f"全 {len(items)} 件（入口 {lay.get('入口', 0)} / 受け口 {lay.get('受け口', 0)} / 解釈点 {lay.get('解釈点', 0)}）。"
          "列の意味とフラグは `targets.csv` と同じ。詳細（根拠の引用・パラメータ）は `attack-surface.json`。", ""]
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
        head = "| ID | 種別 | " + ("ホスト | " if with_host else "") + "メソッド | パス / 識別子 | パラメータ | 概要 | 認証 | フラグ | 由来 | 根拠 |"
        md += [f"## {source}（{len(group)} 件）", "", head, "|" + "---|" * (head.count("|") - 1)]
        for it in group:
            host = f"{cell('<br>'.join([h for h in [it.get('host', ''), *as_list(it.get('also_hosts'))] if h]))} | " if with_host else ""
            md.append(
                f"| {it['id']} | {it['kind']} | {host}{it.get('method', '')} | `{cell(it.get('path', ''))}` | {params_text(it, '<br>').replace('|', '¦')} | {cell(it.get('summary', ''))} | "
                f"{AUTH_JA.get(it.get('auth', ''), '')} | {' '.join(it['flags'])} | {origin_ja(it)} | {cell(ev_text(it, 2))} |"
            )
        md.append("")
    # ---- サイトマップ: 画面と、そこから呼ばれる API（calls を一覧の ID に結ぶ）
    by_call: dict[tuple, str] = {}
    for it in items:
        if is_url_item(it) and it["kind"] != "page":
            for p in (it.get("path"), it.get("internal_path")):
                if p:
                    by_call[(str(it.get("method", "")).upper(), norm_path(str(p)))] = it["id"]

    def resolve_calls(it: dict) -> list[str]:
        out = []
        for c in as_list(it.get("calls")):
            m, _, p = str(c).strip().partition(" ")
            m, p = (m.upper(), p) if p else ("", m)
            hit = by_call.get((m, norm_path(p))) or next((v for (mm, pp), v in by_call.items() if pp == norm_path(p) and (not m or mm in ("ANY", ""))), None) \
                or next((v for (mm, pp), v in by_call.items() if mm == m and pp.endswith(norm_path(p)) and len(norm_path(p)) > 1), None)
            out.append(f"{hit} ({c})" if hit else f"未対応 ({c})")
        return out

    # 画面と、画面を兼ねる URL の入口（同じ URL が HTML と JSON の両方を返すものは http と書き、calls を持つ）
    pages = [it for it in items if it["kind"] == "page" or (is_url_item(it) and as_list(it.get("calls")))]
    if pages:
        md += ["# サイトマップ（画面と、呼び出す API）", "",
               "画面のコードから辿れた呼び出しを、一覧の ID に結んだもの。「未対応」は、呼び出し先が一覧に見つからなかったもの（受ける側が入力に無い、または書き方の違い）。", "",
               "| ID | ソース | パス | 概要 | 認証 | 呼び出す API |", "|---|---|---|---|---|---|"]
        for it in pages:
            md.append(f"| {it['id']} | {it.get('source', '')} | `{cell(it.get('path', ''))}` | {cell(it.get('summary', ''))} | {AUTH_JA.get(it.get('auth', ''), '')} | "
                      f"{'<br>'.join(cell(c) for c in resolve_calls(it))} |")
        md.append("")
    (run / "targets.md").write_text("\n".join(md), encoding="utf-8")

    # ---- リクエストのひな形（HTTP で送れる入口だけ）
    sendable = [it for it in items if is_url_item(it) and it["kind"] in ("http", "page", "static", "proxy", "api", "rest")]
    http_lines = ["# 診断の出発点にするリクエストのひな形（機械生成）。",
                  "# 項目名と場所は、コードから読めたものだけを反映している。値は仮で、実際に通る値は実通信で確かめること。",
                  "# {{base}} は対象の URL、{{名前}} は埋める値。パスの {id} も置き換える。VS Code の REST Client などでそのまま開ける。", ""]
    for it in sendable:
        flags = f" [{' '.join(it['flags'])}]" if it["flags"] else ""
        http_lines += [f"### {it['id']} {it.get('source', '')} — {squash(it.get('summary', ''))[:80]} / 認証: {AUTH_JA.get(it.get('auth', ''), '')}{flags}",
                       request_template(it), ""]
    (run / "requests.http").write_text("\n".join(http_lines), encoding="utf-8")
    # ---- Excel ブック（主たる成果物）
    book = Workbook()
    entries = [it for it in items if it["layer"] == "入口"]
    intake_items = [it for it in items if it["layer"] == "受け口"]
    parser_items = [it for it in items if it["layer"] == "解釈点"]
    req_row = {it["id"]: n for n, it in enumerate(sendable, 2)}      # 「リクエスト」シートでの行
    entry_row = {it["id"]: n for n, it in enumerate(entries, 2)}     # 「対象一覧」シートでの行

    def hosts(it: dict) -> str:
        return "\n".join(h for h in [it.get("host", ""), *as_list(it.get("also_hosts"))] if h)

    def styles(n: int, i: int, link_cols: tuple = ()) -> list[str]:
        base = "alt" if i % 2 else "text"
        return [("link_alt" if base == "alt" else "link") if c in link_cols else base for c in range(n)]

    sh = book.sheet("概要", widths=[26, 14, 14, 14, 14, 60], freeze=False, autofilter=False)
    sh.row(["アタックサーフェス調査 対象一覧"], "title")
    sh.row([f"実行: {stats['run']}　／　入力: {stats['input_root']}"], "note")
    sh.row([""], "note")
    sh.row(["ソース", "入口", "受け口", "解釈点", "計"], "head")
    for i, s in enumerate(stats["sources"]):
        sh.row([s["name"], s["入口"], s["受け口"], s["解釈点"], s["入口"] + s["受け口"] + s["解釈点"]], "alt" if i % 2 else "text")
    sh.row(["計", lay.get("入口", 0), lay.get("受け口", 0), lay.get("解釈点", 0), len(items)], "head")
    sh.row([""], "note")
    sh.row(["シート", "内容"], "head")
    for name, desc in (("対象一覧", "入口。外部から入力が届く経路。1 行 1 対象。ID からリクエストのひな形へ飛べる"),
                       ("受け口", "開発者のコードが動く前に、基盤（フレームワーク・ミドルウェア・プロキシ）が受け取っているもの"),
                       ("解釈点", "受け取った値を解釈する処理と、値が届く入口"),
                       ("サイトマップ", "画面と、その画面から呼ばれる API（画面がある場合のみ）"),
                       ("リクエスト", "HTTP で送れる入口ごとのリクエストのひな形。項目名と場所はコードから読めたもの、値は仮"),
                       ("調査メモ", "調査の担当者が残した観察と未検証の仮説（判定の後で突き合わせる用）"),
                       ("凡例", "フラグ・記号・列の意味")):
        sh.row([name, desc], "text")
    sh.row([""], "note")
    sh.row(["静的にコードを読んだ結果です。脆弱性の有無は判定していません。一覧には観察した事実だけを載せ、優先度などの判断は付けていません。"], "note")
    sh.row(["確定できなかった点は coverage.md、解説は REPORT.md にあります。調査メモ（観察と未検証の仮説）は、判定の後で突き合わせる用です。"], "note")

    # 観察した事実だけを載せる（判断の列は置かない。調査メモは別シート）
    head = ["ID", "ソース", "種別", "ホスト", "Method", "パス / 識別子", "パラメータ", "概要", "認証", "認証の根拠", "フラグ", "届く解釈点", "由来", "根拠（ファイル:行）"]
    sh = book.sheet("対象一覧", widths=[10, 14, 9, 22, 9, 44, 34, 44, 12, 34, 22, 30, 16, 38])
    sh.row(head, "head")
    for i, it in enumerate(entries):
        first = Link(it["id"], "リクエスト", req_row[it["id"]]) if it["id"] in req_row else it["id"]
        sh.row([first, it.get("source", ""), it["kind"], hosts(it), it.get("method", ""), it.get("path", ""), params_text(it), squash(it.get("summary", "")),
                AUTH_JA.get(it.get("auth", ""), it.get("auth", "")), squash(it.get("auth_evidence", "")), "\n".join(it["flags"]), "\n".join(map(str, as_list(it.get("reaches")))),
                origin_ja(it), ev_text(it, 3).replace(" ; ", "\n")],
               styles(len(head), i))

    head = ["ID", "ソース", "識別子", "掛かる範囲", "受け取るもの", "部品（バージョン）", "概要", "認証", "フラグ", "由来", "根拠（ファイル:行）"]
    sh = book.sheet("受け口", widths=[10, 14, 40, 20, 40, 28, 48, 12, 22, 16, 38])
    sh.row(head, "head")
    for i, it in enumerate(intake_items):
        sh.row([it["id"], it.get("source", ""), it.get("path", ""), squash(it.get("scope", "")), "\n".join(map(str, as_list(it.get("consumes")))),
                squash(it.get("component", "")), squash(it.get("summary", "")), AUTH_JA.get(it.get("auth", ""), it.get("auth", "")), "\n".join(it["flags"]),
                origin_ja(it), ev_text(it, 3).replace(" ; ", "\n")], styles(len(head), i))

    head = ["ID", "ソース", "解釈点", "何を解釈するか", "部品（バージョン）", "届く入口", "届き方", "概要", "認証", "フラグ", "由来", "根拠（ファイル:行）"]
    sh = book.sheet("解釈点", widths=[10, 14, 40, 36, 26, 36, 14, 46, 12, 22, 16, 38])
    sh.row(head, "head")
    for i, it in enumerate(parser_items):
        sh.row([it["id"], it.get("source", ""), it.get("path", ""), squash(it.get("parses", "")), squash(it.get("component", "")),
                "\n".join(map(str, as_list(it.get("fed_by")))) or "未特定", REACH_JA.get(it.get("reach", ""), it.get("reach", "") or "-"), squash(it.get("summary", "")),
                AUTH_JA.get(it.get("auth", ""), it.get("auth", "")), "\n".join(it["flags"]), origin_ja(it),
                ev_text(it, 3).replace(" ; ", "\n")], styles(len(head), i))

    if pages:
        head = ["ID", "ソース", "ホスト", "パス", "概要", "認証", "呼び出す API"]
        sh = book.sheet("サイトマップ", widths=[10, 14, 22, 40, 48, 12, 60])
        sh.row(head, "head")
        for i, it in enumerate(pages):
            first = Link(it["id"], "対象一覧", entry_row[it["id"]]) if it["id"] in entry_row else it["id"]
            sh.row([first, it.get("source", ""), hosts(it), it.get("path", ""), squash(it.get("summary", "")), AUTH_JA.get(it.get("auth", ""), ""),
                    "\n".join(resolve_calls(it))], styles(len(head), i))

    sh = book.sheet("リクエスト", widths=[10, 9, 46, 12, 110])
    sh.row(["ID", "Method", "パス", "認証", "リクエストのひな形（値は仮。{{base}} と {{名前}}、パスの {id} を置き換える）"], "head")
    for it in sendable:
        first = Link(it["id"], "対象一覧", entry_row[it["id"]]) if it["id"] in entry_row else it["id"]
        sh.row([first, it.get("method", ""), it.get("path", ""), AUTH_JA.get(it.get("auth", ""), ""), request_template(it)], ["link", "text", "text", "text", "mono"])

    # 調査メモ: 観察と未検証の仮説。判定に先入観を与えないよう、一覧とは分けて置く
    noted = [it for it in items if squash(it.get("notes", ""))]
    if noted:
        sh = book.sheet("調査メモ", widths=[10, 8, 14, 44, 110])
        sh.row(["ID", "層", "ソース", "パス / 識別子", "調査メモ（観察と未検証の仮説。判定の後で突き合わせる）"], "head")
        for i, it in enumerate(noted):
            sh.row([it["id"], it["layer"], it.get("source", ""), it.get("path", ""), squash(it.get("notes", ""))], styles(5, i))

    sh = book.sheet("凡例", widths=[24, 100], autofilter=False)
    sh.row(["項目", "意味"], "head")
    for k, v in LEGEND:
        sh.row([k, v], "text")
    book.save(run / "attack-surface.xlsx")

    try:
        (run.parent / "LATEST.txt").write_text(run.name + "\n", encoding="utf-8")
    except OSError:
        pass

    print(f"targets={len(items)} entries={lay.get('入口', 0)} intake={lay.get('受け口', 0)} parsers={lay.get('解釈点', 0)} "
          f"merged_from={len(rows)} line_fixed={fixed} secrets_masked={masked}")
    print(f"out={run.as_posix()} (attack-surface.xlsx attack-surface.json targets.csv targets.md requests.http stats.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
