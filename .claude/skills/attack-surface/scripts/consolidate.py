#!/usr/bin/env python3
"""パス 1・パス 2 の検出項目を 1 つにまとめる。解析はしない。

  1. work/pass*/ の全 findings を読む
  2. work/aliases.jsonl（任意）: 書き方違いの寄せ直しと、誤りの取り下げ
  3. work/prefixes.jsonl（任意）: ソース内のパスを、外から見える公開パスに直す
  4. 同じ対象を 1 件に統合する（URL で表せる入口はメソッドとパス、それ以外は識別子か根拠の位置で照合）
  5. origin が implicit の項目に IMPLICIT を付け、各項目に短い鍵 (key) を振る
  6. work/overrides.jsonl（任意）: フラグ・優先度・認証などの上書きと追記
  7. work/merged.findings.jsonl に書く（--final を付けると work/final.findings.jsonl にも書く）
  8. work/check/merge.md に、何をどうまとめたかを書く（優先度を付ける場合は、未設定の項目のひな形を work/check/overrides.todo.jsonl に出す）

補助ファイルの書式（どれも 1 行 1 件の JSON。無ければ何もしない）:

  aliases.jsonl … 統合の前に、行ごとに適用する。最初に当たった 1 行だけが効く
    {"source": "portal-web", "from": {"path": "/#server-action:deleteAccount"}, "to": {"kind": "rpc", "method": "POST", "path": "server-action:deleteAccount"}}
    {"source": "shop-api", "from": {"method": "GET", "path_regex": "^/old-debug$"}, "drop": "コメントアウトされた定義だった"}
    {"source": "shop-api", "from": {"path": "upload:multer"}, "to": {"anchor": {"file": "…/app.js", "line": 12, "quote": "const upload = multer({"}}}
      to.anchor … 根拠の 1 件目だけを付け替える（受け口・解釈点は根拠 1 件目の位置で照合されるので、位置を揃えたいときに使う）

  prefixes.jsonl … URL で表せる入口に適用する。host も付けられる
    {"source": "shop-api", "prefix": "/shop", "host": "shop.example.co.jp", "evidence": {"file": "…/nginx.conf", "line": 16, "quote": "location /shop/ {"}}
      under … ソース内のパスがこの接頭辞で始まるものだけに適用する（省略時は全部）

  overrides.jsonl … 統合の後に、上の行から順に適用する。同じ項目に複数の行が当たれば、後の行が勝つ
    {"match": {"source": "shop-api", "path_regex": "^/shop/api/v1/admin/"}, "set": {"priority": "high", "priority_reason": "管理系"}, "add_flags": ["UNREFERENCED"]}
    {"match": {"key": "3f9a1c2e"}, "set": {"auth": "none"}, "remove_flags": ["AUTH_CONFLICT"]}
      match … 書いた条件をすべて満たす項目が対象。値をリストにすると「いずれか」。{} は全項目
              source kind method layer(入口/受け口/解釈点) flag tag path path_regex key found_by(部分一致) host origin auth confidence priority reach file(根拠のパスの部分一致)
      操作  … set（フィールドの上書き。空文字の値は無視） add_flags remove_flags add_tags append_notes
              replace_fed_by（{"古い書き方": "新しい書き方"}。fed_by の該当する要素だけを置き換える）

使い方:
  python consolidate.py RUN            # 統合の下書きと報告（何度でも実行できる）
  python consolidate.py RUN --final    # final.findings.jsonl として確定
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
    MATCH_KEYS, anchor, apply_aliases, apply_prefixes, as_list, category_of, first_evidence, host_of, is_manifest, is_url_item, kind_of, layer_of,
    load_jsonl, load_run, matches, merge_rows, norm_path, same_spot, stable_key, utf8_stdout,
)


def label(it: dict) -> str:
    return f"{kind_of(it)} {it.get('method', '') or ''} {it.get('path', '')}".replace("  ", " ").strip()


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    ap.add_argument("--final", action="store_true")
    args = ap.parse_args()
    run = Path(args.run)
    load_run(run)
    work = run / "work"
    (work / "check").mkdir(exist_ok=True)

    rows: list[dict] = []
    per_file: dict[str, int] = {}
    errors: list[str] = []
    for d in sorted(p for p in work.iterdir() if p.is_dir() and re.fullmatch(r"pass\d+", p.name)):
        for fpath in sorted(d.rglob("*.findings.jsonl")):
            got, errs = load_jsonl(fpath)
            per_file[f"{d.name}/{fpath.name}"] = len(got)
            rows += got
            errors += [f"{d.name}/{e}" for e in errs]

    def load_optional(name: str) -> list[dict]:
        p = work / name
        if not p.exists():
            return []
        got, errs = load_jsonl(p)
        errors.extend(f"{name}: {e}" for e in errs)
        return got

    aliases, prefixes, overrides = load_optional("aliases.jsonl"), load_optional("prefixes.jsonl"), load_optional("overrides.jsonl")

    # ---- 2〜4. 寄せ直し・公開パス・統合
    kept, dropped, alias_hits = apply_aliases(rows, aliases)
    prefix_hits = apply_prefixes(kept, prefixes)
    items = merge_rows(kept)

    # ---- 5. 機械的に決まる印と鍵
    used: Counter = Counter()
    for it in items:
        if str(it.get("origin", "")).lower() == "implicit" and "IMPLICIT" not in it["flags"]:
            it["flags"] = sorted([*it["flags"], "IMPLICIT"])
        key = stable_key(it)
        used[key] += 1
        it["key"] = key if used[key] == 1 else f"{key}-{used[key]}"

    # 上書きを当てる前の姿を残す（overrides を作り直すときは、こちらを元にする）
    (work / "merged.raw.findings.jsonl").write_text(
        "\n".join(json.dumps({k: v for k, v in it.items() if not k.startswith("_")}, ensure_ascii=False) for it in items) + "\n", encoding="utf-8")

    # ---- 6. 上書きと追記
    override_hits: Counter = Counter()
    unknown_conds: list[str] = []
    for i, ov in enumerate(overrides):
        cond = ov.get("match") or {}
        bad = [k for k in cond if not k.startswith("_") and k not in MATCH_KEYS]
        if bad:
            unknown_conds.append(f"overrides {i + 1} 行目: 知らない条件 {', '.join(bad)}（使える条件: {' '.join(MATCH_KEYS)}）")
        for it in items:
            if not matches(it, cond):
                continue
            override_hits[i] += 1
            for k, v in (ov.get("set") or {}).items():
                if v != "" and k != "key":
                    it[k] = v
            flags = [f for f in as_list(it.get("flags")) if f not in as_list(ov.get("remove_flags"))]
            it["flags"] = sorted(dict.fromkeys([*flags, *map(str, as_list(ov.get("add_flags")))]))
            it["tags"] = sorted(dict.fromkeys([*map(str, as_list(it.get("tags"))), *map(str, as_list(ov.get("add_tags")))]))
            if isinstance(ov.get("replace_fed_by"), dict):
                it["fed_by"] = list(dict.fromkeys(str(ov["replace_fed_by"].get(str(x), x)) for x in as_list(it.get("fed_by"))))
            if ov.get("append_notes") and str(ov["append_notes"]) not in str(it.get("notes", "")):
                it["notes"] = (str(it.get("notes", "")) + " / " + str(ov["append_notes"])).strip(" /")

    # ---- 解釈点の fed_by を入口に結び、入口の reaches を逆引きで埋める
    entry_by_url: dict[tuple, dict] = {}
    entry_by_name: dict[str, dict] = {}
    for it in items:
        if layer_of(it) != "入口":
            continue
        for p in (it.get("path"), it.get("internal_path")):
            if not p:
                continue
            if is_url_item(it):
                entry_by_url[(str(it.get("method", "") or "").upper(), norm_path(str(p)))] = it
            entry_by_name[re.sub(r"\s+", " ", str(p)).strip().lower()] = it
    fed_unmatched: Counter = Counter()
    fed_linked = 0
    for it in items:
        if kind_of(it) != "parser":
            continue
        for fb in map(str, as_list(it.get("fed_by"))):
            s = re.sub(r"\s+", " ", fb).strip()
            if not s or s in ("不明", "unknown", "全ルート") or s.startswith("全"):
                continue
            m, _, p = s.partition(" ")
            hit = entry_by_name.get(s.lower())
            if hit is None and p.startswith("/"):
                hit = entry_by_url.get((m.upper(), norm_path(p))) or entry_by_url.get(("ANY", norm_path(p)))
            if hit is None and s.startswith("/"):
                hit = next((v for (mm, pp), v in entry_by_url.items() if pp == norm_path(s)), None)
            if hit is None and p:
                hit = entry_by_name.get(p.lower())
            if hit is None:
                fed_unmatched[s] += 1
                continue
            fed_linked += 1
            it["_linked"] = True
            if str(it.get("path", "")) not in map(str, as_list(hit.get("reaches"))):
                hit["reaches"] = [*as_list(hit.get("reaches")), it.get("path", "")]
    # 入口に結べた解釈点からは「経路が未確定」の印を外す（別の担当者が経路を書いていれば、未確定ではない）
    reach_cleared = 0
    for it in items:
        if it.get("_linked") and "REACH_UNKNOWN" in as_list(it.get("flags")):
            it["flags"] = [x for x in it["flags"] if x != "REACH_UNKNOWN"]
            it["fed_by"] = [x for x in as_list(it.get("fed_by")) if str(x) not in ("不明", "unknown")]
            if str(it.get("reach", "")) in ("", "unknown"):
                it["reach"] = "indirect" if "SECOND_ORDER" in it["flags"] else "direct"
            reach_cleared += 1

    # ---- 7. 書き出し
    def clean(it: dict) -> dict:
        out = {k: v for k, v in it.items() if not k.startswith("_")}
        if not out.get("also_hosts"):
            out.pop("also_hosts", None)
        return out

    text = "\n".join(json.dumps(clean(it), ensure_ascii=False) for it in items) + "\n"
    (work / "merged.findings.jsonl").write_text(text, encoding="utf-8")
    if args.final:
        (work / "final.findings.jsonl").write_text(text, encoding="utf-8")

    # 優先度付けは任意。1 件でも優先度が付いているとき（付ける運用のとき）だけ、未設定の項目のひな形を出す
    prioritizing = any(it.get("priority") for it in items)
    todo = [it for it in items if not it.get("priority")] if prioritizing else []
    todo_path = work / "check" / "overrides.todo.jsonl"
    if todo:
        todo_path.write_text("\n".join(json.dumps(
            {"match": {"key": it["key"]}, "set": {"priority": "", "priority_reason": ""},
             "_what": f"{it.get('source', '')} | {label(it)} | {str(it.get('summary', ''))[:60]} | 認証 {it.get('auth', '')} | {' '.join(it['flags'])}"},
            ensure_ascii=False) for it in todo) + "\n", encoding="utf-8")
    elif todo_path.exists():
        todo_path.unlink()

    # ---- 8. 報告
    layers = Counter(layer_of(it) for it in items)
    md = ["# 統合結果", "",
          f"- 読んだ行: {len(rows)}（{len(per_file)} ファイル）→ 取り下げ {len(dropped)} → 統合後 **{len(items)} 件**"
          f"（入口 {layers['入口']} / 受け口 {layers['受け口']} / 解釈点 {layers['解釈点']}）",
          f"- 書き出し先: `work/merged.findings.jsonl`" + ("、`work/final.findings.jsonl`" if args.final else "（確定するには --final）"),
          f"- 補助ファイル: aliases {len(aliases)} 行 / prefixes {len(prefixes)} 行 / overrides {len(overrides)} 行", ""]
    if errors:
        md += [f"## 読めなかった行: {len(errors)} 件", ""] + [f"- {e}" for e in errors[:40]] + [""]

    unused = [("aliases", i, a) for i, a in enumerate(aliases) if not alias_hits[i]]
    unused += [("prefixes", i, p) for i, p in enumerate(prefixes) if not prefix_hits[i]]
    unused += [("overrides", i, o) for i, o in enumerate(overrides) if not override_hits[i]]
    if unused or unknown_conds:
        md += [f"## どの項目にも当たらなかった補助ファイルの行: {len(unused)}", "",
               "条件の書き間違い（パスの表記、ソース名）を疑う。`key` で指した項目は、識別子や根拠の位置を変えると鍵も変わる。", ""]
        md += [f"- {x}" for x in unknown_conds]
        md += [f"- {name} {i + 1} 行目: `{json.dumps(x, ensure_ascii=False)[:200]}`" for name, i, x in unused[:40]] + [""]

    no_auth = [it for it in items if not it.get("auth")]
    md += ["## 残っている作業", "",
           (f"- 優先度が未設定: {len(todo)} 件" if prioritizing else "- 優先度: 付けていない（任意。成果物には出ない）") + ("（ひな形: `work/check/overrides.todo.jsonl`。`priority` と `priority_reason` を埋めて `work/overrides.jsonl` に足す。"
                                          "まとまった範囲は `path_regex` や `flag` の条件 1 行で書くほうが早い）" if todo else ""),
           f"- 認証欄が空: {len(no_auth)} 件",
           f"- 認証の判断が食い違ったもの (AUTH_CONFLICT): {sum(1 for it in items if 'AUTH_CONFLICT' in as_list(it.get('flags')))} 件（根拠を読み直して `overrides.jsonl` で確定し、フラグを外す）",
           f"- 備考を全部は残さなかった項目: {sum(1 for it in items if it.get('_notes_dropped'))} 件（言い換えの重複を避けるため 1 項目 3 件・600 字まで。元の記録は `work/pass*/` にある）", ""]

    multi = [it for it in items if len(it.get("_spellings", [])) > 1]
    if multi:
        md += [f"## 書き方が複数あり、自動で 1 件にまとめたもの: {len(multi)} 件", "",
               "別の対象をまとめてしまっていないかを確かめる。誤っていたら、片方の書き方を `aliases.jsonl` で別の識別子に直す"
               "（受け口・解釈点なら、識別子の `種類:` を変えるか `to.anchor` で根拠の位置を分ける）。", "",
               "| ソース | 採用した書き方 | ほかの書き方 | 根拠 |", "|---|---|---|---|"]
        for it in multi[:150]:
            f, ln, _q = first_evidence(it)
            md.append(f"| {it.get('source', '')} | `{it['_spellings'][0]}` | {'<br>'.join('`' + s + '`' for s in it['_spellings'][1:6])} | {f.rsplit('/', 1)[-1]}:{ln} |")
        if len(multi) > 150:
            md.append(f"| … | ほか {len(multi) - 150} 件 | | |")
        md.append("")

    # 同じ箇所を根拠にしているのに別件のまま残ったもの
    by_file: dict[tuple, list[dict]] = defaultdict(list)
    for it in items:
        f, ln, _q = first_evidence(it)
        if f and ln:
            by_file[(str(it.get("source", "")).lower(), f)].append(it)
    suspects: list[tuple[str, str, str, list[dict]]] = []
    seen_pairs: set = set()
    for (src, f), grp in by_file.items():
        for i, a in enumerate(grp):
            for b in grp[i + 1:]:
                _fa, la, qa = first_evidence(a)
                _fb, lb, qb = first_evidence(b)
                if not same_spot(la, qa, lb, qb):
                    continue
                aa, ab = anchor(a) is not None, anchor(b) is not None
                why = ""
                if aa and ab:
                    # 依存の宣言行は、1 行が別々の仕組みの根拠になるのが普通。種類が同じときだけ疑う
                    same_cat = bool(category_of(a)) and category_of(a) == category_of(b)
                    if kind_of(a) != kind_of(b):
                        if same_cat or not is_manifest(f):
                            why = "同じ箇所を受け口と解釈点の両方に書いている（層の判断が割れた）"
                    elif not same_cat and not is_manifest(f):
                        why = "同じ箇所で識別子の種類が違う（別の仕組みならこのままでよい）"
                elif not aa and not ab and str(a.get("method", "") or "") == str(b.get("method", "") or ""):
                    pa, pb = norm_path(a.get("path", "")), norm_path(b.get("path", ""))
                    if is_url_item(a) != is_url_item(b):
                        why = "同じものを別の種別で書いている可能性"
                    elif pa != pb and len(pa) > 1 and len(pb) > 1 and (pa.endswith(pb) or pb.endswith(pa)):
                        why = "片方が接頭辞つき・片方が接頭辞なし"
                    elif pa == pb and host_of(a) != host_of(b):
                        continue  # ホスト違いは別の対象（根拠が同じ箇所なら統合済み）
                if why and (id(a), id(b)) not in seen_pairs:
                    seen_pairs.add((id(a), id(b)))
                    suspects.append((src, f"{f.rsplit('/', 1)[-1]}:{la}", why, [a, b]))
    if suspects:
        md += [f"## 同じ箇所を根拠にしているのに別件として残ったもの: {len(suspects)} 組", "",
               "同じ対象なら `aliases.jsonl` で片方をもう片方の書き方（kind・path）に寄せる。接頭辞の違いなら `prefixes.jsonl` を見直す。別の対象ならそのままでよい。", "",
               "| ソース | 根拠 | 疑い | 別件として残った書き方 |", "|---|---|---|---|"]
        for src, where, why, grp in suspects[:120]:
            md.append(f"| {src} | {where} | {why} | {'<br>'.join('`' + label(g) + '`' for g in grp)} |")
        if len(suspects) > 120:
            md.append(f"| … | | | ほか {len(suspects) - 120} 組 |")
        md.append("")

    # 同じパスに「全メソッド (ANY)」と個別メソッドの両方がある入口
    by_path: dict[tuple, list[dict]] = defaultdict(list)
    for it in items:
        if is_url_item(it):
            by_path[(str(it.get("source", "")).lower(), norm_path(it.get("path", "")), host_of(it))].append(it)
    any_dups = [grp for grp in by_path.values()
                if any(str(g.get("method", "")) in ("", "ANY") for g in grp) and any(str(g.get("method", "")) not in ("", "ANY") for g in grp)]
    if any_dups:
        md += [f"## 同じパスに ANY と個別メソッドの両方がある: {len(any_dups)} 組", "",
               "定義が本当に全メソッドを受ける（`app.all`、`app.use`、中継）なら両方残す。まとめ書きとして ANY と書いただけなら、`aliases.jsonl` で ANY の行を取り下げる"
               "（`{\"source\": …, \"from\": {\"method\": \"ANY\", \"path\": …}, \"drop\": \"個別メソッドの項目と重複\"}`）。", "",
               "| ソース | パス | メソッド | ANY の発見元 |", "|---|---|---|---|"]
        for grp in any_dups[:80]:
            a = next(g for g in grp if str(g.get("method", "")) in ("", "ANY"))
            md.append(f"| {a.get('source', '')} | `{a.get('path', '')}` | {' '.join(sorted(str(g.get('method', '')) or '(空)' for g in grp))} | {a.get('found_by', '')} |")
        md.append("")

    # 同じメソッドとパスを、別々のファイルの定義から 1 件にまとめたもの（同じソースに HTTP サーバーが複数ある場合の誤統合を疑う）
    # ルート表とハンドラを別のファイルから書くのは普通なので、衝突しやすい形（ルート直下と、配下すべてを受けるパス）だけを挙げる
    cross_file = [it for it in items if is_url_item(it) and len(it.get("_first_files", [])) > 1
                  and (norm_path(it.get("path", "")) == "/" or norm_path(it.get("path", "")).endswith("{*}"))]
    if cross_file:
        md += [f"## 別々のファイルの定義を、同じパスとして 1 件にまとめたもの（ルート直下と、配下すべてを受けるパス）: {len(cross_file)} 件", "",
               "ルート表とハンドラのように、同じ入口を別のファイルから書いたものなら正しい。**同じソースの中に別の HTTP サーバーや別の動作モードがあって、たまたま同じパスになっている**なら誤り。"
               "誤りなら、片方に `aliases.jsonl` で `host`（`役割名:ポート` の形）を付けて分ける。", "",
               "| ソース | メソッド パス | 根拠にされたファイル |", "|---|---|---|"]
        for it in sorted(cross_file, key=lambda x: (norm_path(x.get("path", "")) not in ("/", "/{*}"), -len(x["_first_files"])))[:100]:
            md.append(f"| {it.get('source', '')} | `{it.get('method', '')} {it.get('path', '')}` | {'<br>'.join(f.rsplit('/', 2)[-2] + '/' + f.rsplit('/', 1)[-1] if '/' in f else f for f in it['_first_files'][:5])} |")
        if len(cross_file) > 100:
            md.append(f"| … | ほか {len(cross_file) - 100} 件 | |")
        md.append("")

    md += ["## 解釈点と入口の結び付け", "",
           f"解釈点の `fed_by` のうち、入口の項目に結べたもの {fed_linked} 件（結べた入口には、`reaches` を自動で足してある）。**結べなかった書き方: {len(fed_unmatched)} 通り。**"
           f" 入口に結べたので `REACH_UNKNOWN` を外した解釈点: {reach_cleared} 件。", ""]
    if fed_unmatched:
        md += ["`fed_by` は、入口の項目と同じ書き方（`POST /api/x`、`server-action:名前`、キュー名など、その入口の `method` と `path`）で書くと結ばれる。"
               "結べなかったものは、`overrides.jsonl` で `fed_by` を入口の書き方に直す（多いものから）。", "",
               "| fed_by の書き方 | 件数 |", "|---|---:|"]
        md += [f"| `{s[:110]}` | {n} |" for s, n in fed_unmatched.most_common(80)]
        if len(fed_unmatched) > 80:
            md.append(f"| … ほか {len(fed_unmatched) - 80} 通り | |")
        md.append("")

    multi_host = [it for it in items if it.get("also_hosts")]
    if multi_host:
        md += [f"## 複数のホストで公開されている同じ定義: {len(multi_host)} 件", "",
               "根拠が同じ箇所で、ホストだけが違う書き方をまとめたもの。ホストごとに扱い（認証・アクセス制限）が違うなら、`aliases.jsonl` でホストごとの根拠（server ブロックの行など）に付け替えて分ける。", ""]
        md += [f"- {it.get('source', '')} `{label(it)}` — {host_of(it)} / {' / '.join(it['also_hosts'])}" for it in multi_host[:60]] + [""]

    if dropped:
        md += [f"## 取り下げたもの: {len(dropped)} 件", ""] + [f"- {r.get('source', '')} `{r.get('method', '')} {r.get('path', '')}` — {why}" for r, why in dropped[:80]] + [""]
    by_src = Counter(str(it.get("source", "")) for it in items)
    md += ["## ソース別の件数", "", "| ソース | 件数 |", "|---|---:|"] + [f"| {s} | {n} |" for s, n in by_src.most_common()] + [""]
    (work / "check" / "merge.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"rows={len(rows)} dropped={len(dropped)} merged={len(items)} entries={layers['入口']} intake={layers['受け口']} parsers={layers['解釈点']} "
          f"auto_merged_spellings={len(multi)} suspects={len(suspects)} unused_rules={len(unused)} no_priority={len(todo)}")
    print(f"report={(work / 'check' / 'merge.md').as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
