"""読む範囲を決める。解析はしない。

棚卸しした全ファイルを、読み方の区分（ティア）に分ける。

  A / B … 全文を読む
  C     … 流し読み（冒頭と構造を見て、関係しないと判断した理由を記録する）
  D     … 開かない（翻訳、テスト用データ、変更履歴、ロックファイル、バイナリなど）。読み手には割り当てない。検索の対象には残る

D に落とすのは「見落とし」と引き換えなので、次の 3 つで守る。

  1. 落とさない名前を先に除く（依存定義、インフラ・サーバー設定、API 仕様、環境設定）
  2. 落とした全ファイルを機械的に走査し、入口・解釈処理らしい行が 1 つでもあれば C に戻す
  3. 区分ごとの件数・サイズ・例を work/scope.md に出し、取りまとめ役が確かめる。直したいときは work/scope.jsonl に書いて --refresh
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
from _common import load_jsonl, read_text, resolve  # noqa: E402

# 区分 → (ティア, 一覧に出す説明)
CATEGORIES = {
    "binary": ("D", "バイナリ（画像・フォント・圧縮物・実行形式・文書）"),
    "lock": ("D", "ロックファイル（通読しない。依存定義に版が書かれていない部品の版は、ここを検索して引く。knowledge.md の版はここからも補ってある）"),
    "secret": ("C", "鍵・証明書（中身を書き写さない。種類と所在だけを記録する）"),
    "translation": ("D", "翻訳・文言の定義（言語ごとの同形のファイル群）"),
    "fixture": ("D", "テスト用のデータ（サンプルの HTML・XML・JSON・メールなど）"),
    "snapshot": ("D", "スナップショット・静的解析の基準ファイル"),
    "history": ("D", "ライセンス・謝辞・行動規範"),
    "changelog": ("C", "変更履歴（流し読み: 削除・移動された入口と、セキュリティ修正の記載を検索して拾う。全文は読まない）"),
    "test": ("C", "テストコード（流し読み: 呼んでいる口と、テスト専用の経路・設定を拾う）"),
    "docs": ("C", "文書（流し読み: 構成・ポート・API の説明・コマンド例を拾う）"),
    "vendored": ("C", "リポジトリに同梱された外部ライブラリ（名前とバージョンを控える）"),
    "migration": ("C", "DB マイグレーション"),
    "patch": ("C", "パッチ・差分（流し読み: 何に当てる差分かを見る）"),
}
# バイナリのうち、所在を報告に書く価値があるもの（鍵・証明書・DB・実行可能な成果物）
NOTABLE_BINARY = {".jks", ".keystore", ".p12", ".pfx", ".der", ".db", ".sqlite", ".sqlite3", ".jar", ".war", ".ear", ".apk", ".ipa", ".aar", ".exe", ".dll", ".so", ".dylib", ".wasm", ".node"}

# どの区分にも落とさない名前（入口や構成を決めるもの）
KEEP = re.compile(
    r"(?i)(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|pipfile|setup\.(py|cfg)|pom\.xml|build\.gradle(\.kts)?|go\.mod|gemfile|composer\.json|cargo\.toml|mix\.exs|"
    r"pubspec\.yaml|[^/]+\.(cs|fs|vb)proj|dockerfile[^/]*|[^/]*docker-compose[^/]*|compose\.ya?ml|procfile|makefile|web\.xml|\.htaccess|androidmanifest\.xml|info\.plist|"
    r"serverless\.ya?ml|vercel\.json|netlify\.toml|firebase\.json|wrangler\.toml|fly\.toml|app\.ya?ml|chart\.yaml|kustomization\.yaml)$|"
    r"(openapi|swagger|postman|insomnia)[^/]*$|\.(tf|tfvars|proto|graphqls?|gql|har|http|rest|wsdl|conf|env)$|(^|/)\.env[^/]*$|(^|/)nginx[^/]*$|(^|/)readme[^/]*$"
)
CODE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".py", ".rb", ".php", ".go", ".rs", ".java", ".kt", ".scala", ".cs", ".fs", ".vb", ".swift",
            ".m", ".dart", ".ex", ".exs", ".erl", ".c", ".h", ".cpp", ".cc", ".pl", ".lua", ".sh", ".ps1", ".groovy", ".clj", ".hs", ".erb", ".cshtml", ".jsp", ".blade.php"}
DATA_EXT = {".html", ".htm", ".xml", ".json", ".txt", ".eml", ".msg", ".csv", ".tsv", ".ics", ".vcf", ".atom", ".rss", ".opml", ".log", ".snap", ".out", ".golden", ".expected",
            ".svg", ".pem", ".crt", ".key", ".md"}
LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "gemfile.lock", "poetry.lock", "cargo.lock", "go.sum", "packages.lock.json", "uv.lock",
              "bun.lockb", "bun.lock", "pubspec.lock", "podfile.lock", "flake.lock", "npm-shrinkwrap.json"}
TRANSLATION_EXT = {".xlf", ".xliff", ".po", ".pot", ".mo", ".arb", ".strings", ".stringsdict", ".resx"}
TRANSLATION_DIRS = {"locale", "locales", "i18n", "lang", "langs", "language", "languages", "translations", "translation", "l10n", "intl"}
TRANSLATION_FILE_EXT = {".json", ".yml", ".yaml", ".properties", ".ts", ".js", ".php", ".toml", ".ini", ".txt", ".csv", ".xml"}
LANG_CODE = re.compile(r"^(?:[\w\-]*[._\-])?[a-z]{2,3}(?:[_\-][A-Za-z]{2,4})?(?:[_\-][A-Za-z0-9]{2,8})?$")
FIXTURE_DIRS = {"testdata", "fixtures", "fixture", "__fixtures__", "__snapshots__", "cassettes", "vcr_cassettes", "golden", "goldens", "test-data", "test_data", "testfiles", "test-files"}
TEST_DIRS = {"test", "tests", "spec", "specs", "__tests__", "__test__", "e2e", "cypress", "playwright", "testing", "integration-tests", "integration_tests"}
TEST_NAME = re.compile(r"(?i)([._\-](test|spec|e2e)\.[a-z]+$|_test\.(go|py|rb|rs|dart|exs?)$|(^|/)test_[^/]+\.py$|Tests?\.(java|cs|kt|scala|groovy|php)$|\.stories\.[jt]sx?$)")
DOC_DIRS = {"docs", "doc", "documentation", "wiki", "website", "man"}
DOC_EXT = {".md", ".mdx", ".rst", ".adoc", ".asciidoc", ".1", ".5", ".8"}
VENDOR_DIRS = {"vendor", "vendors", "third_party", "third-party", "thirdparty", "3rdparty"}
MIGRATION_DIRS = {"migrations", "migration", "migrate"}
HISTORY_NAME = re.compile(r"(?i)^(licen[sc]e|copying|notice|authors|contributors|code[-_ ]of[-_ ]conduct|patents|credits|thanks)(\b|[._\-])")
CHANGELOG_NAME = re.compile(r"(?i)^(changelog|changes|history|news|release[-_ ]?notes?|upgrading|upgrade[-_ ]?guide|breaking[-_ ]?changes)(\b|[._\-])")
BASELINE_NAME = re.compile(r"(?i)baseline[^/]*\.(txt|json|xml|neon|ya?ml)$|\.snap$")
SECRET_EXT = {".key", ".pem", ".crt", ".cer", ".ppk", ".asc", ".gpg", ".pub", ".jwk", ".keys"}
SECRET_NAME = re.compile(r"(?i)^(id_(rsa|dsa|ecdsa|ed25519)|.*private[-_.]?key.*|.*\.keystore)$")
SECRET_SHAPE = re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----|(?i:private[_-]?key\s*[:=]\s*[\"'|>-])")
SCAN_MAX = 4_000_000


def _propose(rel: str, f: dict, lang_groups: set[str]) -> str:
    """区分の案（どれにも当たらなければ空）。rel はソース内の相対パス。"""
    low = rel.lower()
    parts = low.split("/")
    name, dirs = parts[-1], parts[:-1]
    ext = f["ext"]
    if not f.get("text"):
        return "binary"
    if ext in SECRET_EXT or SECRET_NAME.match(name):
        return "secret"
    if KEEP.search(low):
        return ""
    if name in LOCK_NAMES or ext == ".lock":
        return "lock"
    stem = name[: -len(ext)] if ext and name.endswith(ext) else name
    if ext in TRANSLATION_EXT or ("/".join(dirs) in lang_groups and LANG_CODE.match(stem)) or (len(dirs) >= 1 and "/".join(dirs[:-1]) + "|" + dirs[-1] in lang_groups):
        return "translation"
    if BASELINE_NAME.search(name):
        return "snapshot"
    in_fixture = any(d in FIXTURE_DIRS for d in dirs)
    in_test = any(d in TEST_DIRS for d in dirs)
    if (in_fixture and ext not in CODE_EXT) or (in_test and ext in DATA_EXT and ext != ".md"):
        return "fixture"
    if in_fixture or in_test or TEST_NAME.search(rel):
        return "test"
    if CHANGELOG_NAME.search(name) and ext in ("", ".md", ".txt", ".rst", ".adoc"):
        return "changelog"
    if HISTORY_NAME.search(name) and ext in ("", ".md", ".txt", ".rst", ".adoc"):
        return "history"
    if any(d in VENDOR_DIRS for d in dirs):
        return "vendored"
    if any(d in MIGRATION_DIRS for d in dirs) and ext in CODE_EXT | {".sql"}:
        return "migration"
    if ext in (".patch", ".diff"):
        return "patch"
    if ext in DOC_EXT and (any(d in DOC_DIRS for d in dirs) or ext in (".md", ".mdx", ".rst", ".adoc")):
        return "docs"
    return ""


def _language_groups(files: list[dict], rel_of) -> set[str]:
    """翻訳ファイルの置き場所。翻訳らしい名前のディレクトリの下に、言語コードの名前が 3 つ以上並んでいる場合だけ採る。

    返す集合の要素: "dir"（その直下のファイルが言語ごと）または "dir|code"（その下の code/ ディレクトリが言語ごと）。
    """
    by_dir: dict[str, set[str]] = defaultdict(set)      # dir → 言語コードらしいファイル名（拡張子なし）
    by_parent: dict[str, set[str]] = defaultdict(set)   # dir → 言語コードらしい子ディレクトリ名
    for f in files:
        parts = rel_of(f).lower().split("/")
        if len(parts) < 2 or f["ext"] not in TRANSLATION_FILE_EXT:
            continue
        dirs, stem = parts[:-1], parts[-1][: -len(f["ext"])] if f["ext"] else parts[-1]
        if any(d in TRANSLATION_DIRS for d in dirs) and LANG_CODE.match(stem):
            by_dir["/".join(dirs)].add(stem)
        if len(dirs) >= 2 and any(d in TRANSLATION_DIRS for d in dirs[:-1]) and LANG_CODE.match(dirs[-1]):
            by_parent["/".join(dirs[:-1])].add(dirs[-1])
    groups = {d for d, names in by_dir.items() if len(names) >= 3}
    for d, codes in by_parent.items():
        if len(codes) >= 3:
            groups |= {f"{d}|{c}" for c in codes}
    return groups


_PATH_VALUE = re.compile(r"""["'>=:]\s*["']?(/[A-Za-z0-9_\-{}:.*]+(?:/[A-Za-z0-9_\-{}:.*]*)+|https?://[^\s"'<>]+)["']?\s*[,<}\]]?\s*$""")
_ROUTE_KEY = re.compile(r"""(?i)["']?(path|route|url|uri|endpoint|handler|controller|method|upstream|target|redirect|rewrite)s?["']?\s*[:=]""")


def _has_marks(path: Path, ext: str, hints: list, infra: list, parser_hints: list) -> list[tuple[int, str]]:
    """落とす区分のファイルに、入口・解釈処理らしい行があるか。最大 3 件。

    コードの拡張子なら、ルート定義・注釈・解釈処理の目印をそのまま使う。
    データの拡張子（json・xml・yaml・html など）は実行されないので、コード用の目印は意味を持たない（文言中の語に誤って当たる）。
    代わりに、ルート表や設定の形をしていないかを見る: 値がパスや URL の行が多い、path / route / handler などのキーが並ぶ、インフラ設定の語がある。
    """
    try:
        lines = read_text(path).splitlines()
    except OSError:
        return []
    found: list[tuple[int, str]] = []
    for n, line in enumerate(lines, 1):
        if len(line) <= 600 and SECRET_SHAPE.search(line):
            return [(n, "鍵・証明書の形をした行")]
    if ext in CODE_EXT:
        for n, line in enumerate(lines, 1):
            if 8 <= len(line) <= 600:
                for name, rx in (*hints, *infra, *parser_hints):
                    if rx.search(line):
                        found.append((n, name))
                        break
                if len(found) >= 3:
                    break
        return found
    path_lines: list[int] = []
    key_lines: list[int] = []
    for n, line in enumerate(lines, 1):
        if not 8 <= len(line) <= 600:
            continue
        for name, rx in infra:
            if rx.search(line):
                found.append((n, name))
                break
        if _ROUTE_KEY.search(line):
            key_lines.append(n)
            if _PATH_VALUE.search(line):
                path_lines.append(n)
    total = max(1, sum(1 for line in lines if line.strip()))
    # ルート表らしさ: path / url などのキーにパスや URL の値が付いた行が、まとまって（3 行以上かつ全体の 3% 以上）ある
    if len(path_lines) >= 3 and len(path_lines) / total >= 0.03:
        found += [(n, "パスや URL を値に持つ定義") for n in path_lines[:3]]
    return found[:3]


def triage(inv: dict, overrides: list[dict] | None = None) -> dict:
    """inv["files"] の各ファイルに scope（区分）を付け、ティアを決め直す。戻り値は scope.md 用の集計。"""
    from check import HINTS, PARSER_HINTS  # 遅延: check は kb を読むため

    strong = [(n, rx) for n, rx in HINTS if n in ("ルート定義らしい行", "ルーティング用の注釈", "ファイル規約のハンドラ", "GraphQL・RPC・WebSocket の定義")]
    # インフラ設定の語は、文言にも現れる一般語（listen、ingress、redirect など）を除いた、設定にしか出ない形だけを使う
    infra = [("インフラ上の露出", re.compile(r"(?i)(?:proxy_pass|fastcgi_pass|ProxyPass|reverse_proxy|containerPort|hostPort|nodePort|targetPort|server_name)|^\s*ports\s*:\s*$|listen\s+\d+"))]
    base = inv["base_dir"]
    roots = {s["name"]: str(s.get("root", "")).replace("\\", "/").rstrip("/") for s in inv["sources"]}

    def rel_of(f: dict) -> str:
        root = roots.get(f["source"], "")
        p = f["path"]
        return p[len(root) + 1:] if root and p.startswith(root + "/") else p.rsplit("/", 1)[-1]

    by_source: dict[str, list[dict]] = defaultdict(list)
    for f in inv["files"]:
        by_source[f["source"]].append(f)
    promoted: list[dict] = []
    for source, files in by_source.items():
        groups = _language_groups(files, rel_of)
        for f in files:
            f.pop("scope", None)
            cat = _propose(rel_of(f), f, groups)
            if not cat and f.get("text") and f["tier"] != "C" and f["ext"] in (".js", ".mjs", ".cjs", ".css") and f["size"] > 60_000 and not KEEP.search(rel_of(f).lower()):
                try:  # 同梱された配布物の印（冒頭のライセンス表記・版数）
                    with open(resolve(base, f["path"]), "rb") as fh:
                        head = fh.read(800)
                    if re.search(rb"/\*!|@license|@preserve|\(c\)\s*\d{4}|Copyright\s+(?:\(c\)\s*)?\d{4}|v?\d+\.\d+\.\d+", head):
                        cat = "vendored"
                except OSError:
                    pass
            if not cat:
                if f["tier"] == "C" and not f.get("text"):
                    cat = "binary"
                else:
                    continue
            tier, _desc = CATEGORIES[cat]
            # ロックファイルは名前の完全一致で決まり、中身は依存の取得先 URL の列なので走査しない
            if tier == "D" and cat != "lock" and f.get("text") and f["size"] <= SCAN_MAX:
                # 翻訳の文言には action などの語がそのまま現れるので、語だけで当たる注釈の目印は使わない
                hints = [h for h in strong if h[0] != "ルーティング用の注釈"] if cat == "translation" else strong
                marks = _has_marks(resolve(base, f["path"]), f["ext"], hints, infra, PARSER_HINTS)
                if marks:  # 安全網: 落とす区分だが、入口・解釈処理らしい行がある → 流し読みに戻す
                    promoted.append({"path": f["path"], "source": source, "category": cat, "marks": marks})
                    f.update(tier="C", scope=cat, why=f"{CATEGORIES[cat][1].split('（')[0]}に見えるが、{marks[0][1]}（{marks[0][0]} 行目）があるため流し読みに戻した")
                    continue
            if tier == "D" or f["tier"] != "C":  # 既に C のもの（minify・生成物など）は元の理由を残す
                f.update(tier=tier, why=CATEGORIES[cat][1].split("（")[0])
            f["scope"] = cat

    applied = Counter()
    for i, ov in enumerate(overrides or []):
        tier = str(ov.get("tier", "")).upper()
        if tier not in ("A", "B", "C", "D"):
            continue
        for f in inv["files"]:
            ok = (ov.get("path") and f["path"].replace("\\", "/").endswith(str(ov["path"]).replace("\\", "/"))) or \
                 (ov.get("path_regex") and re.search(ov["path_regex"], f["path"])) or (ov.get("scope") and f.get("scope") == ov["scope"] and not ov.get("path") and not ov.get("path_regex"))
            if ok and (not ov.get("source") or ov["source"] == f["source"]):
                f.update(tier=tier, why=f"取りまとめ役の判断: {ov.get('reason', '理由の記載なし')}")
                applied[i] += 1
    return {"promoted": promoted, "override_hits": applied, "overrides": overrides or []}


def load_overrides(work: Path) -> tuple[list[dict], list[str]]:
    """(scope.jsonl の行, 読めなかった行の説明)"""
    p = work / "scope.jsonl"
    return load_jsonl(p) if p.exists() else ([], [])


def write_scope(work: Path, inv: dict, result: dict) -> Path:
    """work/scope.md: 何を読み、何を読まないことにしたか。"""
    files = inv["files"]
    root = str(inv.get("input_root", "")).rstrip("/")

    def show(p: str) -> str:
        return p[len(root) + 1:] if root and p.startswith(root + "/") else p

    def human(n: float) -> str:
        return f"{n / 1e6:.1f}MB" if n >= 1e6 else f"{n / 1e3:.0f}KB"

    tiers = Counter(f["tier"] for f in files)
    size = Counter()
    for f in files:
        size[f["tier"]] += f["size"]
    md = ["# 読む範囲の定義", "",
          "全ファイルを、読み方の区分に分けた結果。**D（開かない）に落としたものに、読むべきファイルが紛れていないかを確かめてから先へ進む。**", "",
          "| ティア | 読み方 | ファイル | サイズ |", "|---|---|---:|---:|",
          f"| A | 全文を読む（入口に直結しそうな名前） | {tiers['A']} | {human(size['A'])} |",
          f"| B | 全文を読む | {tiers['B']} | {human(size['B'])} |",
          f"| C | 流し読み（冒頭と構造を見て、関係しないと判断した理由を記録） | {tiers['C']} | {human(size['C'])} |",
          f"| D | 開かない（読み手に割り当てない。検索の対象には残る） | {tiers['D']} | {human(size['D'])} |", ""]

    md += ["## 区分ごとの内訳", "", "サイズの大きい順に例を挙げる。例の名前と置き場所が、区分の説明と合っているかを見る。", ""]
    for source in dict.fromkeys(f["source"] for f in files):
        md += [f"### {source}", "", "| 区分 | ティア | ファイル | サイズ | 例（大きい順） |", "|---|---|---:|---:|---|"]
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for f in files:
            if f["source"] == source and (f.get("scope") or f["tier"] in ("C", "D")):
                groups[(f.get("scope") or "other", f["tier"])].append(f)
        for (cat, tier), fl in sorted(groups.items(), key=lambda kv: (kv[0][1] != "D", -sum(x["size"] for x in kv[1]))):
            desc = CATEGORIES[cat][1] if cat in CATEGORIES else "そのほか（minify 済み・生成物・巨大ファイル・スタイルなど。理由は units の一覧に出る）"
            ex = "<br>".join(f"`{show(x['path'])}`（{human(x['size'])}）" for x in sorted(fl, key=lambda x: -x["size"])[:4])
            md.append(f"| {desc} | {tier} | {len(fl)} | {human(sum(x['size'] for x in fl))} | {ex} |")
        md.append("")
        notable = [f for f in files if f["source"] == source and not f.get("text") and f["ext"] in NOTABLE_BINARY]
        if notable:
            md += [f"**所在を報告に書くバイナリ（鍵・証明書・DB・実行可能な成果物）: {len(notable)} 件**", ""]
            md += [f"- `{show(f['path'])}`（{human(f['size'])}）" for f in notable[:40]] + [""]

    promoted = result["promoted"]
    md += [f"## 安全網が流し読みに戻したもの: {len(promoted)} 件", "",
           "D に落とす区分に当たったが、入口や解釈処理らしい行が見つかったファイル。ティア C として読み手に割り当ててある。", ""]
    if promoted:
        md += ["| ファイル | 当たった区分 | 見つかった目印（行） |", "|---|---|---|"]
        md += [f"| `{show(p['path'])}` | {CATEGORIES[p['category']][1].split('（')[0]} | {'、'.join(f'{name}（{ln}）' for ln, name in p['marks'])} |" for p in promoted[:200]]
        if len(promoted) > 200:
            md.append(f"| … ほか {len(promoted) - 200} 件 | | |")
        md.append("")
    else:
        md += ["なし。", ""]

    if result["overrides"]:
        md += ["## 取りまとめ役による変更（scope.jsonl）", ""]
        md += [f"- {i + 1} 行目: `{json.dumps({k: v for k, v in ov.items() if not k.startswith('_')}, ensure_ascii=False)}` → {result['override_hits'][i]} 件" for i, ov in enumerate(result["overrides"])]
        md.append("")

    md += ["## 確かめること", "",
           "1. D の各区分について、例に挙がったファイルを 2〜3 個開く。**翻訳やテスト用データの形をしていないもの、設定やコードが混じっているものがあれば戻す**",
           "2. 区分の名前と合わない置き場所（`locale/` の下の設定、`fixtures/` の下のサーバー定義、`vendor/` の下の自作コード）が無いかを、例とディレクトリ名から見る",
           "3. 「安全網が戻したもの」を見て、同じ種類の取りこぼしが D に残っていそうなら、その区分ごと C に戻す",
           "4. ティア C の「テストコード」「文書」が、このシステムでは入口の定義を含む（テスト用サーバーが本番にも載る、文書に API 定義が埋め込まれている）なら B に上げる",
           "5. 迷ったら読む側に倒す。戻すときは `work/scope.jsonl` に 1 行ずつ書き、`inventory.py --refresh RUN` を実行する", "",
           "```json",
           '{"path_regex": "/locale/routes\\\\.json$", "tier": "B", "reason": "翻訳の置き場所にあるがルート定義"}',
           '{"scope": "fixture", "source": "shop-api", "tier": "C", "reason": "fixtures にサーバー設定が混じっている"}',
           "```", "",
           "D のファイルも、パス 2 の検索には掛かる。検索で当たったら、区分に関係なく開いて読む。",
           "ここで決めた範囲（区分・件数・戻したもの）は、`coverage.md` の「読んだ範囲」にそのまま載せる。", ""]
    path = work / "scope.md"
    path.write_text("\n".join(md) + "\n", encoding="utf-8")
    return path
