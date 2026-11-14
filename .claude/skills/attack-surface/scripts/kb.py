"""知識ベース（references/）のうち、この入力に関係する項目を抜き出す。解析はしない。

依存の宣言・コンテナイメージ名・ファイルの有無・決まった記述を手がかりに、
  - implicit-endpoints.json（暗黙に存在するエンドポイント）
  - parser-components.json（受け取り・解釈を担う部品）
の該当項目を選び、work/knowledge.md に書き出す。読み手・探し手は知識ベース全体ではなくこの抜粋を読む。
check.py は同じ照合結果を「言及漏れ」の検査に使う。

手がかり (when / match) のキー:
  npm pypi gem composer maven nuget go cargo hex pub … 依存名（末尾 * は前方一致）
  docker … コンテナイメージ名（* 可）
  files  … パスに対する正規表現
  code   … {"glob": "*.py|settings/*.py", "regex": "…"}（glob に合うファイルの中身に対する正規表現）
"""
from __future__ import annotations

import fnmatch
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
from _common import read_text, resolve  # noqa: E402

REF = Path(__file__).parent.parent / "references"
COMPONENTS = REF / "parser-components.json"
IMPLICIT = REF / "implicit-endpoints.json"

ECO_FILES = {
    "npm": lambda n: n == "package.json",
    "pypi": lambda n: (n.startswith("requirements") and n.endswith(".txt")) or n in ("pyproject.toml", "pipfile", "setup.py", "setup.cfg", "environment.yml", "constraints.txt"),
    "gem": lambda n: n == "gemfile" or n.endswith(".gemspec"),
    "composer": lambda n: n == "composer.json",
    "maven": lambda n: n == "pom.xml" or n.startswith("build.gradle") or n == "libs.versions.toml",
    "nuget": lambda n: n.endswith((".csproj", ".fsproj", ".vbproj")) or n in ("packages.config", "directory.packages.props"),
    "go": lambda n: n == "go.mod",
    "cargo": lambda n: n == "cargo.toml",
    "hex": lambda n: n == "mix.exs",
    "pub": lambda n: n == "pubspec.yaml",
}
_DOCKERISH = re.compile(r"(^dockerfile|\.dockerfile$|\.ya?ml$|\.tf$|\.hcl$|\.nomad$|^containerfile)", re.I)
_CODE_SIZE_MAX = 800_000


def _name_rx(name: str, extra: str = r"[\w.\-/@]*") -> str:
    return re.escape(name[:-1]) + extra if name.endswith("*") else re.escape(name)


def dep_patterns(eco: str, name: str) -> list[re.Pattern]:
    n = _name_rx(name)
    if eco in ("npm", "composer"):
        pats = [rf'"{n}"\s*:\s*"([^"]*)"']
    elif eco == "pypi":
        nn = "[-_.]+".join(re.escape(p) for p in re.split(r"[-_.]+", name.rstrip("*")) if p) + (r"[\w.\-]*" if name.endswith("*") else "")
        pats = [
            rf'(?im)^\s*{nn}\s*(?:\[[^\]\n]*\])?\s*((?:[<>=!~]=?=?)\s*[\w.*]+)?\s*(?:[;#,@].*)?$',
            rf'''(?i)["']{nn}(?:\[[^\]\n]*\])?\s*((?:[<>=!~]=?=?)\s*[\w.*]+)?[^"'\n]*["']''',
            rf'(?im)^\s*{nn}\s*=\s*(.+)$',
        ]
    elif eco == "gem":
        pats = [rf'''(?m)^\s*gem\s+["']{n}["'](?:\s*,\s*["']([^"'\n]+)["'])?''', rf'''dependency\s*\(?\s*["']{n}["'](?:\s*,\s*["']([^"'\n]+)["'])?''']
    elif eco == "maven":
        pats = [rf'<artifactId>\s*{n}\s*</artifactId>(?:\s*<version>\s*([^<]+)</version>)?', rf'''[:]{n}(?::([\w.\-+${{}}]+))?["')\s]''', rf'''(?m)^\s*id\s*\(?\s*["']{n}["']''']
    elif eco == "nuget":
        pats = [rf'(?i)(?:Include|Update)\s*=\s*"{n}"(?:\s+Version\s*=\s*"([^"]+)")?', rf'(?i)<package\s+id\s*=\s*"{n}"(?:\s+version\s*=\s*"([^"]+)")?', rf'(?i)Sdk\s*=\s*"{n}"']
    elif eco == "go":
        pats = [rf'(?m)^\s*(?:require\s+)?{n}(?:/[\w.\-/]+)?\s+(v[\w.\-+]+)(?![^\n]*//\s*indirect)']
    elif eco == "cargo":
        pats = [rf'(?m)^\s*{n}\s*=\s*[^\n]*?"(\d[^"]*)"', rf'(?m)^\s*{n}\s*=', rf'(?m)^\s*\[(?:dev-|build-)?dependencies\.{n}\]']
    elif eco == "hex":
        pats = [rf'\{{\s*:{n}\s*,\s*"([^"]+)"', rf'\{{\s*:{n}\b']
    elif eco == "pub":
        pats = [rf'(?m)^\s+{n}\s*:\s*\^?([\w.\-+]*)']
    else:
        return []
    return [re.compile(p) for p in pats]


LOCK_FILES = {
    "gem": ("gemfile.lock",), "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"), "composer": ("composer.lock",),
    "pypi": ("poetry.lock", "uv.lock", "pipfile.lock"), "cargo": ("cargo.lock",), "go": ("go.sum",), "pub": ("pubspec.lock",), "hex": ("mix.lock",),
}


def lock_version(eco: str, name: str, text: str) -> str:
    """ロックファイルの文面から、部品の固定された版を探す。見つからなければ空。"""
    n = re.escape(name.rstrip("*"))
    pats = {
        "gem": [rf"(?m)^ {{4}}{n} \(([^)\s]+)\)"],
        "npm": [rf'"node_modules/{n}"\s*:\s*\{{\s*"version"\s*:\s*"([^"]+)"', rf'(?m)^"?{n}@[^\n]*:\n\s+version:?\s+"?([^"\s]+)"?', rf"(?m)^\s+'?/?{n}@(\d[^'\s:(]*)"],
        "composer": [rf'"name"\s*:\s*"{n}"\s*,\s*"version"\s*:\s*"([^"]+)"'],
        "pypi": [rf'(?im)^name\s*=\s*"{n}"\s*\nversion\s*=\s*"([^"]+)"', rf'(?i)"{n}"\s*:\s*\{{[^{{}}]*?"version"\s*:\s*"==([^"]+)"'],
        "cargo": [rf'(?m)^name\s*=\s*"{n}"\s*\nversion\s*=\s*"([^"]+)"'],
        "go": [rf"(?m)^{n}(?:/[\w.\-/]+)? (v[\w.\-+]+)"],
        "pub": [rf"(?m)^  {n}:\n(?:    .*\n)*?    version: \"([^\"]+)\""],
        "hex": [rf'"{n}": \{{:hex, :\w+, "([^"]+)"'],
    }.get(eco, [])
    for p in pats:
        try:
            m = re.search(p, text)
        except re.error:
            continue
        if m:
            return m.group(1)[:30]
    return ""


def docker_pattern(name: str) -> re.Pattern:
    n = _name_rx(name, r"[\w.\-]*")
    return re.compile(
        rf'''(?im)^\s*(?:FROM\s+(?:--platform=\S+\s+)?|-?\s*["']?image["']?\s*[:=]\s*)["']?((?:[\w.\-]+(?::\d+)?/)*{n})(?::([\w.\-]+))?(?:@sha256:[0-9a-f]+)?(?=["'\s]|$)''')


def _glob_match(glob: str, path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    low = path.lower()
    for g in str(glob or "*").lower().split("|"):
        g = g.strip()
        if not g:
            continue
        if "/" in g:
            if fnmatch.fnmatch(low, g) or fnmatch.fnmatch(low, "*/" + g):
                return True
        elif fnmatch.fnmatch(name, g):
            return True
    return False


def load_kb() -> tuple[list[dict], list[dict]]:
    """(暗黙エンドポイントの項目, 解釈部品の項目)。読めなければ空。"""
    def load(path: Path, key: str) -> list[dict]:
        try:
            return [x for x in json.loads(path.read_text(encoding="utf-8"))[key] if isinstance(x, dict) and x.get("id")]
        except (OSError, ValueError, KeyError, TypeError):
            return []
    return load(IMPLICIT, "entries"), load(COMPONENTS, "components")


def scan(inventory: dict) -> dict:
    """ソースごとに、知識ベースの各項目の手がかりを探す。

    戻り値: {"implicit": {source: [{"item": 項目, "hits": [(名前, パス, 行, 版)]}]}, "components": {同}, "kb_sizes": (件数, 件数)}
    """
    entries, comps = load_kb()
    base = inventory["base_dir"]
    per_source: dict[str, dict] = defaultdict(lambda: {"manifests": defaultdict(list), "docker": [], "files": [], "locks": defaultdict(list)})
    for f in inventory["files"]:
        c = per_source[f["source"]]
        c["files"].append(f)
        if not f.get("text") or f["size"] > 2_000_000:
            continue
        name = f["path"].rsplit("/", 1)[-1].lower()
        for eco, names in LOCK_FILES.items():
            if name in names and f["size"] < 30_000_000:
                try:
                    c["locks"][eco].append(read_text(resolve(base, f["path"])))
                except OSError:
                    pass
        is_manifest = [eco for eco, test in ECO_FILES.items() if test(name)]
        is_docker = bool(_DOCKERISH.search(name)) and f["size"] < 500_000
        if not (is_manifest or is_docker):
            continue
        try:
            text = read_text(resolve(base, f["path"]))
        except OSError:
            continue
        for eco in is_manifest:
            c["manifests"][eco].append((f["path"], text))
        if is_docker:
            c["docker"].append((f["path"], text))

    # code の手がかりは、ファイルを 1 回ずつ読んでまとめて調べる
    code_rules: list[tuple[tuple[str, str], str, re.Pattern]] = []
    for kbname, items, wkey in (("implicit", entries, "when"), ("components", comps, "match")):
        for it in items:
            for rule in (it.get(wkey) or {}).get("code", []) or []:
                if isinstance(rule, dict) and rule.get("regex"):
                    try:
                        code_rules.append(((kbname, it["id"]), str(rule.get("glob", "*")), re.compile(rule["regex"], re.M)))
                    except re.error:
                        pass
    code_hits: dict[tuple[str, str, str], list] = defaultdict(list)
    if code_rules:
        for source, c in per_source.items():
            for f in c["files"]:
                if not f.get("text") or f["size"] > _CODE_SIZE_MAX:
                    continue
                todo = [r for r in code_rules if _glob_match(r[1], f["path"]) and len(code_hits[(source, *r[0])]) < 3]
                if not todo:
                    continue
                try:
                    text = read_text(resolve(base, f["path"]))
                except OSError:
                    continue
                for owner, _glob, rx in todo:
                    m = rx.search(text)
                    if m:
                        word = re.sub(r"\s+", " ", m.group(0)).strip()[:40]
                        code_hits[(source, *owner)].append((word, f["path"], text.count("\n", 0, m.start()) + 1, ""))

    def hits_for(kbname: str, it: dict, when: dict, source: str, c: dict) -> list[tuple[str, str, int, str]]:
        hits: list[tuple[str, str, int, str]] = []
        for key, names in (when or {}).items():
            if key in ECO_FILES:
                for path, text in c["manifests"].get(key, []):
                    for name in names:
                        for rx in dep_patterns(key, str(name)):
                            m = rx.search(text)
                            if m:
                                ver = (m.group(1) or "").strip() if m.groups() else ""
                                locked = next((v for v in (lock_version(key, str(name), lt) for lt in c["locks"].get(key, [])) if v), "")
                                if locked and locked not in ver:  # 依存定義に版が無い・範囲指定のときは、固定された版を添える
                                    ver = f"{ver} → ロック {locked}".strip(" →") if ver else f"ロック {locked}"
                                hits.append((str(name).rstrip("*"), path, text.count("\n", 0, m.start()) + 1, ver[:40]))
                                break
            elif key == "docker":
                for path, text in c["docker"]:
                    for name in names:
                        m = docker_pattern(str(name)).search(text)
                        if m:
                            hits.append((m.group(1), path, text.count("\n", 0, m.start(1)) + 1, (m.group(2) or "")[:30]))
            elif key == "files":
                for pat in names:
                    try:
                        rx = re.compile(str(pat), re.I)
                    except re.error:
                        continue
                    hit = next((f for f in c["files"] if rx.search(f["path"])), None)
                    if hit:
                        hits.append((hit["path"].rsplit("/", 1)[-1], hit["path"], 0, ""))
            elif key == "code":
                hits += code_hits.get((source, kbname, it["id"]), [])
        seen, uniq = set(), []
        for h in hits:
            if (h[0], h[1]) not in seen:
                seen.add((h[0], h[1]))
                uniq.append(h)
        return uniq

    out: dict = {"implicit": defaultdict(list), "components": defaultdict(list), "kb_sizes": (len(entries), len(comps))}
    for source, c in per_source.items():
        for it in entries:
            h = hits_for("implicit", it, it.get("when") or {}, source, c)
            if h:
                out["implicit"][source].append({"item": it, "hits": h})
        for it in comps:
            h = hits_for("components", it, it.get("match") or {}, source, c)
            if h:
                out["components"][source].append({"item": it, "hits": h})
    return out


def _cell(s) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")


def _clues(hits: list, limit: int = 4) -> str:
    return "<br>".join(f"`{n}`{(' ' + v) if v else ''} — {p}{(':' + str(ln)) if ln else ''}" for n, p, ln, v in hits[:limit])


def write_knowledge(run: Path, inventory: dict, result: dict | None = None) -> Path:
    """work/knowledge.md を書く。"""
    result = result or scan(inventory)
    n_entries, n_comps = result["kb_sizes"]
    md = ["# この入力に関係する知識（知識ベースからの抜粋）", "",
          "依存の宣言・コンテナイメージ名・ファイル・決まった記述を手がかりに、知識ベースから機械的に抜き出したもの。",
          "**ここに載っているのは「あり得る」であって「ある」ではない。** 設定で無効・移動されていないか、実際に組み込まれているかは読んで確かめる。",
          "**ここに無いものも「無い」ではない。** 知識ベースは網羅ではなく、手がかりの拾い漏れもある。載っていない依存については、既定で何を公開し何を解釈するかを自分の知識で考える。",
          "手がかりの欄（ファイル:行）は、そのまま根拠（evidence）の位置として使える。引用は自分でその行を開いて写す。", ""]

    md += ["## 1. 暗黙に存在し得るエンドポイント（implicit レンズ）", "",
           "載せるときは `origin: implicit`、`kb` に見出しの ID（例 `\"kb\": \"next-auth\"`）を書く。確からしさが low のものは `confidence` も low にする。"
           "パスの `{admin}` `{mount}` などは、組み込まれている場所を読んで置き換える。",
           "設定で無効・移動されていると確かめたものは載せず、`dismissed` として報告する（ID と理由）。", ""]
    if not any(result["implicit"].values()):
        md += ["該当なし（手がかりが見つからなかった）。", ""]
    for source in sorted(result["implicit"]):
        md += [f"### {source}", ""]
        for x in result["implicit"][source]:
            it = x["item"]
            base = f"（base: {it['base']} の配下になり得る）" if it.get("base") else ""
            md += [f"#### `{it['id']}` — {it.get('name', '')}{base}", "", f"手がかり: {_clues(x['hits'])}", "",
                   "| メソッド | パス | ポート等 | 確からしさ | 特徴 | 補足 |", "|---|---|---|---|---|---|"]
            for ep in it.get("endpoints", []):
                extra = " ".join(str(v) for v in (ep.get("proto"), ep.get("port")) if v)
                md.append(f"| {_cell(ep.get('m', ''))} | `{_cell(ep.get('p', ''))}` | {_cell(extra)} | {ep.get('c', '')} | {_cell(' '.join(ep.get('tags', []) or []))} | {_cell(ep.get('note', ''))} |")
            md.append("")

    md += ["## 2. 受け取り・解釈を担う部品（intake / parsers レンズ）", "",
           "部品ごとに、何を受け取り何を解釈しているかを調べて `input-channel` / `parser` として載せる（`component` に名前とバージョン）。",
           "使われていない・外部の値が届かないと確かめたら、載せずに `dismissed` として報告する。", ""]
    if not any(result["components"].values()):
        md += ["該当なし（手がかりが見つからなかった）。", ""]
    for source in sorted(result["components"]):
        md += [f"### {source}", "", "| 部品 ID | 層 | 分類 | 手がかり | 調べること |", "|---|---|---|---|---|"]
        for x in result["components"][source]:
            it = x["item"]
            todo = str(it.get("implies", "")) + (f"<br>※ {it['note']}" if it.get("note") else "")
            md.append(f"| `{it['id']}` | {'受け口' if it.get('layer') == 'input-channel' else '解釈点'} | {_cell(it.get('category', ''))} | {_clues(x['hits'])} | {_cell(todo)} |")
        md.append("")

    hit_i = {x["item"]["id"] for xs in result["implicit"].values() for x in xs}
    hit_c = {x["item"]["id"] for xs in result["components"].values() for x in xs}
    entries, comps = load_kb()
    md += ["## 3. 手がかりが見つからなかった項目（名前だけ）", "",
           f"知識ベースの {n_entries} + {n_comps} 項目のうち、上に出なかったもの。依存定義が入力に無い・別の名前で入っている場合はここに落ちる。"
           "心当たりのあるものは知識ベース本体（`references/implicit-endpoints.json` / `references/parser-components.json`）を ID で検索する。", "",
           "- 暗黙のエンドポイント: " + (", ".join(e["id"] for e in entries if e["id"] not in hit_i) or "なし"),
           "- 部品: " + (", ".join(c["id"] for c in comps if c["id"] not in hit_c) or "なし"), ""]
    path = run / "work" / "knowledge.md"
    path.write_text("\n".join(md) + "\n", encoding="utf-8")
    return path
