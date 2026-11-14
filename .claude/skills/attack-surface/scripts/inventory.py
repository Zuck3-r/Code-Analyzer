#!/usr/bin/env python3
"""Input の棚卸しと、読む単位（ユニット）への分割案を作る。

解析はしない。「何がどれだけあるか」を数え、読み手に割り振れる形に並べるだけ。
ここで付けるティア（A/B/C）は読む順序と深さの目安で、対象から外す判断ではない。

使い方:
  python inventory.py [--input Input] [--output Output] [--run 名前] [--extract]
  python inventory.py --refresh RUN        # units.json を手で直した後に、ユニット別一覧を作り直して検査する
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tarfile
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
from _common import utf8_stdout  # noqa: E402
import kb  # noqa: E402

# 個々のファイルを一覧に出さず、まとめて数えるだけにするディレクトリ（依存物・VCS・キャッシュ）
PRUNE = {
    ".git": "VCS の履歴", ".hg": "VCS の履歴", ".svn": "VCS の履歴",
    "node_modules": "npm の依存物", "bower_components": "依存物", "jspm_packages": "依存物",
    ".venv": "Python 仮想環境", "venv": "Python 仮想環境", "site-packages": "Python の依存物", "__pycache__": "キャッシュ",
    ".gradle": "ビルドキャッシュ", ".terraform": "Terraform のプロバイダ", "Pods": "CocoaPods の依存物", ".dart_tool": "キャッシュ",
    ".mypy_cache": "キャッシュ", ".pytest_cache": "キャッシュ", ".ruff_cache": "キャッシュ", ".tox": "キャッシュ",
    ".yarn": "依存物キャッシュ", ".pnpm-store": "依存物キャッシュ", ".bundle": "依存物", ".cache": "キャッシュ",
}
VENDOR_MARKERS = ("composer.json", "go.mod", "Gemfile")
BUILD_DIRS = {"dist", "build", "out", "target", "bin", "obj", ".next", ".nuxt", ".output", ".svelte-kit", "coverage", "storybook-static", ".vercel", ".netlify", "_site"}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".psd", ".avif", ".heic",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg", ".webm", ".flac", ".mkv",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".ear", ".apk", ".ipa", ".aar", ".whl", ".nupkg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".pyo", ".o", ".a", ".lib", ".wasm", ".node",
    ".db", ".sqlite", ".sqlite3", ".bin", ".dat", ".keystore", ".jks", ".p12", ".pfx", ".der",
}
ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz")
LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "gemfile.lock", "poetry.lock", "cargo.lock", "go.sum", "packages.lock.json", "uv.lock", "bun.lockb", "pubspec.lock", "podfile.lock"}
MANIFESTS = {
    "package.json", "requirements.txt", "pyproject.toml", "pipfile", "setup.py", "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "gemfile", "composer.json", "cargo.toml", "mix.exs", "pubspec.yaml", "dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "compose.yml", "compose.yaml", "serverless.yml", "serverless.yaml", "template.yaml", "template.yml",
    "vercel.json", "netlify.toml", "firebase.json", "wrangler.toml", "fly.toml", "render.yaml", "procfile", "app.yaml",
    "androidmanifest.xml", "info.plist", "web.xml", "chart.yaml", "kustomization.yaml", "makefile", "nginx.conf",
}
LANG = {
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".vue": "Vue", ".svelte": "Svelte", ".py": "Python", ".rb": "Ruby", ".php": "PHP", ".go": "Go", ".rs": "Rust", ".java": "Java",
    ".kt": "Kotlin", ".scala": "Scala", ".cs": "C#", ".fs": "F#", ".vb": "VB", ".swift": "Swift", ".m": "Objective-C", ".dart": "Dart",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".c": "C", ".h": "C/C++", ".cpp": "C++", ".cc": "C++", ".pl": "Perl", ".lua": "Lua",
    ".sh": "Shell", ".ps1": "PowerShell", ".sql": "SQL", ".tf": "Terraform", ".proto": "Protobuf", ".graphql": "GraphQL", ".gql": "GraphQL",
    ".html": "HTML", ".htm": "HTML", ".erb": "ERB", ".cshtml": "Razor", ".jsp": "JSP", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
    ".toml": "TOML", ".xml": "XML", ".md": "Markdown", ".conf": "Config", ".ini": "Config", ".properties": "Config", ".env": "Config",
    ".cls": "Apex", ".abap": "ABAP", ".cob": "COBOL", ".cbl": "COBOL", ".groovy": "Groovy", ".clj": "Clojure", ".hs": "Haskell", ".r": "R",
}
# 入口に直結しやすい名前（ティア A の目安）。読む順序のヒントであり、これに当たらないファイルも読む
TIER_A = re.compile(
    r"(rout|controller|handler|endpoint|(^|[/_.\-])api([/_.\-]|$)|server|(^|/)(app|main|index|program|startup|application|bootstrap)\.|urls?\.py|views?[/_.]|resource|servlet|"
    r"action|middleware|auth|secur|guard|filter|gateway|proxy|webhook|graphql|resolver|schema|rpc|socket|channel|consumer|listener|"
    r"subscriber|worker|(^|[/_.\-])jobs?([/_.\-]|$)|task|cron|schedul|command|(^|[/_.\-])cli([/_.\-]|$)|config|setting|(^|/)\.env|docker|compose|k8s|kube|helm|"
    r"chart|deploy|terraform|\.tf$|\.tfvars$|nginx|apache|httpd|caddy|haproxy|traefik|envoy|ingress|serverless|cloudformation|"
    r"(^|/)cdk|pulumi|vercel|netlify|firebase|wrangler|fly\.toml|procfile|openapi|swagger|postman|insomnia|\.proto$|\.graphqls?$|"
    r"\.gql$|\.http$|\.rest$|\.har$|\.wsdl$|readme|manifest|package\.json|requirements|pyproject|pom\.xml|build\.gradle|go\.mod|"
    r"gemfile|composer\.json|\.csproj|cargo\.toml|mix\.exs|pubspec|info\.plist|web\.xml|struts|\.htaccess|\.github/workflows|"
    r"\.gitlab-ci|jenkinsfile|azure-pipelines|bitbucket-pipelines|makefile|\.rules$|rules\.json|cors|csrf|session|token|oauth|saml|"
    r"upload|download|import|export|admin|debug|internal|health|metric|migrat|seed|\.sql$|interceptor|plugin|hook|trigger|lambda|function)",
    re.I,
)
GENERATED = re.compile(rb"(?i)code generated|@generated|do not edit|auto-?generated|generated by")


def _ext(name: str) -> str:
    lower = name.lower()
    for multi in (".tar.gz", ".blade.php", ".d.ts", ".min.js", ".min.css"):
        if lower.endswith(multi):
            return multi
    i = lower.rfind(".")
    return lower[i:] if i > 0 else ""


def safe_extract(archive: Path, dest: Path) -> tuple[int, str]:
    """zip / tar を dest に展開する。パス逸脱・リンク・巨大展開を拒否する。戻り値 (ファイル数, エラー)。"""
    limit_bytes, limit_files = 2_000_000_000, 200_000
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    count = total = 0
    try:
        if archive.name.lower().endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    target = (dest / info.filename).resolve()
                    if root not in target.parents or (info.external_attr >> 16) & 0o170000 == 0o120000:
                        continue
                    total += info.file_size
                    count += 1
                    if total > limit_bytes or count > limit_files:
                        return count, "展開サイズまたはファイル数が上限を超えたため途中で打ち切り"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, open(target, "wb") as out:
                        while chunk := src.read(1 << 20):
                            out.write(chunk)
        else:
            with tarfile.open(archive) as tf:
                for member in tf:
                    if not member.isfile():
                        continue
                    target = (dest / member.name).resolve()
                    if root not in target.parents:
                        continue
                    total += member.size
                    count += 1
                    if total > limit_bytes or count > limit_files:
                        return count, "展開サイズまたはファイル数が上限を超えたため途中で打ち切り"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    src = tf.extractfile(member)
                    if src is not None:
                        with open(target, "wb") as out:
                            while chunk := src.read(1 << 20):
                                out.write(chunk)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError) as exc:
        return count, f"展開に失敗: {exc}"
    return count, ""


def rel_to(base: Path, p: Path) -> str:
    try:
        return p.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def classify(path: Path, rel_in_source: str, size: int, in_build: bool) -> dict:
    name = path.name
    ext = _ext(name)
    info = {"ext": ext, "lang": LANG.get(ext, ""), "lines": 0, "text": True, "tier": "B", "why": ""}
    if ext in BINARY_EXT or ext in ARCHIVE_EXT:
        info.update(text=False, tier="C", why="アーカイブ（--extract で展開可）" if ext in ARCHIVE_EXT else "バイナリ")
        return info
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
            if b"\x00" in head:
                info.update(text=False, tier="C", why="バイナリ")
                return info
            rest = fh.read(6_000_000) if size <= 6_000_000 else b""
    except OSError:
        info.update(text=False, tier="C", why="読み取り不可")
        return info
    data = head + rest
    info["lines"] = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    lower = name.lower()
    avg = (len(data) / max(1, info["lines"])) if data else 0
    if lower in LOCK_NAMES:
        info.update(tier="C", why="ロックファイル")
    elif ext == ".map":
        info.update(tier="C", why="ソースマップ（元ソースを含むことがある）")
    elif ext in (".min.js", ".min.css") or (size > 20_000 and avg > 500 and ext in (".js", ".mjs", ".cjs", ".css")):
        info.update(tier="C", why="minify 済み（埋め込まれたパス・URL は検索で確認する価値あり）")
    elif size > 1_500_000:
        info.update(tier="C", why="巨大ファイル")
    elif in_build:
        info.update(tier="C", why="ビルド成果物のディレクトリ")
    elif GENERATED.search(head[:600]):
        info.update(tier="C", why="自動生成の表記あり（生成されたルート定義・スタブの可能性は残る）")
    elif ext in (".svg", ".css", ".scss", ".less", ".snap", ".po", ".pot", ".csv", ".tsv"):
        info.update(tier="C", why="スタイル・データ類")
    elif TIER_A.search(rel_in_source):
        info.update(tier="A", why="")
    return info


def walk_source(name: str, root: Path, base: Path) -> tuple[list[dict], dict]:
    files: list[dict] = []
    meta = {"name": name, "root": rel_to(base, root), "files": 0, "bytes": 0, "languages": {}, "manifests": [], "has_git": False, "pruned": []}
    if root.is_file():
        info = classify(root, root.name, root.stat().st_size, False)
        files.append({"path": rel_to(base, root), "source": name, "size": root.stat().st_size, **info})
        return files, meta
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        rel_dir = d.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for sub in sorted(dirnames):
            why = PRUNE.get(sub)
            if sub == "vendor" and any((d / m).exists() for m in VENDOR_MARKERS):
                why = "依存物 (vendor)"
            if why is None:
                if not (d / sub).is_symlink():
                    keep.append(sub)
                continue
            if sub == ".git":
                meta["has_git"] = True
            n = b = 0
            for dp, _dn, fn in os.walk(d / sub):
                for f in fn:
                    n += 1
                    if n <= 50_000:
                        try:
                            b += os.path.getsize(os.path.join(dp, f))
                        except OSError:
                            pass
            meta["pruned"].append({"dir": rel_to(base, d / sub), "why": why, "files": n, "bytes": b})
        dirnames[:] = keep
        in_build = any(part in BUILD_DIRS for part in rel_dir.split("/")) if rel_dir else False
        for fn in sorted(filenames):
            p = d / fn
            if p.is_symlink():
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            rel_in_source = f"{rel_dir}/{fn}" if rel_dir else fn
            info = classify(p, rel_in_source, size, in_build)
            files.append({"path": rel_to(base, p), "source": name, "size": size, **info})
            if fn.lower() in MANIFESTS or fn.lower().endswith((".csproj", ".tf", ".sln")):
                if len(meta["manifests"]) < 60:
                    meta["manifests"].append(rel_to(base, p))
    for f in files:
        meta["files"] += 1
        meta["bytes"] += f["size"]
        if f["lang"] and f["tier"] != "C":
            meta["languages"][f["lang"]] = meta["languages"].get(f["lang"], 0) + 1
    meta["languages"] = dict(sorted(meta["languages"].items(), key=lambda kv: -kv[1]))
    return files, meta


def cost(f: dict) -> tuple[float, float]:
    """(読む量の目安バイト, ファイル数の目安)。ティア C は流し読みなので軽く数える。"""
    if f["tier"] == "C" or not f["text"]:
        return min(f["size"], 1500), 0.15
    return f["size"], 1.0


def make_units(files: list[dict], kb: int, max_files: int) -> list[dict]:
    units: list[dict] = []
    budget = kb * 1024
    by_source: dict[str, list[dict]] = {}
    for f in files:
        by_source.setdefault(f["source"], []).append(f)
    # 小さいソースは 1 人の読み手にまとめる（ソースごとに読み手を立てると、読む量より段取りの方が重くなる）
    small = [s for s, fl in by_source.items()
             if sum(cost(x)[0] for x in fl) < budget * 0.35 and sum(cost(x)[1] for x in fl) < max_files * 0.35]
    if len(small) >= 2:
        cur: list[dict] = []
        cur_b = cur_n = 0.0
        names: list[str] = []
        for s in small:
            fl = sorted(by_source.pop(s), key=lambda x: x["path"])
            b, n = sum(cost(x)[0] for x in fl), sum(cost(x)[1] for x in fl)
            if cur and (cur_b + b > budget * 0.8 or cur_n + n > max_files * 0.8):
                units.append({"source": " + ".join(names), "files": [x["path"] for x in cur]})
                cur, cur_b, cur_n, names = [], 0.0, 0.0, []
            cur += fl
            cur_b += b
            cur_n += n
            names.append(s)
        if cur:
            units.append({"source": " + ".join(names), "files": [x["path"] for x in cur]})
    for source, flist in by_source.items():
        by_dir: dict[str, list[dict]] = {}
        for f in sorted(flist, key=lambda x: x["path"]):
            by_dir.setdefault(os.path.dirname(f["path"]), []).append(f)
        cur: list[dict] = []
        cur_b = cur_n = 0.0

        def flush() -> None:
            nonlocal cur, cur_b, cur_n
            if cur:
                units.append({"source": source, "files": [x["path"] for x in cur]})
            cur, cur_b, cur_n = [], 0.0, 0.0

        for d in sorted(by_dir):
            dfiles = by_dir[d]
            db = sum(cost(x)[0] for x in dfiles)
            dn = sum(cost(x)[1] for x in dfiles)
            if cur and (cur_b + db > budget or cur_n + dn > max_files):
                flush()
            if db > budget or dn > max_files:  # 1 ディレクトリが大きすぎる → ファイル単位で詰める
                for x in dfiles:
                    b, n = cost(x)
                    if cur and (cur_b + b > budget or cur_n + n > max_files):
                        flush()
                    cur.append(x)
                    cur_b += b
                    cur_n += n
            else:
                cur.extend(dfiles)
                cur_b += db
                cur_n += dn
        flush()
    for i, u in enumerate(units, 1):
        u["id"] = f"u{i:03d}"
    return units


def describe_units(units: list[dict], files_by_path: dict[str, dict]) -> None:
    for u in units:
        fl = [files_by_path[p] for p in u["files"] if p in files_by_path]
        common = os.path.commonpath([os.path.dirname(p) or "." for p in u["files"]]) if u["files"] else ""
        u["label"] = common.replace("\\", "/")
        u["n_files"] = len(u["files"])
        u["tiers"] = {t: sum(1 for x in fl if x["tier"] == t) for t in "ABC"}
        u["est_tokens"] = int(sum(cost(x)[0] for x in fl) / 3.2)


def write_unit_lists(work: Path, units: list[dict], files_by_path: dict[str, dict]) -> None:
    udir = work / "units"
    udir.mkdir(parents=True, exist_ok=True)
    for old in udir.glob("*.txt"):
        old.unlink()
    for u in units:
        lines = [f"# ユニット {u['id']}  ソース: {u['source']}  ファイル数: {len(u['files'])}",
                 "# ティア\t行数\tパス（このパスをそのまま開き、根拠にもこのパスを書く）",
                 "# 検出項目の source 欄には、そのファイルが属するソース名（下の「# ソース:」の名前）を書く"]
        last_source = None
        for p in u["files"]:
            f = files_by_path.get(p, {})
            if f.get("source") != last_source:
                last_source = f.get("source")
                lines.append(f"# ソース: {last_source}")
            why = f"\t# {f['why']}" if f.get("why") else ""
            lines.append(f"{f.get('tier', '?')}\t{f.get('lines', 0)}\t{p}{why}")
        (udir / f"{u['id']}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_units(units: list[dict], files_by_path: dict[str, dict]) -> list[str]:
    problems: list[str] = []
    seen: dict[str, str] = {}
    for u in units:
        for p in u.get("files", []):
            if p in seen:
                problems.append(f"{p} が {seen[p]} と {u.get('id')} の両方に入っています")
            seen[p] = u.get("id", "?")
            if p not in files_by_path:
                problems.append(f"{p}（{u.get('id')}）は棚卸しに無いパスです")
    missing = [p for p in files_by_path if p not in seen]
    if missing:
        problems.append(f"どのユニットにも入っていないファイルが {len(missing)} 件あります（例: {', '.join(missing[:5])}）")
    return problems


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def write_summary(work: Path, inv: dict, units: list[dict]) -> None:
    files = inv["files"]
    root = str(inv.get("input_root", "")).rstrip("/")

    def show(p: str) -> str:  # 表示用: 入力がプロジェクト外にあるとき、入力ルートより上を省く
        return p[len(root) + 1:] if root and re.match(r"^[A-Za-z]:|^/", root) and p.startswith(root + "/") else p

    out = ["# 入力の棚卸し", "", f"- 入力: `{inv['input_root']}`", f"- 作成: {inv['created']}",
           f"- ファイル: {len(files)} 件 / {human(sum(f['size'] for f in files))}",
           f"- ティア: A {sum(1 for f in files if f['tier'] == 'A')} / B {sum(1 for f in files if f['tier'] == 'B')} / C {sum(1 for f in files if f['tier'] == 'C')}"
           "（A: 入口に直結しそう、B: 通常のコード、C: 生成物・依存物・バイナリなど流し読みでよさそうなもの。目安であり、読んで違えば変える）",
           f"- 読む量の見込み: 約 {sum(u['est_tokens'] for u in units):,} トークン / {len(units)} ユニット", ""]
    out += ["## ソース", "", "| ソース | ファイル | サイズ | 主な言語 | .git | 依存マニフェスト・構成ファイル |", "|---|---:|---:|---|---|---|"]
    for s in inv["sources"]:
        langs = ", ".join(f"{k} {v}" for k, v in list(s["languages"].items())[:5]) or "-"
        mans = "<br>".join(f"`{show(m)}`" for m in s["manifests"][:12]) + (" ほか" if len(s["manifests"]) > 12 else "")
        out.append(f"| {s['name']} | {s['files']} | {human(s['bytes'])} | {langs} | {'あり' if s['has_git'] else '-'} | {mans or '-'} |")
    pruned = [(s["name"], p) for s in inv["sources"] for p in s["pruned"]]
    if pruned:
        out += ["", "## 一覧から外してまとめて数えたディレクトリ", "",
                "依存物や履歴で、個々のファイルは読む対象にしていない。依存ライブラリが生やす入口は「暗黙エンドポイント」として別に拾う。", "",
                "| ディレクトリ | 理由 | ファイル数 | サイズ |", "|---|---|---:|---:|"]
        for _name, p in pruned[:80]:
            out.append(f"| `{p['dir']}` | {p['why']} | {p['files']} | {human(p['bytes'])} |")
    if inv.get("notes"):
        out += ["", "## 注意", ""] + [f"- {n}" for n in inv["notes"]]
    total_tokens = sum(u["est_tokens"] for u in units)
    scale = "小" if total_tokens < 60_000 else "中" if total_tokens < 600_000 else "大"
    out += ["", f"## 規模: {scale}", "",
            f"読む量の見込みは約 {total_tokens:,} トークン。SKILL.md の「規模に応じた進め方」の **{scale}** の欄に従って、読み手と探し手の人数を決める。"]
    out += ["", "## ユニット（読む単位の分割案）", "", "各ユニットのファイル一覧は `units/<ID>.txt`。", "",
            "| ID | ソース | 範囲 | ファイル | A/B/C | 見込みトークン |", "|---|---|---|---:|---|---:|"]
    for u in units:
        t = u["tiers"]
        out.append(f"| {u['id']} | {u['source']} | `{show(u['label']) or '.'}` | {u['n_files']} | {t['A']}/{t['B']}/{t['C']} | {u['est_tokens']:,} |")
    (work / "inventory.md").write_text("\n".join(out) + "\n", encoding="utf-8")


def refresh(run: Path) -> int:
    work = run / "work"
    inv = json.loads((work / "inventory.json").read_text(encoding="utf-8"))
    data = json.loads((work / "units.json").read_text(encoding="utf-8"))
    units = data["units"] if isinstance(data, dict) else data
    files_by_path = {f["path"]: f for f in inv["files"]}
    for i, u in enumerate(units, 1):
        u.setdefault("id", f"u{i:03d}")
        u.setdefault("source", files_by_path.get((u.get("files") or [""])[0], {}).get("source", ""))
    problems = validate_units(units, files_by_path)
    describe_units(units, files_by_path)
    (work / "units.json").write_text(json.dumps({"units": units}, ensure_ascii=False, indent=1), encoding="utf-8")
    write_unit_lists(work, units, files_by_path)
    write_summary(work, inv, units)
    kb.write_knowledge(run, inv)
    print(f"units={len(units)} problems={len(problems)}")
    for p in problems:
        print("PROBLEM:", p)
    return 0


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="Input")
    ap.add_argument("--output", default="Output")
    ap.add_argument("--run", default="")
    ap.add_argument("--extract", action="store_true", help="入力直下の zip / tar を作業ディレクトリに展開して対象に含める")
    ap.add_argument("--unit-kb", type=int, default=180, help="1 ユニットの読む量の目安 (KB)")
    ap.add_argument("--unit-files", type=int, default=60, help="1 ユニットのファイル数の目安")
    ap.add_argument("--refresh", metavar="RUN", default="")
    args = ap.parse_args()
    if args.refresh:
        return refresh(Path(args.refresh))

    base = Path.cwd()
    input_root = Path(args.input)
    if not input_root.exists():
        print(f"ERROR: input not found: {input_root}")
        return 2
    entries = sorted(p for p in input_root.iterdir() if p.name not in (".gitkeep", ".DS_Store", "Thumbs.db", "README.md") or p.is_dir())
    if not entries:
        print("EMPTY: 入力が空です。解析したいリポジトリのフォルダ（または zip）を入力フォルダの直下に置いてください。1 フォルダ = 1 ソースとして扱います。")
        return 3

    run_name = args.run or dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run = Path(args.output) / run_name
    work = run / "work"
    work.mkdir(parents=True, exist_ok=True)

    notes: list[str] = []
    sources: list[tuple[str, Path]] = []
    loose: list[Path] = []
    for p in entries:
        lower = p.name.lower()
        if p.is_dir():
            sources.append((p.name, p))
        elif lower.endswith(ARCHIVE_EXT) and args.extract:
            stem = re.sub(r"\.(zip|tar\.gz|tgz|tar)$", "", p.name, flags=re.I)
            dest = work / "extracted" / stem
            n, err = safe_extract(p, dest)
            if err:
                notes.append(f"`{p.name}`: {err}")
            if n:
                inner = [x for x in dest.iterdir()]
                root = inner[0] if len(inner) == 1 and inner[0].is_dir() else dest
                sources.append((stem, root))
                notes.append(f"`{p.name}` を `{rel_to(base, dest)}` に展開して対象に含めた（{n} ファイル）")
        else:
            if lower.endswith(ARCHIVE_EXT):
                notes.append(f"`{p.name}` はアーカイブ。中身を対象にするには --extract を付けて実行する")
            loose.append(p)

    files: list[dict] = []
    metas: list[dict] = []
    used: set[str] = set()
    for name, root in sources:
        base_name, k = name, 2
        while name in used:
            name = f"{base_name}-{k}"
            k += 1
        used.add(name)
        fl, meta = walk_source(name, root, base)
        files += fl
        metas.append(meta)
    if loose:
        meta = {"name": "(直下のファイル)", "root": rel_to(base, input_root), "files": 0, "bytes": 0, "languages": {}, "manifests": [], "has_git": False, "pruned": []}
        for p in loose:
            info = classify(p, p.name, p.stat().st_size, False)
            files.append({"path": rel_to(base, p), "source": meta["name"], "size": p.stat().st_size, **info})
            meta["files"] += 1
            meta["bytes"] += p.stat().st_size
        metas.append(meta)

    for m in metas:
        if m["has_git"]:
            notes.append(f"`{m['name']}` には .git がある。履歴や別ブランチにだけ残る入口を調べる余地がある（読み取りのみ）")
    big = [f for f in files if f["tier"] != "C" and f["size"] > 400_000]
    for f in big[:20]:
        notes.append(f"`{f['path']}` は大きい（{human(f['size'])}）。読み手を単独で割り当てるか、分けて読む")

    files_by_path = {f["path"]: f for f in files}
    units = make_units(files, args.unit_kb, args.unit_files)
    describe_units(units, files_by_path)
    inv = {
        "run": run_name, "created": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "base_dir": str(base.resolve()),
        "input_root": rel_to(base, input_root), "sources": metas, "files": files, "notes": notes,
    }
    (work / "inventory.json").write_text(json.dumps(inv, ensure_ascii=False, indent=1), encoding="utf-8")
    (work / "units.json").write_text(json.dumps({"units": units}, ensure_ascii=False, indent=1), encoding="utf-8")
    write_unit_lists(work, units, files_by_path)
    write_summary(work, inv, units)
    for sub in ("pass1", "pass2", "check"):
        (work / sub).mkdir(exist_ok=True)

    # 知識ベースのうち、この入力に関係する項目の抜粋（読み手・探し手は知識ベース全体ではなくこれを読む）
    found = kb.scan(inv)
    kb.write_knowledge(run, inv, found)
    print(f"sources={len(metas)} files={len(files)} units={len(units)} est_tokens={sum(u['est_tokens'] for u in units)}")
    print(f"summary={rel_to(base, work / 'inventory.md')}")
    print(f"knowledge={rel_to(base, work / 'knowledge.md')} implicit={sum(len(v) for v in found['implicit'].values())} components={sum(len(v) for v in found['components'].values())}")
    print(f"RUN={rel_to(base, run)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
