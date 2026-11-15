"""スクリプト共通の小道具。解析はしない（帳簿付けだけ）。標準ライブラリのみ。"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.dont_write_bytecode = True  # スキルのフォルダに __pycache__ を作らない


def utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def read_text(path: Path) -> str:
    data = path.read_bytes()
    for enc in ("utf-8-sig", "cp932", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def load_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    """(レコード, 読めなかった行の説明)。壊れた行があっても止めない。"""
    rows: list[dict] = []
    errors: list[str] = []
    try:
        text = read_text(path)
    except OSError as exc:
        return rows, [f"{path}: 読めません ({exc})"]
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip().rstrip(",")
        if not s or s in ("[", "]") or s.startswith("//") or s.startswith("```"):
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{n}: JSON として読めません ({exc.msg})")
            continue
        if isinstance(obj, dict):
            obj["_src"] = f"{path.name}:{n}"
            rows.append(obj)
        elif isinstance(obj, list):
            for o in obj:
                if isinstance(o, dict):
                    o["_src"] = f"{path.name}:{n}"
                    rows.append(o)
    return rows, errors


def load_run(run: Path) -> tuple[dict, dict]:
    work = run / "work"
    inv_path = work / "inventory.json"
    if not inv_path.exists():
        sys.exit(f"ERROR: {inv_path} がありません。先に inventory.py を実行してください。")
    inventory = json.loads(inv_path.read_text(encoding="utf-8"))
    units = json.loads((work / "units.json").read_text(encoding="utf-8")) if (work / "units.json").exists() else {"units": []}
    return inventory, units


def resolve(base_dir: str, file: str) -> Path:
    """記録上のパス（プロジェクトルートからの相対、または絶対）を実パスにする。"""
    p = Path(file)
    return p if p.is_absolute() else Path(base_dir) / file


def norm_file(file: str) -> str:
    return str(file).replace("\\", "/").lstrip("./") if not re.match(r"^[A-Za-z]:|^/", str(file)) else str(file).replace("\\", "/")


def short_file(file: str, inventory: dict) -> str:
    """表示用: 入力ルートより上の部分を落とす（入力がプロジェクト外にあると絶対パスが長くなるため）。"""
    f = norm_file(file)
    root = str(inventory.get("input_root", "")).replace("\\", "/").rstrip("/")
    if root and f.lower().startswith(root.lower() + "/") and re.match(r"^[A-Za-z]:|^/", root):
        return f[len(root) + 1:]
    return f


def as_list(v) -> list:
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def squash(s: str) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()


# ---------------------------------------------------------------- 検出項目の正規化と突き合わせ
#
# 同じ対象を別の人が別の書き方で記録しても 1 件として扱えるようにする。
#   URL で表せる入口         … ソース・メソッド・正規化したパスで照合（ホストは、両方に書いてあれば一致が必要）
#   ホスト名 / ポート         … ホスト名、ポート番号で照合
#   受け口・解釈点            … 根拠 1 件目が同じ箇所（同じ行か同じ引用）を指すかで照合
#   それ以外（RPC・ジョブ・Server Action・資格情報の所在など、識別子の書き方が揺れるもの）
#                             … 識別子が同じ、または根拠 1 件目が同じ箇所で識別子に共通の語がある

KIND_GROUP = {
    "http": "http", "page": "http", "static": "http", "proxy": "http", "api": "http", "rest": "http",
    "websocket": "ws", "ws": "ws", "sse": "ws",
    "graphql": "graphql", "grpc": "rpc", "rpc": "rpc",
    "port": "port", "cloud": "cloud", "host": "host",
    "event": "event", "job": "event", "queue": "event", "cron": "event",
    "protocol": "protocol",
}
ANCHOR_KINDS = {"input-channel", "parser"}
LAYER_OF = {"input-channel": "受け口", "parser": "解釈点"}
_URL_PREFIX = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//([^/?#]*)(.*)$")


def kind_of(f: dict) -> str:
    return str(f.get("kind", "") or "other").lower().strip()


def layer_of(f: dict) -> str:
    return LAYER_OF.get(kind_of(f), "入口")


def split_host(path: str) -> tuple[str, str]:
    """`https://host:port/path` → ("host:port", "/path")。URL でなければ ("", path)。"""
    p = str(path or "").strip()
    m = _URL_PREFIX.match(p)
    if m:
        return m.group(1).lower(), m.group(2) or "/"
    return "", p


def host_of(f: dict) -> str:
    h = str(f.get("host", "") or "").strip().lower()
    h = re.sub(r"^(?:[a-z][a-z0-9+.\-]*:)?//", "", h).rstrip("/")
    return h or split_host(f.get("path", ""))[0]


_HOST_HEAD = re.compile(r"^([a-z0-9](?:[a-z0-9\-.]*[a-z0-9])?(?::\d{1,5})?)(?=$|[\s/,、（(])")
_FQDN = re.compile(r"(?<![\w.\-])((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z][a-z0-9\-]*[a-z0-9](?::\d{1,5})?)(?![\w\-])")


def clean_host(text) -> tuple[str, list[str], str]:
    """host 欄の記述を (ホスト名, ほかのホスト名, ホスト名として読めなかった記述) に分ける。

    host 欄に説明や複数のホストが書かれていても照合が壊れないようにするためのもの。
    ホスト名として読めない記述（「(Docker ホスト):8025」「shop-api（コンテナ網の内側）」）は host を空にして、記述を返す。
    """
    raw = squash(text)
    s = re.sub(r"^(?:[a-z][a-z0-9+.\-]*:)?//", "", raw.lower()).rstrip("/")
    if not s:
        return "", [], ""
    m = _HOST_HEAD.match(s)
    if not m:
        return "", [], raw
    host, rest = m.group(1), s[m.end():]
    if not rest.strip(" /,、"):
        return host, [], ""
    others = [h for h in dict.fromkeys(_FQDN.findall(rest)) if h != host]
    leftover = _FQDN.sub("", rest).strip(" /,、()（）")
    if leftover and "." not in host:
        return "", [], raw  # 先頭の語がホスト名とは限らない（「docker ホスト」など）
    return host, others, (raw if leftover else "")


def norm_path(path: str) -> str:
    p = split_host(path)[1]
    p = p.split("?", 1)[0]
    p = re.sub(r"\{[^{}]*\*\}", "{*}", p)
    p = re.sub(r"\{[^{}*]*\}", "{}", p)
    p = re.sub(r"(?<=/):[A-Za-z_]\w*", "{}", p)
    p = re.sub(r"<[^<>/]+>", "{}", p)
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1:
        p = p.rstrip("/")
    return p.lower()


def curly_path(path: str) -> str:
    """パスの可変部分の書き方を `{name}` に揃える（`:id`、`<int:id>` → `{id}`）。"""
    p = re.sub(r"(?<=/):([A-Za-z_]\w*)", r"{\1}", str(path or ""))
    return re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", p)


def port_of(f: dict) -> str:
    m = re.search(r"(\d{1,5})\s*/\s*(tcp|udp)", str(f.get("path", "")), re.I)
    if m:
        return f"{int(m.group(1))}/{m.group(2).lower()}"
    m = re.search(r"(\d{2,5})(?!.*\d)", str(f.get("path", "")))
    return f"{int(m.group(1))}/tcp" if m else norm_path(f.get("path", ""))


def is_url_item(f: dict) -> bool:
    kind = kind_of(f)
    return KIND_GROUP.get(kind, kind) in ("http", "ws") and norm_path(f.get("path", "")).startswith("/") and "#" not in str(f.get("path", ""))


def first_evidence(f: dict) -> tuple[str, int, str]:
    ev = f.get("evidence")
    for e in ([ev] if isinstance(ev, dict) else ev or []):
        if isinstance(e, dict) and e.get("file"):
            line = e.get("line")
            return norm_file(e["file"]), line if isinstance(line, int) else 0, squash(e.get("quote", ""))
    return "", 0, ""


def anchor(f: dict) -> tuple | None:
    """受け口・解釈点の突き合わせ用の位置 (source, kind, file, line, quote)。それ以外の種別は None。"""
    kind = kind_of(f)
    if kind not in ANCHOR_KINDS:
        return None
    file, line, quote = first_evidence(f)
    if not file:
        return None
    return (str(f.get("source", "")).strip().lower(), kind, file, line, quote)


SAME_QUOTE_WINDOW = 3  # 引用が同じでも、これより離れた行は別の箇所（check.py が根拠を照合する幅と同じ）


def same_spot(line_a: int, quote_a: str, line_b: int, quote_b: str) -> bool:
    """同じファイル内の 2 つの根拠が同じ箇所を指しているか。

    行が同じ、または近い行で引用が同じなら同じ箇所。隣り合う別の行（app.use(a) と app.use(b)）は別の箇所として扱う。
    同じ文の行が離れた場所に何度も出てくるファイル（設定見本の `apikey = "…"`、`return response.json();`）では、
    引用が同じでも行が離れていれば別の箇所。行番号が書かれていない根拠は、引用だけで比べる。
    """
    if line_a and line_a == line_b:
        return True
    if quote_a and quote_b:
        if quote_a == quote_b:
            return not line_a or not line_b or abs(line_a - line_b) <= SAME_QUOTE_WINDOW
        if abs(line_a - line_b) <= 2 and min(len(quote_a), len(quote_b)) >= 12 and (quote_a in quote_b or quote_b in quote_a):
            return True
    return False


def ident_tokens(s: str) -> set[str]:
    """識別子に含まれる「意味のある語」（4 文字以上の語と数字）。camelCase は分ける。"""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(s or ""))
    return {t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if len(t) >= 4 or t.isdigit()}


_CATEGORY = re.compile(r"^\s*([a-z][a-z0-9+_.\-]{1,24})\s*:(?!//)")
_MANIFEST = re.compile(
    r"(?i)(^|/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|constraints\.txt|pyproject\.toml|pipfile(\.lock)?|setup\.(py|cfg)|"
    r"gemfile(\.lock)?|[^/]+\.gemspec|composer\.(json|lock)|pom\.xml|build\.gradle(\.kts)?|libs\.versions\.toml|go\.(mod|sum)|cargo\.(toml|lock)|"
    r"mix\.exs|pubspec\.yaml|[^/]+\.(cs|fs|vb)proj|packages\.config|directory\.packages\.props|dockerfile[^/]*)$"
)


def category_of(f: dict) -> str:
    """受け口・解釈点の識別子の `種類:`（body: / cookie: / xml: など）。規約どおりでなければ空。"""
    m = _CATEGORY.match(str(f.get("path", "") or "").lower())
    return m.group(1) if m else ""


def is_manifest(file: str) -> bool:
    """依存を宣言するファイルか。1 つの行（依存の宣言）が複数の別の仕組みの根拠になり得る。"""
    return bool(_MANIFEST.search(str(file or "")))


def same_mechanism(a: dict, b: dict, file: str) -> bool:
    """同じ箇所を根拠にする受け口・解釈点どうしが、同じ仕組みを指しているか。

    識別子の `種類:` が同じなら同じ仕組み。依存の宣言行は、1 行が別々の仕組み（Server Actions と画像最適化など）の
    根拠になるので、種類が一致するときだけ同じとみなす。コードの行は、種類が書かれていないか共通の語があれば同じとみなす。
    """
    ca, cb = category_of(a), category_of(b)
    if ca and cb and ca == cb:
        return True
    if is_manifest(file):
        return False
    if not ca or not cb:
        return True
    return bool(ident_tokens(a.get("path", "")) & ident_tokens(b.get("path", "")))


_ROLE_PREFIX = re.compile(r"^\s*(outbound|inbound|secret)\s*:", re.I)


def role_of(f: dict) -> str:
    """識別子の接頭辞のうち、向きや性質を表すもの（outbound: / inbound: / secret:）。無ければ空。

    送信と、その応答の取り込み。資格情報の所在と、それを使う処理。どちらも同じ行を根拠にすることがあるが、別の対象。
    """
    m = _ROLE_PREFIX.match(str(f.get("path", "") or ""))
    return m.group(1).lower() if m else ""


def _ident_words(f: dict) -> set[str]:
    """根拠の位置が同じ項目どうしを「同じ対象」とみなすための語。向きや性質の接頭辞そのもの（secret など）は数えない。"""
    return ident_tokens(_ROLE_PREFIX.sub("", str(f.get("path", "") or ""), count=1)) | ident_tokens(f.get("handler", ""))


def finding_key(f: dict) -> tuple:
    """照合用の鍵 (source, 種別の系統, メソッド, 識別子)。ホストは含めない（Index が別に照合する）。"""
    kind = kind_of(f)
    source = str(f.get("source", "")).strip().lower()
    a = anchor(f)
    if a is not None:
        return (source, kind, "", f"{a[2]}:{a[3]}:{category_of(f)}")
    group = KIND_GROUP.get(kind, kind)
    if group == "host":
        h = host_of(f) or norm_path(f.get("path", ""))
        return (source, "host", "", re.sub(r":\d+$", "", h.strip("/")))
    if group == "port":
        return (source, "port", "", port_of(f))
    method = str(f.get("method", "") or "").upper().strip()
    if is_url_item(f):
        return (source, group, method, norm_path(f.get("path", "")))
    ident = re.sub(r"\s+", " ", str(f.get("path", "") or "")).strip().lower()
    return (source, group, method, ident)


def loose_key(f: dict) -> tuple:
    """メソッドを無視した鍵（ANY と個別メソッドを突き合わせるため）。受け口・解釈点はファイル単位。"""
    a = anchor(f)
    if a is not None:
        return (a[0], a[1], a[2])
    k = finding_key(f)
    return (k[0], k[1], k[3])


def hosts_compatible(a: dict, b: dict) -> bool:
    ha, hb = host_of(a), host_of(b)
    return not ha or not hb or ha == hb


def methods_compatible(a: dict, b: dict) -> bool:
    ma, mb = str(a.get("method", "") or "").upper(), str(b.get("method", "") or "").upper()
    return ma == mb or not ma or not mb


class Index:
    """検出項目の集合。find() で「同じ対象を指す既存の項目」を引く。"""

    def __init__(self) -> None:
        self.by_key: dict[tuple, list[dict]] = defaultdict(list)
        self.by_file: dict[tuple, list[dict]] = defaultdict(list)  # (source, layer, file) → 項目
        self.items: list[dict] = []

    def find(self, f: dict) -> dict | None:
        a = anchor(f)
        if a is not None:
            for it in self.by_file.get((a[0], layer_of(f), a[2]), []):
                b = anchor(it)
                if b is not None and b[1] == a[1] and same_spot(a[3], a[4], b[3], b[4]) and same_mechanism(f, it, a[2]):
                    return it
            return None
        mine_ev = first_evidence(f)
        for it in self.by_key.get(finding_key(f), []):
            its_ev = first_evidence(it)
            same_place = bool(mine_ev[0]) and mine_ev[0] == its_ev[0] and same_spot(mine_ev[1], mine_ev[2], its_ev[1], its_ev[2])
            # 中継（プロキシの設定）と、アプリ自身の入口は、同じパスでも別の対象。根拠が同じ箇所のときだけ同じとみなす
            if (kind_of(f) == "proxy") != (kind_of(it) == "proxy") and not same_place:
                continue
            if hosts_compatible(f, it):
                return it
            # ホストの書き方だけが違う同じ定義（根拠が同じ箇所を指す）。別の箇所で定義された同じパスは別の対象
            its_ev = first_evidence(it)
            if mine_ev[0] and mine_ev[0] == its_ev[0] and same_spot(mine_ev[1], mine_ev[2], its_ev[1], its_ev[2]):
                return it
        if is_url_item(f) or KIND_GROUP.get(kind_of(f), kind_of(f)) in ("host", "port", "graphql"):
            return None
        # 識別子の書き方が揺れる種別: 根拠が同じ箇所を指し、識別子に共通の語があれば同じ対象とみなす。
        # ただし、向きや性質の接頭辞（outbound: / inbound: / secret:）が食い違うものは別の対象として残す
        # （外部への送信とその応答、資格情報の所在とそれを使うワークフローは、同じ行を根拠にしても別物）
        file, line, quote = first_evidence(f)
        if not file:
            return None
        mine, role = _ident_words(f), role_of(f)
        for it in self.by_file.get((str(f.get("source", "")).strip().lower(), "入口", file), []):
            if is_url_item(it) or anchor(it) is not None or not methods_compatible(f, it) or role_of(it) != role:
                continue
            _f2, line2, quote2 = first_evidence(it)
            if same_spot(line, quote, line2, quote2) and (mine & _ident_words(it)):
                return it
        return None

    def add(self, f: dict) -> None:
        self.items.append(f)
        if anchor(f) is None:
            self.by_key[finding_key(f)].append(f)
        file = first_evidence(f)[0]
        if file:
            self.by_file[(str(f.get("source", "")).strip().lower(), layer_of(f), file)].append(f)


# ---------------------------------------------------------------- 統合

CONF_RANK = {"high": 3, "medium": 2, "low": 1}
PRIO_RANK = {"high": 3, "medium": 2, "low": 1}
LIST_FIELDS = ("tags", "flags", "params", "fed_by", "reaches", "consumes", "also_hosts", "calls")
NOTE_MAX_PARTS, NOTE_MAX_CHARS, CONSUMES_MAX = 3, 600, 10


def _bigrams(s: str) -> set[str]:
    s = re.sub(r"\s+", "", str(s or "").lower())
    return {s[i:i + 2] for i in range(len(s) - 1)}


def similar(new: str, old: str, threshold: float = 0.6) -> bool:
    """new の内容が old にほぼ含まれているか（同じことの言い換えを重ねて残さないため）。"""
    a = _bigrams(new)
    return not a or len(a & _bigrams(old)) / len(a) >= threshold


def add_note(cur: dict, text: str) -> None:
    """備考を足す。言い換えは足さず、長さに上限を設ける（元の記録はパスごとのファイルに残っている）。"""
    text = squash(text)
    have = str(cur.get("notes", "") or "")
    if not text or text in have or (have and similar(text, have)):
        return
    if cur.get("_notes_n", 1 if have else 0) >= NOTE_MAX_PARTS or len(have) + len(text) > NOTE_MAX_CHARS:
        cur["_notes_dropped"] = cur.get("_notes_dropped", 0) + 1
        return
    cur["_notes_n"] = cur.get("_notes_n", 1 if have else 0) + 1
    cur["notes"] = (have + " / " + text).strip(" /")


def prepare(r: dict) -> dict:
    """統合前の整形（元の dict は変更しない）。"""
    r = {k: v for k, v in r.items() if not k.startswith("_")}
    r["method"] = str(r.get("method", "") or "").upper().strip()
    r["kind"] = kind_of(r)
    r["evidence"] = [e for e in as_list(r.get("evidence")) if isinstance(e, dict)]
    for k in LIST_FIELDS:
        r[k] = as_list(r.get(k))
    # host 欄は「ホスト名 1 つ」に揃える。説明や複数のホストが書かれていたら、読める分だけ取り出して残りは備考へ
    if r.get("host") not in (None, ""):
        host, others, leftover = clean_host(r["host"])
        r["host"] = host
        r["also_hosts"] = list(dict.fromkeys([*map(str, r["also_hosts"]), *others]))
        if leftover:
            add_note(r, f"host 欄の記述: {leftover}")
    if KIND_GROUP.get(r["kind"], r["kind"]) == "host":
        # ホスト名そのものの項目は path がホスト。host 欄は使わない
        h = host_of(r)
        if h:
            r["path"] = h
        r["host"] = ""
    if is_url_item(r):
        host, path = split_host(r.get("path", ""))
        if host:
            r["path"] = path
            r.setdefault("host", host)
            if not r.get("host"):
                r["host"] = host
        r["path"] = curly_path(r["path"])
        if r.get("internal_path"):
            r["internal_path"] = curly_path(r["internal_path"])
    if is_url_item(r):
        # パスに現れる変数は、書かれていなくてもパラメータとして補う（機械的に決まるため）
        have = {str(p.get("name")) for p in r["params"] if isinstance(p, dict) and p.get("in") == "path"}
        for name in re.findall(r"\{([A-Za-z_][\w\-]*)\*?\}", str(r.get("path", ""))):
            if name not in have:
                have.add(name)
                r["params"].append({"name": name, "in": "path", "required": True})
    r["_first_files"] = [first_evidence(r)[0]] if first_evidence(r)[0] else []
    r.setdefault("_spellings", [])
    r["_spellings"] = [f"{r['kind']} {r['method']} {r.get('path', '')}".replace("  ", " ").strip()]
    return r


def absorb(cur: dict, r: dict) -> None:
    """r を cur に合算する。"""
    seen = {(norm_file(e.get("file", "")), e.get("line")) for e in cur["evidence"]}
    for e in r["evidence"]:
        if (norm_file(e.get("file", "")), e.get("line")) not in seen:
            cur["evidence"].append(e)
    for k in ("tags", "flags", "fed_by", "reaches", "calls"):
        merged = list(dict.fromkeys([*map(str, cur[k]), *map(str, r[k])]))
        cur[k] = sorted(merged) if k in ("tags", "flags") else merged
    cur["consumes"] = list(map(str, cur["consumes"]))
    for c in map(str, r["consumes"]):
        if len(cur["consumes"]) < CONSUMES_MAX and not any(similar(c, have, 0.75) for have in cur["consumes"]):
            cur["consumes"].append(c)
    if len(cur["fed_by"]) > 1:
        cur["fed_by"] = [x for x in cur["fed_by"] if x not in ("不明", "unknown")] or cur["fed_by"]
    have = {(p.get("name"), p.get("in")): p for p in cur["params"] if isinstance(p, dict)}
    for p in r["params"]:
        if not isinstance(p, dict):
            continue
        mine = have.get((p.get("name"), p.get("in")))
        if mine is None:
            cur["params"].append(p)
            have[(p.get("name"), p.get("in"))] = p
        else:  # 同じ項目: 片方にしか無い情報（必須か、型、出どころ、補足）を補う
            for k in ("required", "type", "source", "note"):
                if mine.get(k) in (None, "") and p.get(k) not in (None, ""):
                    mine[k] = p[k]
    fb = [x for x in str(cur.get("found_by", "")).split("+") if x]
    fb += [x for x in str(r.get("found_by", "")).split("+") if x and x not in fb]
    cur["found_by"] = "+".join(fb)
    for ff in r.get("_first_files", []):
        if ff not in cur.setdefault("_first_files", []):
            cur["_first_files"].append(ff)
    for s in r.get("_spellings", []):
        if s not in cur.setdefault("_spellings", []):
            cur["_spellings"].append(s)
    if CONF_RANK.get(r.get("confidence"), 0) > CONF_RANK.get(cur.get("confidence"), 0):
        cur["confidence"] = r["confidence"]
    if PRIO_RANK.get(r.get("priority"), 0) > PRIO_RANK.get(cur.get("priority"), 0):
        cur["priority"], cur["priority_reason"] = r.get("priority"), r.get("priority_reason", cur.get("priority_reason", ""))
    # 認証: 証拠のある判断を優先。required と none が食い違ったら両方の根拠を残して印を付ける（人が決める）
    ca, ra = cur.get("auth", "unknown") or "unknown", r.get("auth", "unknown") or "unknown"
    if ra in ("required", "none"):
        if ca in ("unknown", "n/a", ""):
            cur["auth"], cur["auth_evidence"] = ra, r.get("auth_evidence", "")
        elif ca != ra:
            if "AUTH_CONFLICT" not in cur["flags"]:
                cur["flags"] = sorted([*cur["flags"], "AUTH_CONFLICT"])
            both = f"[{ca}] {cur.get('auth_evidence', '')} ／ [{ra}] {r.get('auth_evidence', '')}"
            if str(r.get("auth_evidence", "")) not in str(cur.get("auth_evidence", "")):
                cur["auth_evidence"] = both
        elif not cur.get("auth_evidence") and r.get("auth_evidence"):
            cur["auth_evidence"] = r["auth_evidence"]  # 同じ判断の言い換えは重ねない
    if cur.get("reach") in (None, "", "unknown") and r.get("reach"):
        cur["reach"] = r["reach"]
    # ホスト: 片方だけに書かれていれば採用。両方に別のホストが書かれていれば（同じ定義が複数のホストで公開されている）、ほかのホストとして残す
    if KIND_GROUP.get(kind_of(cur), kind_of(cur)) != "host":
        hc, hr = host_of(cur), host_of(r)
        also = [*map(str, cur["also_hosts"]), *map(str, r["also_hosts"])]
        if not hc and hr:
            cur["host"] = hc = r.get("host") or hr
        elif hc and hr and hc != hr:
            also.append(hr)
        cur["also_hosts"] = [h for h in dict.fromkeys(also) if h and h != hc]
    for k in ("summary", "handler", "auth_evidence", "priority_reason", "component", "parses", "scope", "internal_path"):
        if not cur.get(k) and r.get(k):
            cur[k] = r[k]
    add_note(cur, r.get("notes", ""))


def merge_rows(rows: list[dict]) -> list[dict]:
    """同じ対象を 1 件に統合する。"""
    index = Index()
    for raw in rows:
        r = prepare(raw)
        cur = index.find(r)
        if cur is None:
            index.add(r)
        else:
            absorb(cur, r)
    return index.items


def stable_key(f: dict) -> str:
    """統合後の項目を指すための短い鍵。識別子（と根拠の位置）が変わらない限り、統合を繰り返しても同じ値になる。"""
    ident = "|".join(map(str, finding_key(f))) + "|" + ("" if anchor(f) is not None else host_of(f))
    return hashlib.sha1(ident.encode("utf-8")).hexdigest()[:8]


# ---------------------------------------------------------------- 補助ファイル（aliases / prefixes / overrides）

MATCH_KEYS = ("source", "kind", "method", "layer", "flag", "tag", "path", "path_regex", "key", "found_by", "host", "origin", "auth",
              "confidence", "priority", "reach", "file")


def matches(it: dict, cond: dict) -> bool:
    """補助ファイルの条件に項目が当たるか。条件はすべて満たす必要がある。値にリストを書くと「いずれか」。空の条件は全項目に当たる。"""
    paths = [squash(it.get("path", "")), squash(it.get("internal_path", ""))]
    for k, want in cond.items():
        if k.startswith("_") or want is None:
            continue
        wants = [str(w) for w in (want if isinstance(want, list) else [want])]
        low = [w.lower() for w in wants]
        if k == "source":
            ok = str(it.get("source", "")).lower() in low
        elif k == "kind":
            ok = kind_of(it) in low
        elif k == "method":
            ok = str(it.get("method", "") or "").upper() in [w.upper() for w in wants]
        elif k == "layer":
            ok = layer_of(it) in wants
        elif k == "flag":
            ok = any(w in as_list(it.get("flags")) for w in wants)
        elif k == "tag":
            ok = any(w in as_list(it.get("tags")) for w in wants)
        elif k == "path":
            ok = any(squash(w) in paths for w in wants)
        elif k == "path_regex":
            try:
                ok = any(p and re.search(w, p) for w in wants for p in paths)
            except re.error:
                ok = False
        elif k == "key":
            ok = str(it.get("key", "")) in wants
        elif k == "found_by":
            ok = any(w in str(it.get("found_by", "")) for w in wants)
        elif k == "host":
            ok = host_of(it) in low
        elif k == "file":
            files = [norm_file(e.get("file", "")) for e in as_list(it.get("evidence")) if isinstance(e, dict)]
            ok = any(w.replace("\\", "/") in f for w in wants for f in files)
        elif k in ("origin", "auth", "confidence", "priority", "reach"):
            ok = str(it.get(k, "") or "").lower() in low
        else:
            ok = False  # 知らない条件は「当たらない」。merge.md の「当たらなかった行」に出る
        if not ok:
            return False
    return True


def apply_aliases(rows: list[dict], aliases: list[dict]) -> tuple[list[dict], list[tuple[dict, str]], Counter]:
    """書き方違いの寄せ直しと取り下げ。(残った行, [(取り下げた行, 理由)], 当たった回数)。rows は書き換える。"""
    hits: Counter = Counter()
    dropped: list[tuple[dict, str]] = []
    kept: list[dict] = []
    for r in rows:
        drop_reason = None
        for i, al in enumerate(aliases):
            cond = dict(al.get("from") or {})
            if al.get("source"):
                cond.setdefault("source", al["source"])
            if not matches(r, cond):
                continue
            hits[i] += 1
            if "drop" in al:
                drop_reason = str(al["drop"])
            else:
                for k, v in (al.get("to") or {}).items():
                    if k == "anchor" and isinstance(v, dict):
                        # 根拠の 1 件目だけを付け替える（照合の位置を直す）。元の根拠は 2 件目以降に残す
                        rest = [e for e in as_list(r.get("evidence")) if isinstance(e, dict)
                                and not (norm_file(e.get("file", "")) == norm_file(v.get("file", "")) and e.get("line") == v.get("line"))]
                        r["evidence"] = [v, *rest]
                    else:
                        r[k] = v
            break
        if drop_reason is not None:
            dropped.append((r, drop_reason))
        else:
            kept.append(r)
    return kept, dropped, hits


def apply_prefixes(rows: list[dict], prefixes: list[dict]) -> Counter:
    """ソース内のパスを、外から見える公開パスに付け替える。rows は書き換える。"""
    hits: Counter = Counter()
    for r in rows:
        if not is_url_item(r) or r.get("internal_path"):
            continue
        cands = [(i, p) for i, p in enumerate(prefixes)
                 if str(p.get("source", "")).lower() == str(r.get("source", "")).lower() and p.get("prefix")
                 and norm_path(r.get("path", "")).startswith(norm_path(p.get("under", "/")).rstrip("/") or "/")]
        if not cands:
            continue
        i, p = max(cands, key=lambda c: len(str(c[1].get("under", "/"))))
        prefix = "/" + str(p["prefix"]).strip("/")
        url_host, path = split_host(str(r.get("path", "")))
        hits[i] += 1
        if not clean_host(r.get("host", ""))[0]:
            if r.get("host"):
                add_note(r, f"host 欄の記述: {squash(r['host'])}")
            r["host"] = url_host or p.get("host") or ""
        if norm_path(path) == norm_path(prefix) or norm_path(path).startswith(norm_path(prefix) + "/"):
            continue  # すでに公開パスで書かれている
        r["internal_path"] = curly_path(path)
        r["path"] = prefix + (path if path.startswith("/") else "/" + path)
        if isinstance(p.get("evidence"), dict):
            ev = as_list(r.get("evidence"))
            if all(not (isinstance(e, dict) and e.get("file") == p["evidence"].get("file") and e.get("line") == p["evidence"].get("line")) for e in ev):
                r["evidence"] = ev + [p["evidence"]]
    return hits


# ---------------------------------------------------------------- 秘密情報の検知とマスク

_SECRET_PATTERNS = [
    (re.compile(r"(://)([^/\s:@]+):(?!\$|\{|<|%|(?:password|passwd|pass|secret|token|changeme|x{3,}|\.{3})@)([^@\s/*]{3,})@(?!example\.)"), r"\1\2:***@"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "eyJ***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"), "-----BEGIN PRIVATE KEY----- ***"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{30,})"), "***"),
    # 引用符つきの値: password = "…" / "api_key": "…" / Authorization: 'Bearer …'
    (
        re.compile(
            r"""(?i)((?:pass(?:word|wd)?|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|client[_\-]?secret|authorization)\w*["']?\s*[:=]\s*)"""
            r"""(["'])(?!\*{3})(?!required|optional|password|undefined|string\b|\$\{|\{\{|<)([^"'\n]{8,})\2"""
        ),
        r"\1\2***\2",
    ),
    # 環境変数・YAML 形式の裸の値: DB_PASSWORD=… / SECRET_KEY: …
    (
        re.compile(
            r"""\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\s*[:=]\s*)(?!\*{3})(?![A-Za-z_]\w*[.(\[])([^\s"'$<{*(\[][^\s"',;()\[\]]{7,})"""
        ),
        r"\1***",
    ),
    (re.compile(r"(?i)\b(bearer\s+)(?!\*{3})([A-Za-z0-9_\-.=]{16,})"), r"\1***"),
]


def mask_secrets(text: str) -> tuple[str, int]:
    """秘密情報らしき値を *** に置き換える。戻り値 (置換後, 置換数)。"""
    if not isinstance(text, str) or not text:
        return text, 0
    total = 0
    for rx, repl in _SECRET_PATTERNS:
        text, n = rx.subn(repl, text)
        total += n
    return text, total


def mask_obj(obj):
    """dict / list を再帰的に辿ってマスクする。戻り値 (新しいオブジェクト, 置換数)。"""
    if isinstance(obj, str):
        return mask_secrets(obj)
    if isinstance(obj, list):
        out, total = [], 0
        for v in obj:
            nv, n = mask_obj(v)
            out.append(nv)
            total += n
        return out, total
    if isinstance(obj, dict):
        out, total = {}, 0
        for k, v in obj.items():
            nv, n = mask_obj(v)
            out[k] = nv
            total += n
        return out, total
    return obj, 0
