#!/usr/bin/env python3
"""調査の「穴」を機械的に探す。解析はしない。

  1. 成果物の無いユニット
  2. 読了記録の無いファイル（誰も読んでいないファイル）
  3. 入口らしい記述があるのに、検出項目が 1 件も無いファイル
  4. 解釈処理らしい記述があるのに、検出項目が 1 件も無いファイル / 近くに受け口・解釈点の根拠が無い行
  5. 知識ベースに手がかりのあるもののうち、検出項目で触れられていないもの
       5a 受け取り・解釈を担う部品（parser-components.json）
       5b 暗黙に存在し得るエンドポイント（implicit-endpoints.json）
  6. 証跡の不一致（ファイルが無い / 行が範囲外 / 引用がその付近に無い）と、形式・記法の不備
  7. 出力に紛れ込んだ秘密情報らしき値
  8. --diff: パス 1 とパス 2 以降の突き合わせ（aliases.jsonl / prefixes.jsonl があれば適用してから比べる）
  9. --verify: 3 層（入口・受け口・解釈点）のつながりの欠け

使い方:
  python check.py RUN            # 1〜7（対象は work/pass*/ の全項目）
  python check.py RUN --diff     # 1〜8
  python check.py RUN --verify   # final.findings.jsonl を対象に 5〜7 と 9 を行う（出力前の最終照合）

結果は RUN/work/check/report.md（--verify のときは verify.md）。標準出力には要約だけを出す。
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
    ANCHOR_KINDS, KIND_GROUP, Index, anchor, apply_aliases, apply_prefixes, as_list, category_of, clean_host, finding_key, first_evidence, hosts_compatible,
    is_manifest, is_url_item, layer_of, load_jsonl, load_run, loose_key, mask_secrets, norm_file, norm_path, prepare, read_text, resolve, same_spot,
    squash, utf8_stdout,
)
import kb  # noqa: E402

REQUIRED = ("source", "kind", "path", "summary", "origin", "evidence", "auth", "confidence", "found_by")
AUTH = {"required", "none", "unknown", "n/a"}
CONF = {"high", "medium", "low"}

# 「入口がありそう」という目印。言語を問わない緩いパターンで、誤報は承知のうえ（確認するのは人 = AI）
HINTS: list[tuple[str, re.Pattern]] = [
    ("ルート定義らしい行", re.compile(
        r"""(?i)\b(get|post|put|patch|delete|head|options|all|any|route|router|mapping|path|url|endpoint|handle\w*|mount|use|register|resources?|scope|namespace|group|location|rewrite|redirect|forward)\b[^\n]{0,60}["'`]/[\w\-{}:<>\[\]./*$@]*["'`]"""
    )),
    ("ルーティング用の注釈", re.compile(
        r"""@(?:Get|Post|Put|Patch|Delete|Request)Mapping|@(?:Get|Post|Put|Delete|Patch|Head|Options|All|Path|Route|Controller|RestController|WebServlet|MessageMapping|SubscribeMessage|Query|Mutation|Resolver|KafkaListener|RabbitListener|SqsListener|JmsListener|Scheduled|EventPattern|MessagePattern)\b|@\w+\.(?:route|get|post|put|delete|patch|websocket|task)\(|\[(?:Http(?:Get|Post|Put|Delete|Patch)|Route|Authorize|AllowAnonymous|WebMethod|FunctionName|Function)\b|#\[(?:get|post|put|delete|patch|route)\(|\b(?:api_view|action|shared_task|login_required|csrf_exempt)\b"""
    )),
    # ファイルの置き場所や決まった名前の export がそのまま入口になるもの（ルート文字列がコードに現れない）
    ("ファイル規約のハンドラ", re.compile(
        r"""^\s*export\s+(?:async\s+)?(?:function\s+|const\s+)(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ALL|loader|action|load|actions|handler|onRequest\w*|getServerSideProps|getStaticProps|middleware)\b|"""
        r"""^\s*export\s*\{[^}]*\bas\s+(?:GET|POST|PUT|PATCH|DELETE)\b|^\s*export\s+default\s+(?:async\s+)?function\s+\w*\s*\(\s*(?:req|request|event|context)\b|"""
        r"""^\s*["']use server["']|\bdefineEventHandler\s*\(|\bdefineWebSocketHandler\s*\(|\bexports\.handler\s*=|^\s*def\s+(?:lambda_)?handler\s*\(\s*event\b|"""
        r"""\baddEventListener\(\s*["']fetch["']|^\s*export\s+default\s*\{\s*(?:async\s+)?fetch\b|\bfunctions\.https\.on(?:Request|Call)\b|\bon(?:Request|Call)\s*\(""",
        re.M,
    )),
    ("インフラ上の露出", re.compile(
        r"""(?i)\b(?:listen|expose|containerPort|hostPort|nodePort|targetPort|server_name|proxy_pass|fastcgi_pass|ProxyPass|reverse_proxy|ingress|loadBalancer|0\.0\.0\.0/0|cidr_blocks|public-read|allUsers|AuthorizationType|authorizer|function_url|FunctionUrl|httpApi|http_method|route_key|rewrites|redirects)\b|^\s*ports\s*:"""
    )),
    ("外部への呼び出し", re.compile(
        r"""\b(?:fetch|axios|XMLHttpRequest|HttpClient|RestTemplate|WebClient|URLSession|Alamofire|Retrofit|OkHttp|Guzzle|HTTParty|Faraday|urlopen)\b|\brequests\.(?:get|post|put|delete|patch|request)\(|\bhttp\.(?:Get|Post|NewRequest)\(|\bcurl\s+-"""
    )),
    ("URL リテラル", re.compile(r"""\b(?:https?|wss?)://[\w.\-{}$%:]+""")),
    ("非 HTTP の入口", re.compile(
        r"""(?i)\b(?:WebSocket|socket\.on|\.subscribe\(|consumer|onmessage|addEventListener\(\s*["']message|handle_in|ipcMain|registerHandler|deeplink|intent-filter|cron|schedule\(|createServer|\.listen\(|bind\(|accept\()"""
    )),
    # GraphQL のスキーマ / リゾルバ、gRPC・RPC のサービス定義、WebSocket のサーバ側ハンドラ
    ("GraphQL・RPC・WebSocket の定義", re.compile(
        r"""^\s*(?:extend\s+)?type\s+(?:Query|Mutation|Subscription)\b|^\s*schema\s*\{|^\s*rpc\s+\w+\s*\(|^\s*service\s+\w+\s*\{|"""
        r"""\b(?:typeDefs|resolvers|buildSchema|makeExecutableSchema|GraphQLObjectType|graphqlHTTP|ApolloServer|createYoga|gql`|"""
        r"""publicProcedure|protectedProcedure|WebSocketServer|WebSocketGateway|websocket_urlpatterns|AsyncWebsocketConsumer|"""
        r"""ActionCable|channel\s+["']|MapHub<|add_\w+Servicer_to_server|Register\w+Server\()""",
        re.M,
    )),
]
# 「値を解釈していそう」という目印。受け口・解釈点の見落とし候補を挙げるためのもの
PARSER_HINTS: list[tuple[str, re.Pattern]] = [
    ("デシリアライズ", re.compile(
        r"""\b(?:pickle|cPickle|dill|marshal|shelve|jsonpickle)\.loads?\(|\byaml\.(?:load|unsafe_load|full_load|load_all)\(|\bMarshal\.load\b|\bYAML\.(?:load|unsafe_load)\b|\bunserialize\s*\(|"""
        r"""\bObjectInputStream\b|\.readObject\s*\(|\bXMLDecoder\b|\bXStream\b|\bBinaryFormatter\b|\bLosFormatter\b|\bNetDataContractSerializer\b|\bTypeNameHandling\b|"""
        r"""\benableDefaultTyping\b|\bactivateDefaultTyping\b|\bOj\.load\b|\bgob\.NewDecoder\b|\bnode-serialize\b|\bphar://"""
    )),
    ("式・コードの評価", re.compile(
        r"""(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w+|Script)\b|(?<![.\w])exec\s*\(\s*(?!["'])\w|\binstance_eval\b|\bclass_eval\b|\bSpelExpressionParser\b|\bparseExpression\s*\(|"""
        r"""\bOgnl\.\w+|\bMVEL\.\w+|\bScriptEngine\b|\bGroovyShell\b|\bCSharpScript\b|\bassert\s*\(\s*\$_|\bcreate_function\b|\bpreg_replace\s*\([^)]*/e"""
    )),
    ("外部コマンド", re.compile(
        r"""(?<![.\w])(?:system|popen|passthru|shell_exec|proc_open|pcntl_exec)\s*\(|\bsubprocess\.\w+\(|\bos\.(?:system|popen|exec\w*)\(|\bchild_process\b|\bexecSync\b|\bexecFile\w*\(|(?<![.\w])spawn\w*\s*\(|"""
        r"""\bRuntime\.getRuntime\(\)\.exec\b|\bProcessBuilder\b|\bProcess\.Start\b|\bexec\.Command(?:Context)?\(|\bKernel\.(?:system|exec|spawn)\b|\bOpen3\.\w+|\bIO\.popen\b|`[^`\n]*\#\{[^`\n]*`|\bShellExecute\b"""
    )),
    ("テンプレートの描画", re.compile(
        r"""\brender_template_string\b|\bTemplate\s*\(\s*[a-z_]\w*\s*[,)]|\bfrom_string\s*\(|\bERB\.new\b|\bLiquid::Template\.parse\b|\b(?:ejs|pug|nunjucks|Handlebars|Mustache|Eta)\.(?:render|compile|renderString)\w*\(|"""
        r"""\bVelocity\.evaluate\b|\bnew\s+Template\s*\(|\bcreateTemplate\s*\(|\bTwig\\Environment\b.*createTemplate|\bRazorEngine\b|\btemplate\.Must\(|\btemplate\.New\("""
    )),
    ("XML の解釈", re.compile(
        r"""\bDocumentBuilder(?:Factory)?\b|\bSAXParser(?:Factory)?\b|\bXMLInputFactory\b|\bXMLReader\b|\bSAXReader\b|\bSAXBuilder\b|\bTransformerFactory\b|\bXmlDocument\b|\bXmlReader\.Create\b|\bXDocument\.(?:Load|Parse)\b|"""
        r"""\bXmlSerializer\b|\bsimplexml_load_\w+|\bDOMDocument\b|\bxml_parse\w*\(|\betree\.(?:parse|fromstring|XML|iterparse)\b|\bminidom\.\w+|\bxmltodict\.parse\b|\bparseString\s*\(|\bNokogiri::XML\b|\bREXML::\w+|"""
        r"""\bDOMParser\b|\bXMLParser\b|\bxml\.(?:Unmarshal|NewDecoder)\b|\bSAMLResponse\b|\bXSLT\w*\b"""
    )),
    ("画像・動画・文書の解析や変換", re.compile(
        r"""\bMiniMagick\b|\bRMagick\b|\bMagick::\w+|\bImagick\b|\bsharp\s*\(|\bImage\.open\s*\(|\bImageIO\.read\b|\bimagecreatefrom\w+|\bgetimagesize\b|\bexif_read_data\b|\bImage\.Load\w*\(|\bimage\.Decode\w*\(|"""
        r"""\b(?:ffmpeg|ffprobe|exiftool|ghostscript|libreoffice|soffice|wkhtmltopdf|pdftotext|pdftoppm|tesseract|unoconv|mutool|identify|mogrify)\b|\bpuppeteer\.launch\b|\bchromium\.launch\b|\bpage\.(?:goto|setContent|pdf|screenshot)\s*\(|"""
        r"""\bPdfReader\b|\bPDDocument\b|\bPDFParser\b|\bload_workbook\b|\bXSSFWorkbook\b|\bWorkbookFactory\b|\bPhpSpreadsheet\b|\bIOFactory::load\b|\bDocument\s*\(\s*\w+\s*\)\s*#?\s*docx"""
    )),
    ("アーカイブの展開", re.compile(
        r"""\bZipFile\b|\bZipArchive\b|\bZipInputStream\b|\bZipEntry\b|\.extractall\s*\(|\.extractTo\s*\(|\bextractAllTo\w*\(|\btarfile\.\w+|\bTarArchive\w*\b|\bTarInputStream\b|\bAdmZip\b|\bunzipper\b|\bzip\.(?:NewReader|OpenReader)\b|"""
        r"""\btar\.NewReader\b|\bZip::File\b|\bGem::Package\b|\bshutil\.unpack_archive\b|\bdecompress\s*\("""
    )),
    ("表計算・CSV・メールの解釈", re.compile(
        r"""\bcsv\.(?:reader|DictReader)\b|\bfgetcsv\b|\bstr_getcsv\b|\bCSV\.(?:parse|read|foreach|new)\b|\bCsvReader\b|\bCSVParser\b|\bpd\.read_(?:csv|excel|json|xml|html|pickle)\b|\bXLSX\.read\w*\(|"""
        r"""\bemail\.message_from_\w+|\bMimeMessage\b|\bMail\.read(?:_from_string)?\b|\bsimpleParser\s*\(|\bimap_\w+\(|\bIMAP4\w*\b|\bMimeKit\b"""
    )),
    ("入力で決まる宛先・パス・名前", re.compile(
        r"""\bfile_get_contents\s*\(\s*\$|\bcurl_setopt\s*\([^)]*CURLOPT_URL|\bURI\.open\b|\bopen-uri\b|\burlopen\s*\(|\burllib\.request\.\w+\(|\bconstantize\b|\bpublic_send\s*\(|\bsend\s*\(\s*params|\bClass\.forName\s*\(|"""
        r"""\b__import__\s*\(|\bimportlib\.import_module\b|\brequire\s*\(\s*(?!["'`])[A-Za-z_$]|\binclude(?:_once)?\s*\(?\s*\$|\brequire(?:_once)?\s*\(?\s*\$|\bcall_user_func(?:_array)?\s*\(|\bgetattr\s*\(\s*\w+\s*,\s*(?!["'])\w|"""
        r"""\bsendFile\s*\(|\bsend_file\s*\(|\bres\.download\s*\(|\bsend_from_directory\s*\(|\bFileResponse\s*\(|\breadFile\w*\s*\([^)]*\b(?:req|request|params|query|body)\b|\bldap_search\b|\.search_s\s*\(|\bDirectorySearcher\b"""
    )),
    ("トークンの検証", re.compile(
        r"""\bjwt\.(?:decode|verify)\s*\(|\bJWT\.decode\b|\bJwts\.parser\w*\b|\bparseClaimsJws\b|\bJwtSecurityTokenHandler\b|\bjose\.\w+Verify\b|\bjwtVerify\s*\(|\bgetUnverified\w+\(|\bdecode\s*\([^)]*verify\s*=\s*False"""
    )),
]
NOISY_EXT = {".md", ".txt", ".rst", ".lock", ".svg", ".css", ".scss", ".less", ".map", ".csv", ".snap"}

def load_dismissed(run: Path) -> set[tuple[str, str]]:
    """work/dismissed.jsonl に「確かめたうえで非該当」と記録されたもの。(source, 知識ベースの ID)"""
    out: set[tuple[str, str]] = set()
    dpath = run / "work" / "dismissed.jsonl"
    if dpath.exists():
        for d in load_jsonl(dpath)[0]:
            for key in ("component", "implicit", "id"):
                if d.get(key):
                    out.add((str(d.get("source", "")).lower(), str(d[key]).lower()))
    return out


def _mentioned(blob: str, word: str) -> bool:
    w = str(word).lower()
    if not w:
        return False
    if len(w) <= 4:
        return re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", blob) is not None
    return w in blob


def component_gaps(matched: dict, rows: list[dict], dismissed: set) -> tuple[list[dict], dict]:
    """手がかりの見つかった解釈部品のうち、受け口・解釈点の項目で触れられていないもの。"""
    blobs: dict[str, dict[str, str]] = defaultdict(lambda: defaultdict(str))  # source → kind → 項目の文面
    for r in rows:
        kind = str(r.get("kind", "")).lower()
        if kind in ANCHOR_KINDS or kind == "file-input":
            text = json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, ensure_ascii=False).lower()
            blobs[str(r.get("source", "")).lower()][kind] += "\n" + text
    gaps: list[dict] = []
    stat = {"present": 0, "mentioned": 0, "dismissed": 0}
    for source, found in matched.items():
        skey = source.lower()
        all_blob = "".join(blobs[skey].values())
        for x in found:
            comp, hits = x["item"], x["hits"]
            stat["present"] += 1
            layer = comp.get("layer", "parser")
            layer_blob = blobs[skey].get(layer, "") + blobs[skey].get("file-input", "")
            ok = any(_mentioned(all_blob, h[0].rsplit("/", 1)[-1]) for h in hits) or any(_mentioned(layer_blob, k) for k in comp.get("keywords", []))
            if ok:
                stat["mentioned"] += 1
            elif (skey, comp["id"].lower()) in dismissed:
                stat["dismissed"] += 1
            else:
                gaps.append({"source": source, "id": comp["id"], "category": comp.get("category", ""), "layer": layer, "hits": hits[:6],
                             "implies": comp.get("implies", ""), "note": comp.get("note", "")})
    return gaps, stat


def implicit_gaps(matched: dict, rows: list[dict], dismissed: set) -> tuple[list[dict], dict]:
    """手がかりの見つかった「暗黙のエンドポイント」の項目のうち、検出項目に 1 つも出てこないもの。"""
    paths: dict[str, list[str]] = defaultdict(list)
    blobs: dict[str, str] = defaultdict(str)   # 暗黙の仕組みとして書かれた項目の文面
    named: dict[str, set[str]] = defaultdict(set)  # kb 欄・タグに書かれた知識ベースの ID
    port_blobs: dict[str, str] = defaultdict(str)  # 全項目の識別子（ポート番号の言及を見る）
    cited: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))  # 項目が根拠にしている行（手がかりの行と照らす）
    for r in rows:
        skey = str(r.get("source", "")).lower()
        for p in (r.get("path"), r.get("internal_path")):
            if p:
                paths[skey].append(norm_path(str(p)))
        named[skey].update(str(x).lower() for x in [*as_list(r.get("kb")), *as_list(r.get("tags"))])
        port_blobs[skey] += f"\n{r.get('path', '')} {r.get('host', '')}"
        implicit = str(r.get("origin", "")).lower() == "implicit"
        if implicit:
            blobs[skey] += "\n" + json.dumps({k: r.get(k) for k in ("path", "summary", "handler", "component", "notes", "port")}, ensure_ascii=False).lower()
        for e in as_list(r.get("evidence")):
            # 手がかりが設定やコードの行なら、その行を根拠にした項目があれば言及とみなす。依存の宣言行は、暗黙の仕組みとして書かれた項目だけを数える
            if isinstance(e, dict) and e.get("file") and isinstance(e.get("line"), int) and (implicit or not is_manifest(norm_file(e["file"]))):
                cited[skey][norm_file(e["file"])].append(e["line"])
    gaps: list[dict] = []
    stat = {"present": 0, "mentioned": 0, "dismissed": 0}
    for source, found in matched.items():
        skey = source.lower()
        for x in found:
            it = x["item"]
            stat["present"] += 1
            tails = []
            for ep in it.get("endpoints", []):
                p = norm_path(str(ep.get("p", "")).split("?", 1)[0])
                p = re.sub(r"^(?:/?\{\})+", "", p)  # 先頭の {admin} {mount} などは組み込み先で変わる
                if p.startswith("/") and len(p.strip("/{}*")) >= 3:
                    tails.append(p)
            ports = [str(ep["port"]) for ep in it.get("endpoints", []) if ep.get("port")]
            # 言及の判定: kb 欄の ID / エンドポイントのパスの一致 / ポート番号 / 暗黙の仕組みの項目が、手がかりの行（の近く）を根拠にしている
            ok = it["id"].lower() in named[skey] or any(fp == t or fp.endswith(t) for t in tails for fp in paths[skey]) \
                or _mentioned(blobs[skey], it["id"]) or any(re.search(rf"(?<!\d){re.escape(pt)}(?!\d)", port_blobs[skey] + blobs[skey]) for pt in ports) \
                or any(ln and any(abs(ln - c) <= 3 for c in cited[skey].get(p, [])) for _n, p, ln, _v in x["hits"])
            if ok:
                stat["mentioned"] += 1
            elif (skey, it["id"].lower()) in dismissed:
                stat["dismissed"] += 1
            else:
                gaps.append({"source": source, "id": it["id"], "name": it.get("name", ""), "hits": x["hits"][:4],
                             "endpoints": [f"{ep.get('m', '')} {ep.get('p', '')}".strip() for ep in it.get("endpoints", [])]})
    return gaps, stat


HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def spec_operations(text: str) -> list[tuple[str, str]] | None:
    """OpenAPI / Swagger の文書から (メソッド, パス) を取り出す。仕様書でなければ None。JSON と YAML の両方に対応（YAML は字下げから読む）。"""
    head = text[:4000]
    if text.lstrip().startswith("{"):
        if not re.search(r'"(openapi|swagger)"\s*:', text) or not re.search(r'"paths"\s*:', text):
            return None
    elif not re.search(r"""(?im)^\s*["']?(openapi|swagger)["']?\s*:""", head) or not re.search(r"""(?m)^\s*["']?paths["']?\s*:""", text):
        return None
    ops: list[tuple[str, str]] = []
    if text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        base = str(doc.get("basePath", "") or "").rstrip("/")
        for path, item in (doc.get("paths") or {}).items():
            if isinstance(item, dict):
                ops += [(m.upper(), base + str(path)) for m in item if m.lower() in HTTP_METHODS]
        return ops
    base_m = re.search(r"""(?m)^basePath\s*:\s*["']?([^\s"'#]+)""", text)
    base = base_m.group(1).rstrip("/") if base_m else ""
    in_paths, path, path_indent = False, "", -1
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            in_paths = bool(re.match(r"""["']?paths["']?\s*:\s*$""", line.strip()))
            continue
        if not in_paths:
            continue
        m = re.match(r"""\s+["']?(/[^"':]*(?::[^"'/\s][^"':]*)*)["']?\s*:\s*(?:#.*)?$""", line)
        if m and (path_indent < 0 or indent <= path_indent):
            path, path_indent = m.group(1), indent
            continue
        m = re.match(r"""\s+["']?(\w+)["']?\s*:""", line)
        if m and path and indent > path_indent and m.group(1).lower() in HTTP_METHODS:
            ops.append((m.group(1).upper(), base + path))
    return ops


def spec_gaps(inventory: dict, rows: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """(見つけた仕様書, 仕様にあるのに一覧に無い操作, 一覧にあるのに仕様に無い入口)。パスは末尾の一致で比べる（接頭辞の付き方が違い得るため）。"""
    base = inventory["base_dir"]
    specs, missing, undocumented = [], [], []
    by_source: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for r in rows:
        for p in (r.get("path"), r.get("internal_path")):
            if p and str(p).lstrip().startswith(("/", "http")):
                by_source[str(r.get("source", "")).lower()].append((str(r.get("method", "") or "").upper(), norm_path(str(p))))

    def same(a: str, b: str) -> bool:
        return a == b or (len(b) > 1 and a.endswith(b)) or (len(a) > 1 and b.endswith(a))

    spec_ops: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for f in inventory["files"]:
        if not f.get("text") or f["ext"] not in (".json", ".yaml", ".yml") or f["size"] > 5_000_000:
            continue
        try:
            ops = spec_operations(read_text(resolve(base, f["path"])))
        except OSError:
            continue
        if ops is None:
            continue
        specs.append({"file": f["path"], "source": f["source"], "ops": len(ops)})
        spec_ops[f["source"].lower()] += [(m, norm_path(p)) for m, p in ops]
        for m, p in ops:
            np = norm_path(p)
            # 仕様書は別のソース（文書用のリポジトリ）に置かれることがあるので、全ソースの項目と比べる
            if not any(same(fp, np) and (fm == m or fm in ("ANY", "")) for found in by_source.values() for fm, fp in found):
                missing.append({"file": f["path"], "source": f["source"], "method": m, "path": p})
    all_spec = [op for ops in spec_ops.values() for op in ops]
    if all_spec:
        for r in rows:
            if str(r.get("kind", "")).lower() != "http" or str(r.get("origin", "")).lower() != "code" or "UNDOCUMENTED" in as_list(r.get("flags")):
                continue
            m, np = str(r.get("method", "") or "").upper(), norm_path(str(r.get("path", "")))
            ip = norm_path(str(r.get("internal_path", ""))) if r.get("internal_path") else np
            if not any((same(np, sp) or same(ip, sp)) and (sm == m or m in ("ANY", "")) for sm, sp in all_spec):
                undocumented.append(r)
    return specs, missing, undocumented


def collect(run: Path, verify: bool) -> tuple[dict[str, list[dict]], list[str], list[dict], list[str]]:
    """(パス名 → 検出項目, 読めなかった行, 読了記録, 見つけた findings ファイル名)"""
    work = run / "work"
    findings: dict[str, list[dict]] = defaultdict(list)
    errors: list[str] = []
    coverage: list[dict] = []
    names: list[str] = []
    if verify:
        fpath = work / "final.findings.jsonl"
        if not fpath.exists():
            sys.exit(f"ERROR: {fpath} がありません。採用する全項目をこのファイルにまとめてから --verify を実行してください。")
        rows, errs = load_jsonl(fpath)
        findings["final"] = rows
        errors += errs
        names.append(fpath.name)
    else:
        for d in sorted(p for p in work.iterdir() if p.is_dir() and re.fullmatch(r"pass\d+", p.name)):
            for fpath in sorted(d.rglob("*.findings.jsonl")):
                rows, errs = load_jsonl(fpath)
                for r in rows:
                    r["_file"] = f"{d.name}/{fpath.name}"
                findings[d.name] += rows
                errors += [f"{d.name}/{e}" for e in errs]
                names.append(f"{d.name}/{fpath.name}")
    for d in sorted(p for p in work.iterdir() if p.is_dir() and re.fullmatch(r"pass\d+", p.name)):
        for cpath in sorted(d.rglob("*.coverage.jsonl")):
            rows, errs = load_jsonl(cpath)
            for r in rows:
                r["_unit"] = cpath.name.split(".")[0]
            coverage += rows
            errors += [f"{d.name}/{e}" for e in errs]
    return findings, errors, coverage, names


def verify_evidence(rows: list[dict], base_dir: str) -> tuple[list[dict], list[dict]]:
    """(問題のある項目, 行番号を自動で直せる候補)"""
    problems: list[dict] = []
    fixable: list[dict] = []
    cache: dict[str, list[str] | None] = {}

    def lines_of(file: str) -> list[str] | None:
        if file not in cache:
            p = resolve(base_dir, file)
            try:
                cache[file] = read_text(p).splitlines() if p.is_file() else None
            except OSError:
                cache[file] = None
        return cache[file]

    for r in rows:
        ref = f"{r.get('_file', '')} {r.get('_src', '')}".strip()
        label = f"{r.get('method', '')} {r.get('path', '')}".strip() or "(path なし)"

        def bad(msg: str) -> None:
            problems.append({"ref": ref, "item": label, "source": r.get("source", ""), "problem": msg})

        missing = [k for k in REQUIRED if r.get(k) in (None, "", [])]
        if missing:
            bad("必須フィールドが無い: " + ", ".join(missing))
        if r.get("auth") and r["auth"] not in AUTH:
            bad(f"auth の値が不正: {r['auth']}（required / none / unknown）")
        if r.get("confidence") and r["confidence"] not in CONF:
            bad(f"confidence の値が不正: {r['confidence']}（high / medium / low）")
        ev = r.get("evidence")
        if isinstance(ev, dict):
            ev = [ev]
        if not isinstance(ev, list):
            continue
        for e in ev:
            if not isinstance(e, dict) or not e.get("file"):
                bad("evidence に file が無い")
                continue
            file = norm_file(e["file"])
            lines = lines_of(file)
            if lines is None:
                bad(f"根拠のファイルが存在しない: {file}")
                continue
            line = e.get("line")
            quote = squash(e.get("quote", ""))
            if not isinstance(line, int) or line < 1 or line > max(1, len(lines)):
                if quote:
                    hit = find_quote(lines, quote)
                    if len(hit) == 1:
                        fixable.append({"ref": ref, "file": file, "line": line, "correct": hit[0]})
                        continue
                bad(f"行番号が範囲外: {file}:{line}（全 {len(lines)} 行）")
                continue
            if not quote:
                bad(f"引用 (quote) が空: {file}:{line}")
                continue
            lo, hi = max(0, line - 4), min(len(lines), line + 3)
            if quote_in(squash(" ".join(lines[lo:hi])), quote):
                continue
            hit = find_quote(lines, quote)
            if len(hit) == 1:
                fixable.append({"ref": ref, "file": file, "line": line, "correct": hit[0]})
            elif hit:
                bad(f"引用が {file}:{line} 付近に無い（同じ文言が {len(hit)} か所: 行 {', '.join(map(str, hit[:6]))}）")
            else:
                bad(f"引用がファイル内に見つからない: {file}:{line} 「{quote[:70]}」")
    return problems, fixable


def quote_in(hay: str, quote: str) -> bool:
    """引用が含まれるか。`***`（伏せ字）と `…` `...`（省略）は任意の文字列に一致させる。"""
    parts = [p for p in re.split(r"\*{3,}|…|\.{3}", quote) if p.strip()]
    if not parts:
        return True
    pos = 0
    for part in parts:
        part = part.strip()
        idx = hay.find(part, pos)
        if idx < 0:
            return False
        pos = idx + len(part)
    return True


def find_quote(lines: list[str], quote: str) -> list[int]:
    first = next((p.strip() for p in re.split(r"\*{3,}|…|\.{3}", quote) if p.strip()), "")
    if len(first) < 6:
        return []
    hits = []
    for i, line in enumerate(lines, 1):
        if first in squash(line) and quote_in(squash(" ".join(lines[i - 1 : i + 2])), quote):
            hits.append(i)
    return hits


def silent_files(inventory: dict, rows: list[dict], cov_by_file: dict[str, dict], top: int) -> tuple[list[dict], list[dict], list[dict]]:
    """(入口らしい記述があるのに検出ゼロのファイル, 解釈処理らしい記述があるのに検出ゼロのファイル,
        検出のあるファイルの中で、解釈処理らしい行の近くに受け口・解釈点の根拠が無いもの)"""
    with_findings = set()
    anchor_lines: dict[str, list[int]] = defaultdict(list)  # ファイル → 受け口・解釈点の根拠がある行
    for r in rows:
        is_anchor = str(r.get("kind", "")).lower() in ANCHOR_KINDS
        ev = r.get("evidence")
        for e in ([ev] if isinstance(ev, dict) else ev or []):
            if isinstance(e, dict) and e.get("file"):
                with_findings.add(norm_file(e["file"]))
                if is_anchor and isinstance(e.get("line"), int):
                    anchor_lines[norm_file(e["file"])].append(e["line"])
    entry_like, parser_like, parser_lines = [], [], []
    base = inventory["base_dir"]
    for f in inventory["files"]:
        if not f.get("text") or f["tier"] == "C" or f["ext"] in NOISY_EXT or f["size"] > 800_000:
            continue
        try:
            lines = read_text(resolve(base, f["path"])).splitlines()
        except OSError:
            continue
        has_findings = f["path"] in with_findings
        is_test = bool(re.search(r"(^|/)(tests?|spec|__tests__|fixtures?|mocks?)(/|$)|[._](test|spec)\.", f["path"], re.I))
        kinds: Counter = Counter()
        where: list[int] = []
        pkinds: Counter = Counter()
        pwhere: list[int] = []
        for n, line in enumerate(lines, 1):
            if len(line) > 600:
                continue
            if not has_findings:
                for name, rx in HINTS:
                    if rx.search(line):
                        kinds[name] += 1
                        if len(where) < 8:
                            where.append(n)
                        break
            if re.match(r"\s*(?:#|//|\*|/\*|<!--|--\s)", line):
                continue  # コメント行は解釈処理の目印にしない
            for name, rx in PARSER_HINTS:
                if rx.search(line):
                    pkinds[name] += 1
                    if len(pwhere) < 8:
                        pwhere.append(n)
                    if has_findings and not is_test and not any(abs(n - a) <= 3 for a in anchor_lines.get(f["path"], [])):
                        parser_lines.append({"file": f["path"], "line": n, "kind": name, "text": squash(line)[:110]})
                    break
        if has_findings:
            continue
        cov = cov_by_file.get(f["path"], {})
        judged = cov.get("surface") is False and cov.get("status") == "read"
        strong = (kinds["ルート定義らしい行"] + kinds["ルーティング用の注釈"] + kinds["インフラ上の露出"] + kinds["非 HTTP の入口"]
                  + kinds["GraphQL・RPC・WebSocket の定義"] + kinds["ファイル規約のハンドラ"])
        score = strong * 3 + kinds["外部への呼び出し"] * 2 + kinds["URL リテラル"]
        if score >= 3:
            entry_like.append({"file": f["path"], "score": score, "kinds": dict(kinds), "lines": where, "judged": judged})
        if pkinds:
            parser_like.append({"file": f["path"], "score": sum(pkinds.values()), "kinds": dict(pkinds), "lines": pwhere, "judged": judged, "test": is_test})
    entry_like.sort(key=lambda x: (x["judged"], -x["score"]))
    parser_like.sort(key=lambda x: (x["judged"], x["test"], -x["score"]))
    return entry_like[:top], parser_like[:top], parser_lines


def notation_issues(rows: list[dict]) -> list[dict]:
    """統合で割れやすい書き方（誤りではないが、直しておくと統合の手間が減る）。"""
    out: list[dict] = []
    for r in rows:
        ref = f"{r.get('_file', '')} {r.get('_src', '')}".strip()
        label = f"{r.get('method', '') or ''} {r.get('path', '')}".strip()
        kind = str(r.get("kind", "")).lower()

        def warn(msg: str) -> None:
            out.append({"ref": ref, "item": label, "problem": msg})

        if r.get("host") and KIND_GROUP.get(kind, kind) != "host":
            host, others, leftover = clean_host(r["host"])
            if leftover or others:
                warn(f"host 欄がホスト名 1 つになっていない: 「{squash(r['host'])[:50]}」（説明は notes へ。複数のホストは書かず、prefixes.jsonl に任せる）")
        if kind in ANCHOR_KINDS:
            if not category_of(r):
                warn("受け口・解釈点の識別子が `種類:詳細` の形になっていない（例 `body:json`、`xml:xml2js@routes/import.js`）")
            file, _line, _q = first_evidence(r)
            if file and is_manifest(file) and str(r.get("origin", "")).lower() != "implicit":
                warn("根拠の 1 件目が依存の宣言行。組み込んでいる行・呼び出している行を 1 件目にする（依存の行は 2 件目以降へ）")
        elif kind == "rpc" and str(r.get("path", "")).startswith("/"):
            warn("rpc の識別子が URL の形。`trpc:<router.procedure>` `server-action:<関数名>` `grpc:<Service/Method>` の形にする（URL でも呼べるなら http の項目を別に書く）")
    return out


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    ap.add_argument("--diff", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()
    run = Path(args.run)
    inventory, unitdata = load_run(run)
    units = unitdata.get("units", [])
    findings, parse_errors, coverage, names = collect(run, args.verify)
    all_rows = [r for rows in findings.values() for r in rows]
    work = run / "work"
    (work / "check").mkdir(exist_ok=True)
    md: list[str] = ["# 検査結果", "", f"- 対象: {', '.join(f'{k} {len(v)} 件' for k, v in findings.items()) or '検出項目なし'}",
                     f"- 層の内訳: 入口 {sum(1 for r in all_rows if str(r.get('kind', '')).lower() not in ANCHOR_KINDS)} / "
                     f"受け口 {sum(1 for r in all_rows if str(r.get('kind', '')).lower() == 'input-channel')} / "
                     f"解釈点 {sum(1 for r in all_rows if str(r.get('kind', '')).lower() == 'parser')}", ""]
    summary: dict = {"findings": len(all_rows)}

    # ---- 1. ユニットの成果物
    if not args.verify:
        missing_units = []
        for u in units:
            has_f = any(n.startswith("pass1/") and n.split("/")[1].split(".")[0] == u["id"] for n in names)
            has_c = any(c.get("_unit") == u["id"] for c in coverage)
            if not (has_f and has_c):
                missing_units.append((u["id"], u["source"], u.get("label", ""), has_f, has_c))
        summary["units_missing"] = len(missing_units)
        md += ["## 1. 成果物の無いユニット", ""]
        if missing_units:
            md += ["| ユニット | ソース | 範囲 | findings | coverage |", "|---|---|---|---|---|"]
            md += [f"| {i} | {s} | `{lab or '.'}` | {'あり' if hf else '**無し**'} | {'あり' if hc else '**無し**'} |" for i, s, lab, hf, hc in missing_units]
            md += ["", "検出がゼロ件でも、空の findings ファイルと読了記録は必要（読んだ結果ゼロだったことの記録）。"]
        else:
            md.append("なし。")
        md.append("")

    # ---- 2. 読了記録
    cov_by_file: dict[str, dict] = {}
    rank = {"read": 3, "skimmed": 2, "skipped": 1}
    for c in coverage:
        if not c.get("file"):
            continue
        p = norm_file(c["file"])
        if p not in cov_by_file or rank.get(c.get("status"), 0) > rank.get(cov_by_file[p].get("status"), 0):
            cov_by_file[p] = c
    if not args.verify:
        per_source: dict[str, Counter] = defaultdict(Counter)
        unrecorded, weak = [], []
        for f in inventory["files"]:
            c = cov_by_file.get(f["path"])
            status = c.get("status") if c else None
            per_source[f["source"]][status or "未記録"] += 1
            per_source[f["source"]]["計"] += 1
            if status not in rank:
                unrecorded.append(f)
            elif status != "read" and f["tier"] in ("A", "B"):
                weak.append((f, c))
            elif status == "skipped" and not c.get("note"):
                weak.append((f, c))
        summary["files"] = len(inventory["files"])
        summary["unrecorded"] = len(unrecorded)
        summary["unrecorded_ab"] = sum(1 for f in unrecorded if f["tier"] in ("A", "B"))
        md += ["## 2. 読了状況", "", "| ソース | 計 | 全読 | 流し読み | 読まず | 未記録 |", "|---|---:|---:|---:|---:|---:|"]
        for s, c in per_source.items():
            md.append(f"| {s} | {c['計']} | {c['read']} | {c['skimmed']} | {c['skipped']} | {c['未記録']} |")
        md.append("")
        if unrecorded:
            unrecorded.sort(key=lambda f: (f["tier"], f["path"]))
            (work / "check" / "unrecorded.txt").write_text("\n".join(f"{f['tier']}\t{f['path']}" for f in unrecorded) + "\n", encoding="utf-8")
            md += [f"### 読了記録の無いファイル: {len(unrecorded)} 件（うちティア A・B が {summary['unrecorded_ab']} 件）", "",
                   "誰も読んでいない。読み手を割り当て直す。全件は `check/unrecorded.txt`。", ""]
            md += [f"- {f['tier']} `{f['path']}`" for f in unrecorded[:60]]
            if len(unrecorded) > 60:
                md.append(f"- … ほか {len(unrecorded) - 60} 件")
            md.append("")
        if weak:
            md += [f"### 読み方が浅い可能性: {len(weak)} 件", "", "ティア A・B なのに全読していない、または読まなかった理由が書かれていない。", ""]
            md += [f"- {f['tier']} `{f['path']}` — {c.get('status')}" + (f"（{c['note']}）" if c.get("note") else "（理由なし）") for f, c in weak[:40]]
            md.append("")
        known = {f["path"] for f in inventory["files"]}
        unknown = [p for p in cov_by_file if p not in known]
        if unknown:
            md += [f"### 棚卸しに無いパスの読了記録: {len(unknown)} 件", "", "パスの書き方が違っている可能性（ユニット一覧のパスをそのまま使う）。", ""]
            md += [f"- `{p}`" for p in unknown[:20]] + [""]

        # ---- 3 / 4. 検出ゼロなのに、入口らしい / 解釈処理らしい記述のあるファイル
        entry_like, parser_like, parser_lines = silent_files(inventory, all_rows, cov_by_file, args.top)
        summary["silent_entry_files"] = sum(1 for s in entry_like if not s["judged"])
        summary["silent_parser_files"] = sum(1 for s in parser_like if not s["judged"])
        summary["parser_lines_uncovered"] = len(parser_lines)
        for title, rows_, lead in (
            ("## 3. 入口らしい記述があるのに検出項目が無いファイル", entry_like,
             "緩いパターンに掛かった行があるのに、このファイルを根拠とする検出項目が 1 件も無い。誤報も多いが、見落としの有力候補。上から開いて確かめる。"),
            ("## 4. 解釈処理らしい記述があるのに検出項目が無いファイル", parser_like,
             "デシリアライズ・式の評価・外部コマンド・XML・変換・展開などに見える行があるのに、このファイルを根拠とする検出項目が無い。"
             "外部の値が届き得るかを確かめ、届く（または届かないと言い切れない）なら解釈点として載せる。"),
        ):
            md += [title, "", lead, ""]
            if rows_:
                md += ["| ファイル | 目印の内訳 | 該当行 | 読み手の判断 |", "|---|---|---|---|"]
                for s in rows_:
                    kinds = "、".join(f"{k}×{v}" for k, v in s["kinds"].items())
                    md.append(f"| `{s['file']}` | {kinds} | {', '.join(map(str, s['lines']))} | {'読了のうえ「該当なし」' if s['judged'] else '**未判断**'} |")
            else:
                md.append("なし。")
            md.append("")

        md += ["### 4b. 検出のあるファイルの中で、近くに受け口・解釈点の根拠が無い「解釈処理らしい行」", "",
               f"{len(parser_lines)} 行。ファイルには検出項目があるが、この行の前後 3 行を根拠にする受け口・解釈点が無い。"
               "ルートは載せたのに、同じファイルの中の解釈処理（展開・変換・外部コマンドなど）を載せ忘れた、という形の見落としを拾うためのもの。"
               "外部の値が届かないと確かめた行は、そのままでよい。", ""]
        if parser_lines:
            md += ["| ファイル:行 | 目印 | 行の内容 |", "|---|---|---|"]
            md += [f"| `{x['file']}:{x['line']}` | {x['kind']} | `{x['text'].replace('|', '¦').replace('`', chr(39))}` |" for x in parser_lines[:args.top * 2]]
            if len(parser_lines) > args.top * 2:
                md.append(f"| … | | ほか {len(parser_lines) - args.top * 2} 行 |")
            md.append("")

    # ---- 5. 知識ベースに手がかりのあるものの言及漏れ
    matched = kb.scan(inventory)
    dismissed = load_dismissed(run)

    def clues(hits: list) -> str:
        return "<br>".join(f"`{n}`{(' ' + v) if v else ''} — {p}{(':' + str(ln)) if ln else ''}" for n, p, ln, v in hits)

    gaps, cstat = component_gaps(matched["components"], all_rows, dismissed)
    summary["components_present"] = cstat["present"]
    summary["components_unmentioned"] = len(gaps)
    md += ["## 5. 知識ベースに手がかりがあるのに、検出項目に出てこないもの", "",
           "### 5a. 受け取り・解釈を担う部品", "",
           f"手がかりの見つかった部品 {cstat['present']} 種のうち、受け口・解釈点の項目で触れられているもの {cstat['mentioned']}、"
           f"非該当と記録されたもの {cstat['dismissed']}、**どこにも出てこないもの {len(gaps)}**。", ""]
    if gaps:
        md += ["部品ごとに、何を受け取り何を解釈しているかを調べて `input-channel` / `parser` として載せる（`component` に名前とバージョンを書く）。",
               "使われていない・外部の値が届かないと確かめたら `work/dismissed.jsonl` に `{\"source\": …, \"component\": \"<ID>\", \"reason\": …}` を 1 行書く。", "",
               "| ソース | 部品 ID | 分類 | 層 | 手がかり | 調べること |", "|---|---|---|---|---|---|"]
        for g in gaps:
            todo = g["implies"] + (f"<br>※ {g['note']}" if g["note"] else "")
            md.append(f"| {g['source']} | `{g['id']}` | {g['category']} | {'受け口' if g['layer'] == 'input-channel' else '解釈点'} | {clues(g['hits'])} | {todo} |")
        md.append("")

    igaps, istat = implicit_gaps(matched["implicit"], all_rows, dismissed)
    summary["implicit_present"] = istat["present"]
    summary["implicit_unmentioned"] = len(igaps)
    md += ["### 5b. 暗黙に存在し得るエンドポイント", "",
           f"手がかりの見つかった項目 {istat['present']} 種のうち、検出項目に出てくるもの {istat['mentioned']}、"
           f"非該当と記録されたもの {istat['dismissed']}、**どこにも出てこないもの {len(igaps)}**。", "",
           "パス 1 は暗黙の口を挙げない決まりなので、パス 1 の直後にここへ並ぶのは正常。**パス 2（implicit レンズ）の後にも残っていれば言及漏れ**。", ""]
    if igaps:
        md += ["設定で無効・移動されていないかを確かめ、存在し得るなら `origin: implicit` で載せる（内容は `work/knowledge.md`）。"
               "無効と確かめたら `work/dismissed.jsonl` に `{\"source\": …, \"implicit\": \"<ID>\", \"reason\": …}` を 1 行書く。", "",
               "| ソース | ID | 名前 | 手がかり | 知識ベースにあるエンドポイント |", "|---|---|---|---|---|"]
        for g in igaps:
            eps = "<br>".join(f"`{e}`" for e in g["endpoints"][:6]) + (f"<br>ほか {len(g['endpoints']) - 6}" if len(g["endpoints"]) > 6 else "")
            md.append(f"| {g['source']} | `{g['id']}` | {g['name']} | {clues(g['hits'])} | {eps} |")
        md.append("")

    # ---- 5c. 仕様書との照合（入力に OpenAPI / Swagger があるときだけ）
    specs, spec_missing, spec_undoc = spec_gaps(inventory, all_rows)
    summary["spec_files"] = len(specs)
    if specs:
        summary["spec_ops_missing"] = len(spec_missing)
        summary["undocumented_candidates"] = len(spec_undoc)
        md += ["### 5c. 仕様書（OpenAPI / Swagger）との照合", "",
               "入力にあった仕様書: " + "、".join(f"`{s['file']}`（{s['ops']} 操作）" for s in specs), "",
               f"**仕様にあるのに一覧に無い操作: {len(spec_missing)} 件。** 実装を探して載せる。実装が入力に無ければ、`origin: spec`・フラグ `SPEC_ONLY` で載せる（落とさない）。", ""]
        if spec_missing:
            md += ["| 仕様書 | メソッド | パス |", "|---|---|---|"] + [f"| `{x['file'].rsplit('/', 1)[-1]}` | {x['method']} | `{x['path']}` |" for x in spec_missing[:150]] + [""]
        md += [f"**コードに定義があるのに仕様に無い入口: {len(spec_undoc)} 件。** その仕様書がこのソースを対象にしているなら、フラグ `UNDOCUMENTED` を付ける"
               "（`overrides.jsonl`）。対象外の仕様書なら、そのままでよい。", ""]
        if spec_undoc:
            md += [f"- {r.get('source', '')} `{r.get('method', '')} {r.get('path', '')}`" for r in spec_undoc[:150]] + [""]

    # ---- 6. 証跡と形式
    problems, fixable = verify_evidence(all_rows, inventory["base_dir"])
    summary["evidence_problems"] = len(problems)
    summary["line_fixable"] = len(fixable)
    summary["parse_errors"] = len(parse_errors)
    md += ["## 6. 証跡・形式の問題", ""]
    if parse_errors:
        md += [f"### JSON として読めない行: {len(parse_errors)} 件", ""] + [f"- {e}" for e in parse_errors[:40]] + [""]
    if problems:
        md += [f"### 要修正: {len(problems)} 件", "", "根拠のファイルを開き直して直す。本当に存在しなければ、その項目は誤りなので取り下げる。", "",
               "| 記録場所 | 項目 | 問題 |", "|---|---|---|"]
        md += [f"| {p['ref']} | `{p['item']}` | {p['problem']} |" for p in problems[:150]]
        if len(problems) > 150:
            md.append(f"| … | | ほか {len(problems) - 150} 件 |")
        md.append("")
    if fixable:
        md += [f"### 行番号のずれ: {len(fixable)} 件", "", "引用は同じファイルの別の行に 1 か所だけ見つかった。`build_output.py` が正しい行に自動で直す。", ""]
        md += [f"- {x['ref']}: `{x['file']}` 行 {x['line']} → {x['correct']}" for x in fixable[:40]] + [""]
    if not (problems or fixable or parse_errors):
        md += ["なし。", ""]
    if not args.verify:
        notation = notation_issues(all_rows)
        summary["notation_issues"] = len(notation)
        if notation:
            md += [f"### 統合で割れやすい書き方: {len(notation)} 件", "",
                   "誤りではないが、このままだと同じ対象が別件に割れやすい。統合スクリプトが吸収できる分もあるが、次のパスの依頼文で念を押す材料にする。", "",
                   "| 記録場所 | 項目 | 気になる点 |", "|---|---|---|"]
            md += [f"| {p['ref']} | `{p['item'][:80]}` | {p['problem']} |" for p in notation[:80]]
            if len(notation) > 80:
                md.append(f"| … | | ほか {len(notation) - 80} 件 |")
            md.append("")

    # ---- 7. 秘密情報
    leaks = []
    for r in all_rows:
        blob = json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, ensure_ascii=False)
        _, n = mask_secrets(blob)
        if n:
            leaks.append(f"{r.get('_file', '')} {r.get('_src', '')}: `{r.get('method', '')} {r.get('path', '')}`（{n} か所）")
    summary["secret_like"] = len(leaks)
    md += ["## 7. 出力に含まれる秘密情報らしき値", ""]
    if leaks:
        md += ["値を `***` に置き換える（場所と種類だけを書く）。`build_output.py` でも自動で伏せるが、元の記録も直しておく。", ""] + [f"- {x}" for x in leaks[:60]] + [""]
    else:
        md += ["なし。", ""]

    # ---- 8. パス間の突き合わせ
    if args.diff and not args.verify:
        # 表記ゆれに強い照合（_common.Index）で突き合わせる。同じ対象を別の書き方で記録していても既知として扱う
        # 補助ファイル（書き方の寄せ直し・公開パス）があれば、統合と同じ順で適用してから比べる
        aliases = load_jsonl(work / "aliases.jsonl")[0] if (work / "aliases.jsonl").exists() else []
        prefixes = load_jsonl(work / "prefixes.jsonl")[0] if (work / "prefixes.jsonl").exists() else []

        def ready(rows_: list[dict]) -> list[dict]:
            kept, _dropped, _hits = apply_aliases([dict(r) for r in rows_], aliases)
            apply_prefixes(kept, prefixes)
            return [prepare(r) for r in kept]

        p1 = ready(findings.get("pass1", []))
        later = ready([r for k, rows in findings.items() if k != "pass1" for r in rows])
        idx1 = Index()
        for r in p1:
            if idx1.find(r) is None:
                idx1.add(r)
        k1_strict = {finding_key(r) for r in idx1.items}
        by_loose = defaultdict(list)
        for it in idx1.items:
            by_loose[loose_key(it)].append(it)
        idx_new = Index()
        new = []
        for r in later:
            if idx1.find(r) is not None or idx_new.find(r) is not None:
                continue
            near = False
            a = anchor(r)
            if a is not None:
                near = any(anchor(it) is not None for it in idx1.by_file.get((a[0], layer_of(r), a[2]), []))
            elif is_url_item(r):
                # 同じパスでメソッドだけ違うもの。ホストが食い違うものは別の対象なので候補にしない
                same_path = [it for it in by_loose.get(loose_key(r), []) if hosts_compatible(r, it)]
                near = bool(same_path)
                if near and (r.get("method", "") in ("", "ANY") or any(it.get("method", "") in ("", "ANY") for it in same_path)):
                    continue
            idx_new.add(r)
            new.append((r, near))
        idx2 = Index()
        for r in later:
            if idx2.find(r) is None:
                idx2.add(r)
        only1 = [r for r in idx1.items if idx2.find(r) is None]
        # パス 1 は暗黙の口を挙げない決まりなので、origin が implicit の新規は取りこぼしではない
        new_implicit = [(r, near) for r, near in new if str(r.get("origin", "")).lower() == "implicit"]
        new_defined = [(r, near) for r, near in new if str(r.get("origin", "")).lower() != "implicit"]
        new_entry = [(r, near) for r, near in new_defined if layer_of(r) == "入口"]
        summary["pass1"] = len(idx1.items)
        summary["new_in_later_passes"] = len(new)
        summary["new_defined_entries"] = len(new_entry)
        md += ["## 8. パス間の突き合わせ", "", f"- パス 1: {len(idx1.items)} 件（重複を除く）",
               f"- パス 2 以降だけが見つけたもの: **{len(new)} 件**（暗黙の仕組み {len(new_implicit)} / コードや設定に定義のあるもの {len(new_defined)}、うち入口 **{len(new_entry)}**）",
               f"- パス 1 だけが見つけたもの: {len(only1)} 件（そのまま残す）",
               f"- 適用した補助ファイル: aliases {len(aliases)} 行 / prefixes {len(prefixes)} 行", "",
               "同じ対象かどうかは、URL で表せる入口はメソッドとパスで、それ以外は識別子または根拠の位置で判定している。"
               "ここに「新規」と出たもののうち、既存の項目の書き方違いにすぎないものは `work/aliases.jsonl` に寄せ直しを書いて、もう一度 `--diff` を実行すれば既知になる。", ""]
        if new:
            by = Counter((r.get("source", ""), str(r.get("kind", ""))) for r, _ in new_defined)
            if by:
                md += ["### 定義のある新規の偏り（ここが多い範囲は、まだ掘り切れていない）", "", "| ソース | 種別 | 件数 |", "|---|---|---:|"]
                md += [f"| {s} | {k} | {n} |" for (s, k), n in by.most_common()] + [""]
            for title, group in (("### 新規の一覧: コードや設定に定義のあるもの（パス 1 の取りこぼし。根拠を確かめて採用する）", new_defined),
                                 ("### 新規の一覧: 暗黙の仕組み（パス 1 の対象外。根拠を確かめて採用する）", new_implicit)):
                if not group:
                    continue
                md += [title, "", "| 発見元 | ソース | 種別 | メソッド | パス / 識別子 | 備考 |", "|---|---|---|---|---|---|"]
                for r, near in group[:300]:
                    is_anchor = str(r.get("kind", "")).lower() in ANCHOR_KINDS
                    note = ("同じファイルにパス 1 の項目あり（別の箇所）" if is_anchor else "同じパスでメソッド違いがパス 1 にある") if near else ""
                    md.append(f"| {r.get('found_by', '')} | {r.get('source', '')} | {r.get('kind', '')} | {r.get('method', '')} | `{r.get('path', '')}` | {note} |")
                if len(group) > 300:
                    md.append(f"| … | | | | ほか {len(group) - 300} 件 | |")
                md.append("")
        n1_entry = sum(1 for r in idx1.items if layer_of(r) == "入口")
        ratio = len(new_entry) / max(1, n1_entry)
        md += [f"収束の目安: 定義のある入口の新規は、パス 1 の入口 {n1_entry} 件に対して {ratio:.0%}。5% を下回れば収束、特定のソース・種別に 5 件以上固まっていればその範囲をもう一度掘る。",
               "受け口・解釈点と暗黙の仕組みはパス 2 の専用レンズが主に拾うので、初回はここに多く出るのが普通（収束の判断には使わない）。", ""]

    # ---- 9. 3 層のつながり
    if args.verify:
        by_source: dict[str, Counter] = defaultdict(Counter)
        for r in all_rows:
            kind = str(r.get("kind", "")).lower()
            layer = "受け口" if kind == "input-channel" else "解釈点" if kind == "parser" else "入口"
            by_source[str(r.get("source", ""))][layer] += 1
            if KIND_GROUP.get(kind, kind) in ("http", "ws", "graphql", "rpc"):
                by_source[str(r.get("source", ""))]["リクエストを受ける入口"] += 1
        no_intake = [s for s, c in by_source.items() if c["リクエストを受ける入口"] and not c["受け口"]]
        # 同じ箇所を指す解釈点（統合前の重複）はまとめて判定する。どれか 1 行に書いてあれば足りる
        clusters: list[dict] = []
        for r in all_rows:
            a = anchor(r)
            if a is None or a[1] != "parser":
                if str(r.get("kind", "")).lower() == "parser":
                    clusters.append({"key": None, "row": r, "ok": bool(r.get("fed_by")) and bool(r.get("reach"))})
                continue
            hit = next((c for c in clusters if c["key"] == a[:3] and same_spot(a[3], a[4], c["line"], c["quote"])), None)
            ok = bool(r.get("fed_by")) and bool(r.get("reach"))
            if hit is None:
                clusters.append({"key": a[:3], "line": a[3], "quote": a[4], "row": r, "ok": ok})
            else:
                hit["ok"] = hit["ok"] or ok
        no_fed = [c["row"] for c in clusters if not c["ok"]]
        no_scope = [r for r in all_rows if str(r.get("kind", "")).lower() == "input-channel" and not r.get("scope")]
        unknown_reach = [r for r in all_rows if "REACH_UNKNOWN" in (r.get("flags") or [])]
        summary["sources_without_intake"] = len(no_intake)
        summary["parsers_without_fed_by"] = len(no_fed)
        summary["reach_unknown"] = len(unknown_reach)
        md += ["## 9. 3 層のつながり", "", "| ソース | 入口 | 受け口 | 解釈点 |", "|---|---:|---:|---:|"]
        md += [f"| {s} | {c['入口']} | {c['受け口']} | {c['解釈点']} |" for s, c in by_source.items()]
        md.append("")
        if no_intake:
            md += [f"### 受け口の棚卸しが無いソース: {len(no_intake)}", "",
                   "リクエストを受ける入口があるのに `input-channel` が 1 件も無い。リクエスト処理の共通部分（本文の解釈、ヘッダの信頼、Cookie・セッション、自動バインド）を読んで載せる。", ""]
            md += [f"- {s}" for s in no_intake] + [""]
        if no_fed:
            md += [f"### 届く入口が書かれていない解釈点: {len(no_fed)} 件", "",
                   "`fed_by` と `reach` を埋める。辿れなければ `fed_by: [\"不明\"]`、`reach: \"unknown\"` とし、フラグ `REACH_UNKNOWN` を付ける。", ""]
            md += [f"- {r.get('source', '')}: `{r.get('path', '')}`（{r.get('_src', '')}）" for r in no_fed[:80]] + [""]
        if no_scope:
            md += [f"### 掛かる範囲が書かれていない受け口: {len(no_scope)} 件", "", "`scope` に 全ルート / 接頭辞 / 個別のルート を書く。", ""]
            md += [f"- {r.get('source', '')}: `{r.get('path', '')}`（{r.get('_src', '')}）" for r in no_scope[:80]] + [""]
        if unknown_reach:
            md += [f"### 届く経路が未確定の解釈点 (REACH_UNKNOWN): {len(unknown_reach)} 件", "", "残してよい。`coverage.md` に一覧と、何を調べれば確定するかを書く。", ""]
        # 本文を受けるはずの入口で、パス変数以外のパラメータが 1 つも書かれていないもの
        no_params = [r for r in all_rows if str(r.get("kind", "")).lower() in ("http", "rpc", "graphql") and str(r.get("origin", "")).lower() in ("code", "spec")
                     and str(r.get("method", "")).upper() in ("POST", "PUT", "PATCH", "MUTATION")
                     and not any(isinstance(p, dict) and p.get("in") != "path" for p in as_list(r.get("params")))]
        summary["writes_without_params"] = len(no_params)
        if no_params:
            md += [f"### 値を受け取るはずなのに、パラメータが書かれていない入口: {len(no_params)} 件", "",
                   "POST / PUT / PATCH / MUTATION で、パス変数以外のパラメータが 1 つも無い。ハンドラを開き、読んでいる項目（本文・クエリ・ヘッダ・Cookie・ファイル）を `overrides.jsonl` の `set.params` で足す。"
                   "本当に何も読まないなら、`notes` にそう書く。", ""]
            md += [f"- {r.get('source', '')} `{r.get('method', '')} {r.get('path', '')}`" for r in no_params[:60]] + [""]
        if not (no_intake or no_fed or no_scope):
            md += ["欠けは無い。", ""]

    # --verify は別ファイルに書く（パス間の突き合わせ結果を上書きしないため）
    stem = "verify" if args.verify else "report"
    (work / "check" / f"{stem}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (work / "check" / f"{stem}.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(" ".join(f"{k}={v}" for k, v in summary.items()))
    print(f"report={(work / 'check' / f'{stem}.md').as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
