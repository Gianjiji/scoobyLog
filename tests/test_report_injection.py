"""Il report nasce da log non fidati: nulla di ciò che contengono deve diventare markup.

Tre livelli di verifica, dal più economico al più fedele:

  1. il Markdown generato, letto da un parser CommonMark indipendente
     (markdown-it-py), non contiene HTML grezzo, immagini o link non sicuri;
  2. la pagina HTML ha le difese dichiarate (escape, CSP con hash, SRI);
  3. la pagina aperta in un browser vero non esegue nulla (Playwright, se installato).

I livelli 1 e 3 vengono saltati se manca la relativa dipendenza di sviluppo
(vedi requirements-dev.txt).
"""
import base64
import hashlib
import re

import pytest

import scoobyLog
from conftest import marker

SAFE_HREF = re.compile(r"^(https?:|mailto:|#)", re.I)


# ── 1. Il Markdown generato ──────────────────────────────────────────────────

def all_tokens(markdown: str):
    markdown_it = pytest.importorskip("markdown_it")
    parser = markdown_it.MarkdownIt("commonmark", {"html": True}).enable(["table", "strikethrough"])
    for token in parser.parse(markdown):
        yield token
        for child in token.children or []:
            yield child


class TestMarkdownGenerato:
    def test_nessun_html_grezzo(self, hostile_md):
        raw = [t.content for t in all_tokens(hostile_md) if t.type in ("html_inline", "html_block")]
        assert raw == []

    def test_nessuna_immagine(self, hostile_md):
        """Un'immagine remota nel report sarebbe un tracciatore di chi lo apre."""
        assert [t for t in all_tokens(hostile_md) if t.type == "image"] == []

    def test_nessun_link_con_schema_pericoloso(self, hostile_md):
        hrefs = [t.attrGet("href") or "" for t in all_tokens(hostile_md) if t.type == "link_open"]
        assert [h for h in hrefs if not SAFE_HREF.match(h)] == []

    def test_i_payload_restano_leggibili_come_codice(self, hostile_md):
        """Neutralizzare non vuol dire nascondere: l'analista deve vedere cosa c'era nei log."""
        code = " ".join(t.content for t in all_tokens(hostile_md)
                        if t.type in ("code_inline", "fence", "code_block"))
        assert "<img src=x onerror=" in code
        assert "<script>" in code

    def test_il_report_ostile_ha_tutte_le_sezioni(self, hostile_md):
        """Con l'iniezione attiva la struttura del report si rompeva a metà."""
        headings = [t for t in all_tokens(hostile_md) if t.type == "heading_open" and t.tag == "h2"]
        assert len(headings) >= 17

    def test_le_tabelle_del_report_ostile_non_hanno_celle_in_piu(self, hostile_md):
        lines = hostile_md.split("\n")
        for index, line in enumerate(lines[:-1]):
            if not re.fullmatch(r"\|(\s*:?-+:?\s*\|)+", lines[index + 1].strip()):
                continue
            columns = lines[index + 1].count("|") - 1
            cursor = index + 2
            while cursor < len(lines) and lines[cursor].startswith("|"):
                cells = len(re.findall(r"(?<!\\)\|", lines[cursor])) - 1
                assert cells == columns, "riga %d: %s" % (cursor + 1, lines[cursor][:140])
                cursor += 1

    def test_il_parser_di_controllo_vede_davvero_l_html(self):
        """Controprova: senza protezione lo stesso parser segnala l'HTML grezzo."""
        message = 'db connection failed `<img src=x onerror="alert()">` upstream'
        header = "| a | b | c |\n|---|---|---|\n"
        unsafe = header + "| 1 | `%s` | 40 |" % message               # com'era prima
        safe = header + "| 1 | %s | 40 |" % scoobyLog.md_code(message, cell=True)
        assert any(t.type == "html_inline" for t in all_tokens(unsafe))
        assert not any(t.type == "html_inline" for t in all_tokens(safe))


# ── 2. La pagina HTML ────────────────────────────────────────────────────────

class TestPaginaHtml:
    def page(self, markdown="# Titolo", incident="IR-TEST", severity="P1 - Critico"):
        return scoobyLog.wrap_html(markdown, incident, severity)

    def test_l_identificativo_e_sempre_escapato(self):
        page = self.page(incident='"><script>alert()</script>')
        assert "<script>alert()" not in page
        assert page.count("&lt;script&gt;alert()&lt;/script&gt;") == 2   # titolo e banner

    def test_il_markdown_e_incorporato_come_testo(self):
        page = self.page(markdown='</div><script>alert()</script><img src=x onerror=alert()>')
        assert "<script>alert()" not in page
        assert "<img src=x" not in page
        assert "&lt;/div&gt;&lt;script&gt;" in page

    def csp(self, page):
        match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">', page)
        assert match, "manca la Content-Security-Policy"
        import html
        return dict(part.strip().split(" ", 1) for part in html.unescape(match.group(1)).split(";"))

    def test_csp_nessuna_origine_per_difetto(self):
        csp = self.csp(self.page())
        assert csp["default-src"] == "'none'"
        assert csp["base-uri"] == "'none'" and csp["form-action"] == "'none'"

    def test_csp_niente_script_in_linea_liberi(self):
        script_src = self.csp(self.page())["script-src"]
        assert "'unsafe-inline'" not in script_src
        assert "'unsafe-eval'" not in script_src
        assert "*" not in script_src

    def test_csp_l_hash_e_quello_dello_script_della_pagina(self):
        page = self.page()
        inline = re.findall(r"<script>(.*?)</script>", page, re.S)
        assert len(inline) == 1, "deve esserci un solo script in linea"
        digest = base64.b64encode(hashlib.sha256(inline[0].encode("utf-8")).digest()).decode()
        assert "'sha256-%s'" % digest in self.csp(page)["script-src"]

    def test_lo_script_in_linea_non_dipende_dal_report(self):
        """Altrimenti l'hash cambierebbe a ogni report, o peggio conterrebbe dati dei log."""
        first = re.findall(r"<script>(.*?)</script>", self.page("# A", "IR-1", "P1"), re.S)
        second = re.findall(r"<script>(.*?)</script>", self.page("# B <x>", "IR-2", "P4"), re.S)
        assert first == second

    def test_le_risorse_esterne_sono_fissate_per_versione_e_per_hash(self):
        page = self.page()
        external = re.findall(r'<(?:script|link)\b[^>]*(?:src|href)="(https?://[^"]+)"[^>]*>', page)
        assert len(external) == 3
        for tag in re.findall(r'<(?:script|link)\b[^>]*(?:src|href)="https?://[^>]*>', page):
            assert re.search(r'integrity="sha(384|512)-[A-Za-z0-9+/=]+"', tag), tag
            assert 'crossorigin="anonymous"' in tag, tag
            assert re.search(r"/\d+\.\d+\.\d+/", tag), "versione non fissata: " + tag

    def test_l_html_prodotto_da_marked_non_va_mai_direttamente_nella_pagina(self):
        script = scoobyLog._REPORT_SCRIPT
        assert "template.innerHTML = marked.parse(source)" in script
        assert len(re.findall(r"marked\.parse\(", script)) == 1
        assert len(re.findall(r"\.innerHTML\s*=", script)) == 1
        assert script.index("clean(template.content)") < script.index("put(Array.prototype")

    def test_c_e_un_ripiego_senza_rete(self):
        script = scoobyLog._REPORT_SCRIPT
        assert "typeof marked === 'undefined'" in script
        assert "pre.textContent = source" in script

    def test_colore_di_gravita(self):
        assert "--accent: #e74c3c" in self.page(severity="P1 - Critico")
        assert "--accent: #3498db" in self.page(severity="")
        assert "--accent: #3498db" in self.page(severity='red;}</style><script>alert()</script>')


# ── 3. Il browser vero ───────────────────────────────────────────────────────

PROBE = """() => {
  const root = document.getElementById('rendered');
  const all = [...root.querySelectorAll('*')];
  return {
    pwned: window.__pwned || null,
    tags: [...new Set(all.map(e => e.tagName))].sort(),
    handlers: all.filter(e => [...e.attributes].some(a => a.name.startsWith('on'))).length,
    hrefs: [...root.querySelectorAll('a')].map(a => a.getAttribute('href')),
    h2: root.querySelectorAll('h2').length,
    plain: !!root.querySelector('pre.plain'),
    text: root.innerText,
    title: document.title,
  };
}"""

ALLOWED_TAGS = {"H1", "H2", "H3", "H4", "H5", "H6", "P", "BR", "HR", "EM", "STRONG", "DEL",
                "CODE", "PRE", "BLOCKQUOTE", "UL", "OL", "LI", "TABLE", "THEAD", "TBODY", "TR",
                "TH", "TD", "A", "INPUT", "SPAN"}   # SPAN: aggiunto da highlight.js


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except Exception as error:   # browser non scaricato o librerie di sistema mancanti
            pytest.skip("Chromium non avviabile: %s" % str(error).splitlines()[0])
        yield instance
        instance.close()


def open_page(browser, path, offline=False):
    page = browser.new_page()
    requests, dialogs = [], []
    page.on("request", lambda request: requests.append(request.url))
    page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
    if offline:
        page.route("**/*", lambda route: route.abort()
                   if route.request.url.startswith("http") else route.continue_())
    page.goto(path.as_uri(), wait_until="networkidle")
    page.wait_for_timeout(300)
    state = page.evaluate(PROBE)
    state["dialogs"] = dialogs
    state["external"] = sorted({u for u in requests if u.startswith("http")})
    page.close()
    return state


def wrapper_only_markdown():
    """Markdown ostile consegnato direttamente a wrap_html, senza l'aiuto di md_code."""
    return "\n\n".join([
        "# Titolo", "Testo **forte** e `codice`.",
        '<img src=x onerror="%s">' % marker("img"),
        'in linea <svg onload="%s"></svg> qui' % marker("svg"),
        "<script>%s</script>" % marker("script"),
        '<iframe srcdoc="<script>parent.%s</script>"></iframe>' % marker("iframe"),
        "[link](javascript:%s)" % marker("jslink").replace("(", "%28").replace(")", "%29"),
        "[ok](https://example.org/x)", "![pixel](https://tracker.invalid/p.png)",
        '<a href="javascript:%s">a</a>' % marker("a"),
        '<details open ontoggle="%s">d</details>' % marker("details"),
        '<math><mtext><img src=x onerror="%s"></mtext></math>' % marker("math"),
        '<form action="https://example.org"><input name=q><button>vai</button></form>',
        "<style>body{display:none}</style>", '<base href="https://example.org/">',
        "| a | b |\n|---|:-:|\n| 1 | 2 |", "```python\nprint('<b>x</b>')\n```",
    ])


@pytest.fixture(scope="module")
def wrapper_only_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("wrapper") / "wrapper.html"
    path.write_text(scoobyLog.wrap_html(wrapper_only_markdown(),
                                        '"><script>%s</script>' % marker("title"), "P1"),
                    encoding="utf-8")
    return path


def strip_defences(page: str) -> str:
    """La pagina com'era prima: nessuna CSP, nessun escape dell'HTML, nessuna allow-list."""
    page = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>\n', "", page)
    start, end = page.index("  marked.use({"), page.index("  // Layer 2.")
    page = page[:start] + page[end:]
    return page.replace("    clean(template.content);\n", "")


class TestNelBrowser:
    def assert_inert(self, state):
        assert state["pwned"] is None, "JavaScript iniettato eseguito: %s" % state["pwned"]
        assert state["dialogs"] == []
        assert state["handlers"] == 0
        assert set(state["tags"]) <= ALLOWED_TAGS, set(state["tags"]) - ALLOWED_TAGS
        assert [h for h in state["hrefs"] if h and not SAFE_HREF.match(h)] == []
        assert all("cdnjs.cloudflare.com" in url for url in state["external"]), state["external"]

    def test_report_da_log_ostili(self, browser, hostile_html_path):
        state = open_page(browser, hostile_html_path)
        self.assert_inert(state)
        assert not state["plain"], "il report non è stato impaginato"
        assert state["h2"] >= 17
        assert "<img src=x onerror=" in state["text"], "il payload deve restare visibile come testo"

    def test_markdown_ostile_direttamente_nella_pagina(self, browser, wrapper_only_path):
        state = open_page(browser, wrapper_only_path)
        self.assert_inert(state)
        assert "https://example.org/x" in state["hrefs"]
        assert "<script>" in state["title"]          # mostrato, non interpretato
        assert "<img src=x onerror=" in state["text"]

    def test_senza_rete_il_report_resta_leggibile(self, browser, hostile_html_path):
        state = open_page(browser, hostile_html_path, offline=True)
        self.assert_inert(state)
        assert state["plain"]
        assert "Incident Response Report" in state["text"]
        assert "Root Cause Analysis" in state["text"]

    def test_controprova_senza_difese_i_payload_sono_vivi(self, browser, wrapper_only_path, tmp_path):
        """Se questo test fallisse, gli altri tre non proverebbero nulla."""
        unsafe = tmp_path / "unsafe.html"
        unsafe.write_text(strip_defences(wrapper_only_path.read_text(encoding="utf-8")),
                          encoding="utf-8")
        state = open_page(browser, unsafe)
        assert state["pwned"], "i payload di prova non sono eseguibili: test da rivedere"
