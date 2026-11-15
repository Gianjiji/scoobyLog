"""md_code / md_text / md_fence: il dato dei log resta dato, qualunque cosa contenga."""
import random
import re

import pytest

from scoobyLog import md_code, md_fence, md_text

ALPHABET = "ab `|<>[]\\*_\n\t\"'&;:()!#"


def random_values(count=400, seed=11):
    rng = random.Random(seed)
    return ["".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 24))) for _ in range(count)]


def split_code_span(span: str):
    """(delimitatore, contenuto) di uno span di codice prodotto da md_code."""
    opening = re.match(r"`+", span).group(0)
    assert span.endswith(opening) and len(span) >= 2 * len(opening)
    return opening, span[len(opening):len(span) - len(opening)]


class TestMdCode:
    @pytest.mark.parametrize("value", ["web-01", "10.0.0.5", "ERROR", "sess-ab12", "a_b*c", "97%"])
    def test_i_valori_comuni_restano_come_prima(self, value):
        assert md_code(value) == "`%s`" % value
        assert md_code(value, cell=True) == "`%s`" % value

    def test_un_backtick_non_chiude_lo_span(self):
        span = md_code("web`<img src=x onerror=alert()>`")
        fence, content = split_code_span(span)
        assert fence == "``"
        assert "<img src=x onerror=alert()>" in content

    def test_il_delimitatore_non_compare_mai_nel_contenuto(self):
        """Proprietà CommonMark: lo span si chiude solo con una sequenza di pari lunghezza."""
        for value in random_values():
            for cell in (False, True):
                fence, content = split_code_span(md_code(value, cell=cell))
                runs = {len(run) for run in re.findall(r"`+", content)}
                assert len(fence) not in runs, (value, fence, content)

    def test_il_contenuto_non_inizia_ne_finisce_con_un_backtick(self):
        for value in random_values():
            _, content = split_code_span(md_code(value))
            assert not content.startswith("`") and not content.endswith("`"), value

    def test_mai_su_piu_righe(self):
        for value in random_values():
            assert "\n" not in md_code(value) and "\r" not in md_code(value)
        assert md_code("a\r\nb\u2028c") == "`a b c`"

    def test_in_tabella_la_pipe_e_sempre_preceduta_da_backslash(self):
        for value in random_values():
            span = md_code(value, cell=True)
            assert not re.search(r"(?<!\\)\|", span), (value, span)

    def test_fuori_tabella_la_pipe_resta_com_e(self):
        assert md_code("a|b") == "`a|b`"

    def test_troncamento(self):
        assert md_code("x" * 500, 120) == "`" + "x" * 120 + "`"

    def test_il_troncamento_non_puo_spezzare_la_protezione(self):
        """Si tronca prima di scegliere il delimitatore, non dopo."""
        value = "a" * 119 + "``` coda"
        fence, content = split_code_span(md_code(value, 121))
        assert len(fence) == 3 and content.strip().endswith("``")

    @pytest.mark.parametrize("value", ["", None, "   ", "\n"])
    def test_valore_vuoto(self, value):
        assert md_code(value) == "` `"

    def test_valori_non_stringa(self):
        assert md_code(42) == "`42`"
        assert md_code(3.5) == "`3.5`"


class TestMdText:
    def test_il_testo_comune_non_cambia(self):
        for value in ("GET /api/v1/items 200 12ms", "cache hit key=user_42", "a*b", "97% on /var"):
            assert md_text(value) == value

    @pytest.mark.parametrize("char", list("`[]<>\\"))
    def test_i_caratteri_attivi_sono_neutralizzati(self, char):
        assert md_text("a%sb" % char) == "a\\%sb" % char

    def test_niente_tag_html_ne_link(self):
        out = md_text('<img src=x onerror=alert()> [x](javascript:alert())')
        assert not re.search(r"(?<!\\)<", out)
        assert not re.search(r"(?<!\\)\[", out)

    def test_pipe_solo_in_tabella(self):
        assert md_text("a|b") == "a|b"
        assert md_text("a|b", cell=True) == "a\\|b"

    def test_un_backslash_finale_non_mangia_il_separatore_di_cella(self):
        assert md_text("percorso C:\\", cell=True).endswith("\\\\")

    def test_mai_su_piu_righe_e_troncamento(self):
        assert md_text("riga uno\nriga due") == "riga uno riga due"
        assert md_text("abcdef", 3) == "abc"
        assert md_text(None) == ""


class TestMdFence:
    def test_blocco_comune(self):
        assert md_fence("ciao") == "```\nciao\n```"
        assert md_fence("select 1", "sql") == "```sql\nselect 1\n```"

    def test_una_riga_di_backtick_non_chiude_il_blocco(self):
        block = md_fence("prima\n```\n<img src=x onerror=alert()>\n```\ndopo")
        lines = block.split("\n")
        assert lines[0] == lines[-1] == "````"
        assert "````" not in lines[1:-1]

    def test_il_recinto_e_sempre_piu_lungo_del_contenuto(self):
        for value in random_values():
            block = md_fence(value)
            fence = block.split("\n", 1)[0]
            assert len(fence) >= 3
            body = block[len(fence) + 1:len(block) - len(fence) - 1]
            assert all(len(run) < len(fence) for run in re.findall(r"`+", body)), value
