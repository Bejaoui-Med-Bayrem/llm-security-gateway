import base64
import binascii
import codecs
import html
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import unquote

INVISIBLE_CHARS = {
    ord(char): None
    for char in (
        "\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
        "\ufeff\u00ad\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    )
}

HOMOGLYPHS = str.maketrans(
    {
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
        "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
        "\u0458": "j", "\u0455": "s", "\u04bb": "h",
        "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K",
        "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
        "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0406": "I",
        "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03b9": "i",
        "\u03c1": "p", "\u03ba": "k",
        "\u039f": "O", "\u0391": "A", "\u0392": "B", "\u0395": "E",
        "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
        "\u03a1": "P", "\u03a4": "T", "\u03a7": "X", "\u0396": "Z",
    }
)

LEET = str.maketrans("013457@$", "oieastas")

ESCAPE_PATTERN = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
SPACED_LETTERS = re.compile(r"(?<!\w)(?:\w[\s.\-_*|]+){3,}\w(?!\w)")
SEPARATORS = re.compile(r"[\s.\-_*|]+")
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

SUSPICIOUS_SIGNALS = frozenset(
    {"invisible_chars", "mixed_script", "encoded_blob", "spaced_letters"}
)


@dataclass(frozen=True)
class Variant:
    label: str
    text: str


@dataclass
class NormalizationResult:
    original: str
    variants: list[Variant] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)


@lru_cache(maxsize=4096)
def _script(char: str) -> str | None:
    if not char.isalpha():
        return None
    try:
        return unicodedata.name(char).split()[0]
    except ValueError:
        return "UNKNOWN"


def _has_mixed_script(text: str) -> bool:
    for token in text.split():
        scripts = {_script(char) for char in token} - {None}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            return True
    return False


def _has_non_latin(text: str) -> bool:
    return any(_script(char) not in (None, "LATIN") for char in text)


def _unescape(text: str) -> str:
    return ESCAPE_PATTERN.sub(
        lambda match: chr(int(match.group(1) or match.group(2), 16)),
        text,
    )


def _is_leet_token(token: str) -> bool:
    return bool(re.search(r"[A-Za-z]", token) and re.search(r"[0-9@$]", token))


def _deleet(text: str) -> str:
    raw_tokens = text.split(" ")
    has_leet = any(_is_leet_token(token) for token in raw_tokens)
    tokens = []
    for token in raw_tokens:
        if _is_leet_token(token) or (
            has_leet and token.isdigit() and len(token) <= 3
        ):
            token = token.translate(LEET)
        tokens.append(token)
    return " ".join(tokens)


def _readable_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None

    if len(text) < 6:
        return None

    printable = sum(1 for char in text if char.isprintable() or char in "\n\t\r")
    letters = sum(1 for char in text if char.isalpha())

    if printable / len(text) < 0.9 or letters / len(text) < 0.5:
        return None

    return text


MAX_DECODED_BLOBS = 8
MAX_DECODE_DEPTH = 2


def _decode_base64_blob(token: str) -> str | None:
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _readable_text(raw)


def _decode_hex_blob(token: str) -> str | None:
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    return _readable_text(raw)


class Normalizer:

    def normalize(self, text: str) -> NormalizationResult:
        signals: list[str] = []

        working = _unescape(text)

        if "%" in working:
            working = unquote(working)

        if "&" in working:
            working = html.unescape(working)

        working = unicodedata.normalize("NFKC", working)

        stripped = working.translate(INVISIBLE_CHARS)
        if stripped != working:
            signals.append("invisible_chars")
        working = stripped

        if _has_mixed_script(working):
            signals.append("mixed_script")

        if _has_non_latin(working):
            signals.append("non_latin_script")

        cleaned = working.translate(HOMOGLYPHS)

        spaced = SPACED_LETTERS.sub(
            lambda match: SEPARATORS.sub("", match.group(0)),
            cleaned,
        )
        if spaced != cleaned:
            signals.append("spaced_letters")

        variants: list[Variant] = []

        def add(label: str, value: str) -> None:
            if not value or value == text:
                return
            if any(value == variant.text for variant in variants):
                return
            variants.append(Variant(label, value))

        add("normalized", _deleet(spaced))

        decoded_blobs = self._decode_blobs(cleaned)

        for label, decoded in decoded_blobs:
            add(label, _deleet(decoded))
            add("mixed", decoded[::-1])
            add("mixed", codecs.encode(decoded, "rot_13"))
            add("mixed", " ".join(word[::-1] for word in decoded.split(" ")))

        if decoded_blobs:
            signals.append("encoded_blob")

        add("rot13", codecs.encode(cleaned, "rot_13"))
        add("reverse", cleaned[::-1])
        add("reverse_words", " ".join(word[::-1] for word in cleaned.split(" ")))

        return NormalizationResult(
            original=text,
            variants=variants,
            signals=signals,
        )

    @staticmethod
    def _decode_blobs(text: str) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []

        def walk(source: str, level: int, layered: bool) -> None:
            for label, pattern, decoder in (
                ("base64", BASE64_PATTERN, _decode_base64_blob),
                ("hex", HEX_PATTERN, _decode_hex_blob),
            ):
                for token in pattern.findall(source):
                    for reversed_blob in (False, True):
                        if len(results) >= MAX_DECODED_BLOBS:
                            return

                        candidate = token[::-1] if reversed_blob else token
                        decoded = decoder(candidate)

                        if decoded is None:
                            continue

                        multi_layer = layered or reversed_blob
                        results.append(("mixed" if multi_layer else label, decoded))

                        if level < MAX_DECODE_DEPTH:
                            walk(decoded, level + 1, True)

        walk(text, 1, False)
        return results