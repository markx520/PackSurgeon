#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import re
from typing import Iterable, Optional, Tuple


_CHARSET_PATTERN = re.compile(r"charset\s*=\s*[\"']?\s*([a-zA-Z0-9._:-]+)", re.IGNORECASE)

_ENCODING_ALIASES = {
    "utf8": "utf-8",
    "utf_8": "utf-8",
    "unicode-1-1-utf-8": "utf-8",
    "cp65001": "utf-8",
    "gbk": "gb18030",
    "gb2312": "gb18030",
    "gb_2312": "gb18030",
    "x-gbk": "gb18030",
    "cp936": "gb18030",
    "ms936": "gb18030",
    "big5-hkscs": "big5",
    "x-sjis": "shift_jis",
    "sjis": "shift_jis",
}

_DEFAULT_CANDIDATES = (
    "utf-8",
    "utf-8-sig",
    "gb18030",
    "big5",
    "shift_jis",
    "euc-jp",
    "iso-8859-1",
)


def normalize_encoding_name(name: Optional[str]) -> str:
    text = (name or "").strip().lower()
    if not text:
        return ""
    return _ENCODING_ALIASES.get(text, text)


def extract_charset_from_content_type(content_type: Optional[str]) -> str:
    text = str(content_type or "")
    match = _CHARSET_PATTERN.search(text)
    if not match:
        return ""
    return normalize_encoding_name(match.group(1))


def _looks_utf16le_without_bom(data: bytes) -> bool:
    if len(data) < 8:
        return False
    sample = data[:2048]
    odd_zeros = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
    even_zeros = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
    odd_slots = max(1, len(sample) // 2)
    even_slots = max(1, (len(sample) + 1) // 2)
    return (odd_zeros / odd_slots) > 0.25 and (even_zeros / even_slots) < 0.12


def _looks_utf16be_without_bom(data: bytes) -> bool:
    if len(data) < 8:
        return False
    sample = data[:2048]
    odd_zeros = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
    even_zeros = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
    odd_slots = max(1, len(sample) // 2)
    even_slots = max(1, (len(sample) + 1) // 2)
    return (even_zeros / even_slots) > 0.25 and (odd_zeros / odd_slots) < 0.12


def decode_bytes_robust(
    data: bytes,
    content_type: Optional[str] = None,
    hinted_encoding: Optional[str] = None,
    extra_candidates: Optional[Iterable[str]] = None,
) -> Tuple[str, str]:
    """
    Robustly decode bytes to text without silently dropping bytes.
    Returns (decoded_text, encoding_used).
    """
    if data is None:
        return "", "utf-8"
    if isinstance(data, str):
        return data, "str"

    raw = bytes(data)
    if not raw:
        return "", "utf-8"

    candidates = []

    # BOM first
    if raw.startswith(b"\xef\xbb\xbf"):
        candidates.append("utf-8-sig")
    elif raw.startswith(b"\xff\xfe"):
        candidates.append("utf-16le")
    elif raw.startswith(b"\xfe\xff"):
        candidates.append("utf-16be")
    else:
        if _looks_utf16le_without_bom(raw):
            candidates.append("utf-16le")
        elif _looks_utf16be_without_bom(raw):
            candidates.append("utf-16be")

    charset = extract_charset_from_content_type(content_type)
    if charset:
        candidates.append(charset)

    hinted = normalize_encoding_name(hinted_encoding)
    if hinted:
        candidates.append(hinted)

    if extra_candidates:
        for item in extra_candidates:
            normalized = normalize_encoding_name(item)
            if normalized:
                candidates.append(normalized)

    candidates.extend(_DEFAULT_CANDIDATES)

    seen = set()
    deduped = []
    for encoding in candidates:
        if encoding and encoding not in seen:
            seen.add(encoding)
            deduped.append(encoding)

    for encoding in deduped:
        try:
            return raw.decode(encoding), encoding
        except (UnicodeDecodeError, LookupError):
            continue

    # Last resort: 1:1 byte mapping; no byte loss.
    return raw.decode("latin-1"), "latin-1"
