import unicodedata
import re


def clean_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    cleaned = re.sub(r"\s+", " ", ascii_only).strip()
    return cleaned[:1024]
