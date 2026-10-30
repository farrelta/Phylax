"""CPE name parsing shared by adapters and offline validation."""
from __future__ import annotations

def cpe_parts(criteria: str) -> list[str]:
    """Preserve all CPE 2.3 attributes; unsupported constraints force review."""
    parts: list[str] = []
    current = ""
    escaped = False
    for character in criteria:
        if escaped:
            current += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append(current)
            current = ""
        else:
            current += character
    parts.append(current)
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return []
    return parts


def cpe_components(criteria: str) -> tuple[str, str, str]:
    parts = cpe_parts(criteria)
    return (parts[3], parts[4], parts[5]) if parts else ("", "", "")

