"""Shared response shaping: pagination, filtering, markdown/JSON rendering."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any


class ResponseFormat(str, Enum):
    """Output format for list-style tools."""

    MARKDOWN = "markdown"
    JSON = "json"


def paginate(items: list[Any], limit: int, offset: int) -> dict[str, Any]:
    """Standard pagination envelope: total, count, offset, has_more, next_offset."""
    total = len(items)
    page = items[offset : offset + limit]
    has_more = offset + len(page) < total
    return {
        "total": total,
        "count": len(page),
        "offset": offset,
        "items": page,
        "has_more": has_more,
        "next_offset": offset + len(page) if has_more else None,
    }


def name_filter(items: list[dict[str, Any]], needle: str | None, *keys: str) -> list[dict[str, Any]]:
    """Case-insensitive substring filter across the given dict keys."""
    if not needle:
        return items
    n = needle.lower()
    return [
        it
        for it in items
        if any(n in str(it.get(k, "")).lower() for k in keys)
    ]


def render_page(
    page: dict[str, Any],
    fmt: ResponseFormat,
    title: str,
    columns: list[tuple[str, str]],
    note: str | None = None,
) -> str:
    """Render a paginate() envelope as markdown table or JSON.

    columns: list of (item_key, column_header) pairs used for markdown.
    """
    if fmt == ResponseFormat.JSON:
        out = dict(page)
        if note:
            out["_note"] = note
        return json.dumps(out, indent=2, default=str)

    lines = [f"# {title}", ""]
    lines.append(
        f"Showing {page['count']} of {page['total']} (offset {page['offset']})."
        + (f" More available: pass offset={page['next_offset']}." if page["has_more"] else "")
    )
    lines.append("")
    if page["items"]:
        headers = [h for _, h in columns]
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("|" + "|".join("---" for _ in headers) + "|")
        for it in page["items"]:
            row = [
                ("" if it.get(k) is None else str(it.get(k)))
                .replace("|", "\\|")
                .replace("\n", " ")
                for k, _ in columns
            ]
            lines.append("| " + " | ".join(row) + " |")
    else:
        lines.append("_No results._")
    if note:
        lines.append("")
        lines.append(f"> {note}")
    return "\n".join(lines)
