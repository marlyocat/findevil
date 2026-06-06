"""
Markdown table helper.

Centralises the bespoke string concatenation that several tools used to do
inline. Doing it once here means:

- Cell values are escaped consistently (pipe, backtick, embedded newlines).
- Tools can pass a `top_n` cap so a 50k-row report never blows the LLM
  context window — the helper truncates and emits a count of hidden rows.

Pure function, no I/O, no global state. Tested in tests/test_table.py.
"""

from __future__ import annotations


def _escape_cell(value: str) -> str:
    """Make a cell value safe to embed in a Markdown table row.

    Embedded newlines are replaced with ``<br>`` so a multi-line value
    (e.g. a sudo COMMAND with a literal ``\n``) does not break the row.
    """
    return (
        str(value)
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
        .replace("\r", "<br>")
    )


def emit_table(
    headers: list[str],
    rows: list[list[str]],
    top_n: int | None = None,
    footer_note: str = "",
) -> str:
    """Render a GitHub-flavored Markdown table with bounded row count.

    Args:
        headers: Column headers (rendered verbatim — assumed already safe).
        rows: List of rows; each row is a list of cell values. Cells are
            escaped: ``|`` -> ``\\|``, `` ` `` -> ``\\``` ``, and newlines
            -> ``<br>``.
        top_n: If set and ``len(rows) > top_n``, only the first ``top_n``
            rows are rendered and a hidden-row count line is appended.
        footer_note: Optional extra line appended after the table (and after
            the truncation note, if any).

    Returns:
        Assembled Markdown string. No trailing newline.
    """
    header_line = "| " + " | ".join(headers) + " |"
    sep_line = "|" + "|".join("------" for _ in headers) + "|"
    out = [header_line, sep_line]

    visible = rows
    hidden = 0
    if top_n is not None and len(rows) > top_n:
        visible = rows[:top_n]
        hidden = len(rows) - top_n

    for row in visible:
        out.append("| " + " | ".join(_escape_cell(c) for c in row) + " |")

    if hidden:
        out.append(f"\n[{hidden} more rows hidden — pass top_n={len(rows)} to see more]")

    if footer_note:
        out.append(footer_note)

    return "\n".join(out)
