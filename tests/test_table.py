"""Tests for the Markdown table helper in findevil._table."""

from findevil._table import emit_table


def test_basic_two_by_two_renders_with_pipes():
    out = emit_table(["A", "B"], [["1", "2"], ["3", "4"]])
    lines = out.splitlines()
    assert lines[0] == "| A | B |"
    assert lines[1] == "|------|------|"
    assert lines[2] == "| 1 | 2 |"
    assert lines[3] == "| 3 | 4 |"
    # No truncation footer when uncapped
    assert "more rows hidden" not in out


def test_pipe_in_cell_is_escaped():
    out = emit_table(["Cmd"], [["echo a | tee b"]])
    body = out.splitlines()[2]
    assert body == "| echo a \\| tee b |"


def test_backtick_in_cell_is_escaped():
    out = emit_table(["Cmd"], [["rm `which cron`"]])
    assert "rm \\`which cron\\`" in out
    # Raw unescaped backtick should not appear in the body row.
    body = out.splitlines()[2]
    assert "`" not in body.replace("\\`", "")


def test_top_n_truncates_and_emits_hidden_footer():
    rows = [[str(i)] for i in range(5)]
    out = emit_table(["N"], rows, top_n=2)
    lines = out.splitlines()
    # Header + separator + 2 body rows
    assert lines[0] == "| N |"
    assert lines[2] == "| 0 |"
    assert lines[3] == "| 1 |"
    # No row "2" should appear — only the hidden-row notice.
    assert "| 2 |" not in out
    assert "3 more rows hidden" in out
    assert "top_n=5" in out


def test_empty_rows_produces_only_header_and_separator():
    out = emit_table(["A", "B"], [])
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[0] == "| A | B |"
    assert lines[1] == "|------|------|"


def test_newline_in_cell_does_not_break_row():
    out = emit_table(["Note"], [["line1\nline2"]])
    lines = out.splitlines()
    # Header + sep + exactly one body row — embedded \n must be replaced.
    assert len(lines) == 3
    assert lines[2] == "| line1<br>line2 |"


def test_top_n_none_does_not_truncate():
    rows = [[str(i)] for i in range(10)]
    out = emit_table(["N"], rows, top_n=None)
    assert "more rows hidden" not in out
    # All 10 rows + header + sep
    assert len(out.splitlines()) == 12


def test_top_n_equal_to_len_does_not_truncate():
    rows = [[str(i)] for i in range(3)]
    out = emit_table(["N"], rows, top_n=3)
    assert "more rows hidden" not in out


def test_footer_note_is_appended():
    out = emit_table(["A"], [["1"]], footer_note="**Summary:** 1 row")
    assert out.endswith("**Summary:** 1 row")
