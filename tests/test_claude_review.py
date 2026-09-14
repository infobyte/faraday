"""Tests for the helpers in .gitlab/ci/scripts/claude_review.py.

Only covers pure helpers (regex, formatting, lookup-order resolution
with mocked requests). The end-to-end review flow can't be exercised
locally — that requires a live GitLab MR.

The script imports `anthropic` at module level (a CI-only dep). We stub
it before importing so the tests run in dev environments too.
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / ".gitlab" / "ci" / "scripts" / "claude_review.py"
)


def _stub_anthropic():
    if "anthropic" in sys.modules:
        return
    fake = types.ModuleType("anthropic")
    fake.Anthropic = type("Anthropic", (), {})
    fake.APIConnectionError = type("APIConnectionError", (Exception,), {})
    fake.APIStatusError = type("APIStatusError", (Exception,), {})
    fake.APITimeoutError = type("APITimeoutError", (Exception,), {})
    fake.RateLimitError = type("RateLimitError", (Exception,), {})
    sys.modules["anthropic"] = fake


@pytest.fixture(scope="module")
def cr():
    _stub_anthropic()
    spec = importlib.util.spec_from_file_location("claude_review_mod", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["claude_review_mod"] = module
    spec.loader.exec_module(module)
    return module


def _env(cr, mr_iid="42", branch=""):
    return cr.Env(
        anthropic_key="k",
        gitlab_token="t",
        api_url="https://example/api/v4",
        project_id="1",
        mr_iid=mr_iid,
        base_sha="b" * 40,
        head_sha="h" * 40,
        model="claude-sonnet-4-6",
        branch=branch,
    )


def test_branch_ticket_re_matches_white(cr):
    m = cr.BRANCH_TICKET_RE.match("tkt_white_8259_more_claude_review")
    assert m and m.group(1) == "8259"


def test_branch_ticket_re_matches_black(cr):
    m = cr.BRANCH_TICKET_RE.match("tkt_black_8250_fix_security_issues")
    assert m and m.group(1) == "8250"


def test_branch_ticket_re_rejects_unrelated(cr):
    assert cr.BRANCH_TICKET_RE.match("feature_x") is None
    assert cr.BRANCH_TICKET_RE.match("tkt_unknown_1_x") is None


def test_issue_ref_re_finds_closes_and_resolves(cr):
    assert cr.ISSUE_REF_RE.findall("Closes #42 and resolves #99") == ["42", "99"]


def test_issue_ref_re_rejects_plain_hash(cr):
    assert cr.ISSUE_REF_RE.findall("see #100 for context") == []


def test_issue_ref_re_requires_word_boundary(cr):
    assert cr.ISSUE_REF_RE.findall("Fixes#42") == []


def test_issue_ref_re_related_to(cr):
    assert cr.ISSUE_REF_RE.findall("related to #7") == ["7"]


def test_format_issue_block_truncates_long_body(cr):
    issue = {
        "iid": 1,
        "title": "x",
        "web_url": "https://example/issues/1",
        "description": "a" * (cr.MAX_ISSUE_BODY_CHARS + 500),
    }
    block = cr._format_issue_block(issue)
    assert "[truncated]" in block
    assert "=== LINKED ISSUE #1 ===" in block
    assert "=== END LINKED ISSUE #1 ===" in block


def test_format_issue_block_short_body_not_truncated(cr):
    issue = {
        "iid": 5,
        "title": "Short",
        "web_url": "https://example/issues/5",
        "description": "tiny body",
    }
    block = cr._format_issue_block(issue)
    assert "[truncated]" not in block
    assert "tiny body" in block


def test_resolve_priority_closes_issues_first(cr):
    """closes_issues API result wins over description scan."""
    env = _env(cr, branch="tkt_white_999_x")
    mr_detail = {"description": "Closes #42"}
    fake_resp = mock.Mock(status_code=200)
    fake_resp.json.return_value = [{"iid": 7}]
    fake_resp.raise_for_status = mock.Mock()
    with mock.patch.object(cr.requests, "get", return_value=fake_resp):
        iids = cr._resolve_linked_issue_iids(env, mr_detail)
    assert iids == [7, 42, 999]


def test_resolve_branch_fallback_only(cr):
    """When closes_issues + description return nothing, branch supplies the iid."""
    env = _env(cr, branch="tkt_white_8259_x")
    fake_resp = mock.Mock(status_code=200)
    fake_resp.json.return_value = []
    fake_resp.raise_for_status = mock.Mock()
    with mock.patch.object(cr.requests, "get", return_value=fake_resp):
        iids = cr._resolve_linked_issue_iids(env, {"description": ""})
    assert iids == [8259]


def test_resolve_dedupes(cr):
    env = _env(cr, branch="tkt_white_42_x")
    mr_detail = {"description": "Closes #42"}
    fake_resp = mock.Mock(status_code=200)
    fake_resp.json.return_value = [{"iid": 42}]
    fake_resp.raise_for_status = mock.Mock()
    with mock.patch.object(cr.requests, "get", return_value=fake_resp):
        iids = cr._resolve_linked_issue_iids(env, mr_detail)
    assert iids.count(42) == 1


def test_resolve_caps_at_max(cr):
    env = _env(cr)
    desc = " ".join(f"closes #{i}" for i in range(1, 11))
    mr_detail = {"description": desc}
    fake_resp = mock.Mock(status_code=200)
    fake_resp.json.return_value = []
    fake_resp.raise_for_status = mock.Mock()
    with mock.patch.object(cr.requests, "get", return_value=fake_resp):
        iids = cr._resolve_linked_issue_iids(env, mr_detail)
    assert len(iids) == cr.MAX_ISSUES_TO_FETCH


def test_resolve_no_linkage_returns_empty(cr):
    env = _env(cr, branch="feature_x")  # no tkt_ prefix
    fake_resp = mock.Mock(status_code=200)
    fake_resp.json.return_value = []
    fake_resp.raise_for_status = mock.Mock()
    with mock.patch.object(cr.requests, "get", return_value=fake_resp):
        iids = cr._resolve_linked_issue_iids(env, {"description": ""})
    assert iids == []


def test_fetch_issue_context_none_on_no_iids(cr):
    env = _env(cr, branch="feature_x")
    fake_resp = mock.Mock(status_code=200)
    fake_resp.json.return_value = []
    fake_resp.raise_for_status = mock.Mock()
    with mock.patch.object(cr.requests, "get", return_value=fake_resp):
        assert cr.fetch_issue_context(env, {"description": ""}) is None


def test_fetch_issue_context_skips_inaccessible(cr):
    """403/404 on issue fetch is logged and skipped."""
    env = _env(cr, branch="tkt_white_42_x")

    def fake_get(url, **_kw):
        if "closes_issues" in url:
            r = mock.Mock(status_code=200)
            r.json.return_value = []
            r.raise_for_status = mock.Mock()
            return r
        # issue fetch — simulate 403
        r = mock.Mock(status_code=403)
        return r

    with mock.patch.object(cr.requests, "get", side_effect=fake_get):
        assert cr.fetch_issue_context(env, {"description": ""}) is None


# ---------- changed_lines ----------

def test_changed_lines_only_returns_added(cr):
    annotated = (
        "@@ -1,3 +10,5 @@\n"
        "   10:   ctx\n"
        "   11: +added one\n"
        "   12: +added two\n"
        "     : -removed\n"
        "   13:   ctx2\n"
        "+++ b/file.py\n"
        "--- a/file.py"
    )
    assert cr.changed_lines(annotated) == {11, 12}


def test_changed_lines_handles_empty_patch(cr):
    assert cr.changed_lines("") == set()


def test_changed_lines_ignores_hunk_headers(cr):
    """The `+10` in `@@ -1,3 +10,5 @@` must not be picked up as a +line."""
    annotated = "@@ -1,3 +10,5 @@\n   42: +real add"
    assert cr.changed_lines(annotated) == {42}


# ---------- _block_for_replay ----------

class _FakeBlock:
    """Minimal stand-in for an SDK content block."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_block_for_replay_text_strips_extra_fields(cr):
    """Text blocks must shed `parsed_output` and other SDK extras
    that the API rejects on round-trip."""
    block = _FakeBlock(
        type="text",
        text="hello",
        parsed_output={"foo": "bar"},  # the field that crashed CI
        extra_internal="should be dropped",
    )
    out = cr._block_for_replay(block)
    assert out == {"type": "text", "text": "hello"}
    assert "parsed_output" not in out


def test_block_for_replay_text_preserves_citations(cr):
    block = _FakeBlock(
        type="text",
        text="cited",
        citations=[{"type": "char_location", "cited_text": "x"}],
    )
    out = cr._block_for_replay(block)
    assert out["citations"] == [{"type": "char_location", "cited_text": "x"}]


def test_block_for_replay_tool_use_minimal(cr):
    block = _FakeBlock(
        type="tool_use",
        id="toolu_1",
        name="read_file",
        input={"path": "x.py"},
        partial_json="should be dropped",
    )
    out = cr._block_for_replay(block)
    assert out == {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "read_file",
        "input": {"path": "x.py"},
    }


def test_block_for_replay_thinking_keeps_signature(cr):
    block = _FakeBlock(
        type="thinking",
        thinking="reasoning here",
        signature="sig-bytes",
    )
    out = cr._block_for_replay(block)
    assert out == {
        "type": "thinking",
        "thinking": "reasoning here",
        "signature": "sig-bytes",
    }


def test_block_for_replay_redacted_thinking(cr):
    block = _FakeBlock(type="redacted_thinking", data="opaque")
    out = cr._block_for_replay(block)
    assert out == {"type": "redacted_thinking", "data": "opaque"}
