#!/usr/bin/env python3
"""
Claude-powered GitLab MR reviewer.

Runs as a GitLab CI job on Ready (non-Draft) Merge Request pipelines.
Collects the MR diff, asks Claude for structured review comments, and
posts them as inline discussions + a summary note on the MR.

Non-blocking: any failure degrades to a summary note and exits 0 so the
pipeline does not fail on reviewer-side issues.

Required env vars (all provided by GitLab CI + .get-secrets):
  ANTHROPIC_API_KEY
  GITLAB_REVIEW_TOKEN          project access token with `api` scope
  CI_API_V4_URL                e.g. https://gitlab.com/api/v4
  CI_PROJECT_ID
  CI_MERGE_REQUEST_IID
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME
  CI_MERGE_REQUEST_DIFF_BASE_SHA
  CI_COMMIT_SHA
Optional:
  CLAUDE_MODEL                 default: claude-sonnet-4-6
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

import requests
from anthropic import Anthropic, APIStatusError, RateLimitError

DEFAULT_MODEL = "claude-sonnet-4-6"
RESPONSE_TOKEN_BUDGET = 8000
DEFAULT_THINKING_BUDGET = 8000
MAX_INPUT_CHARS_PER_CHUNK = 280_000  # rough proxy for ~80k input tokens
MAX_FILE_DIFF_LINES = 1500
SKIP_PATH_SUFFIXES = (
    ".min.js", ".min.css", ".map",
    "uv.lock", "package-lock.json", "poetry.lock", "yarn.lock",
    "Cargo.lock", "composer.lock",
)
SKIP_PATH_CONTAINS = ("vendor/", "node_modules/", "dist/", "build/")

SYSTEM_PROMPT = """You are a senior code reviewer for Faraday, a Python-based
security platform. You are reviewing a GitLab merge request diff.

Diff format note: every diff line is prefixed with the NEW-file line number
like "  123: + added line" or "  123:   context line". Removed lines have
the prefix "     : - removed line" (no new-file number). When you emit an
inline comment, the `line` field MUST be the number taken directly from
that prefix — nothing else. Never estimate or count. If the line you want
to flag has no prefix number (it was removed), do not emit an inline
comment on it; put the observation in the summary instead.

Your review must be comprehensive and consistent, not a sample. Work in
two phases before emitting the tool call:

Phase 1 — Scan. Read every hunk carefully. Enumerate every potential
concern, no matter how minor, across these categories:
  - Correctness: logic bugs, off-by-one, wrong operator, unreachable code,
    state machine issues, broken invariants, silently-swallowed errors,
    missing error handling at system boundaries.
  - Security: auth bypass, injection (SQL/shell/template), deserialization,
    SSRF, path traversal, secrets in code/logs, unsafe crypto, race
    conditions that affect auth or data integrity.
  - Data integrity: DB migrations, schema drift, missing indexes that
    change query behavior, breaking API/contract changes.
  - Maintainability: duplication, dead code, misleading names, broken
    abstractions — only when the diff clearly shows them.

Phase 2 — Filter. For each phase-1 item, decide:
  - Is it actually present in the diff (not speculative)? Drop if speculative.
  - Is it actionable by the author? Drop if not.
  - Severity: "high" (bug/security risk), "medium" (likely issue),
    "low" (nit/polish).

Emit EVERY remaining high and medium finding via emit_review — do not
cherry-pick. A reviewer running this same check on the same diff should
converge on the same list. Low-severity items go into the summary.

Other rules:
- For each inline comment, use the file path exactly as shown in the
  "===== FILE: <path> =====" header and the exact new-file line number
  from the line's prefix.
- Body format: one-sentence problem, one-sentence fix, optional one line of
  code. No preamble, no restating the code.
- If the MR truly has no high or medium findings, emit zero comments and
  a short summary saying so.
- Never hallucinate. If unsure, skip it.

Return your review by calling the emit_review tool exactly once."""

EMIT_REVIEW_TOOL = {
    "name": "emit_review",
    "description": "Emit structured review output for the MR diff.",
    "input_schema": {
        "type": "object",
        "properties": {
            "comments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string"},
                        "line": {"type": "integer"},
                        "severity": {"enum": ["low", "medium", "high"]},
                        "body": {"type": "string"},
                    },
                    "required": ["file", "line", "severity", "body"],
                },
            },
            "summary": {"type": "string"},
        },
        "required": ["comments", "summary"],
    },
}


@dataclass
class Env:
    anthropic_key: str
    gitlab_token: str
    api_url: str
    project_id: str
    mr_iid: str
    target_branch: str
    base_sha: str
    head_sha: str
    model: str


def _resolve_secret(value: str) -> str:
    """GitLab Vault secrets default to file-based since 15.7 — the env var
    holds a path to a file containing the actual value. Handle both forms."""
    if value and os.path.isfile(value):
        with open(value) as f:
            return f.read().strip()
    return value.strip() if value else value


def load_env() -> Env:
    required = [
        "ANTHROPIC_API_KEY",
        "GITLAB_REVIEW_TOKEN",
        "CI_API_V4_URL",
        "CI_PROJECT_ID",
        "CI_MERGE_REQUEST_IID",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
        "CI_MERGE_REQUEST_DIFF_BASE_SHA",
        "CI_COMMIT_SHA",
    ]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        raise RuntimeError(f"missing env vars: {', '.join(missing)}")
    return Env(
        anthropic_key=_resolve_secret(os.environ["ANTHROPIC_API_KEY"]),
        gitlab_token=_resolve_secret(os.environ["GITLAB_REVIEW_TOKEN"]),
        api_url=os.environ["CI_API_V4_URL"].rstrip("/"),
        project_id=os.environ["CI_PROJECT_ID"],
        mr_iid=os.environ["CI_MERGE_REQUEST_IID"],
        target_branch=os.environ["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"],
        base_sha=os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"],
        head_sha=os.environ["CI_COMMIT_SHA"],
        model=os.environ.get("CLAUDE_MODEL", DEFAULT_MODEL),
    )


def git(*args: str) -> str:
    out = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout


def should_skip_path(path: str) -> bool:
    if any(path.endswith(s) for s in SKIP_PATH_SUFFIXES):
        return True
    if any(s in path for s in SKIP_PATH_CONTAINS):
        return True
    return False


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def annotate_patch(patch: str) -> str:
    """Prepend each diff line with its NEW-file line number so the model
    cannot confuse diff-local offsets with file line numbers.

    Added / context lines: "  123: + added" / "  123:   context"
    Removed lines:         "     : - removed"
    Headers are left unchanged.
    """
    out: list[str] = []
    new_line: int | None = None
    for line in patch.splitlines():
        if line.startswith("@@"):
            m = HUNK_HEADER_RE.match(line)
            new_line = int(m.group(1)) if m else None
            out.append(line)
            continue
        if line.startswith(("diff ", "index ", "--- ", "+++ ", "new file ",
                            "deleted file ", "rename ", "similarity ",
                            "Binary ")):
            out.append(line)
            continue
        if new_line is None:
            out.append(line)
            continue
        if line.startswith("+") and not line.startswith("+++"):
            out.append(f"{new_line:5d}: {line}")
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            out.append(f"     : {line}")
        elif line.startswith(" ") or line == "":
            out.append(f"{new_line:5d}: {line}")
            new_line += 1
        else:
            out.append(line)
    return "\n".join(out)


def _parse_numstat_z(raw: str) -> list[tuple[str, str, str]]:
    """Parse `git diff --numstat -z` output into (added, removed, new_path) tuples.

    Format per git: normal entries are ``added\\tremoved\\tpath\\0``;
    rename/copy entries are ``added\\tremoved\\t\\0oldpath\\0newpath\\0``.
    NUL terminates each logical entry.
    """
    entries: list[tuple[str, str, str]] = []
    parts = raw.split("\0")
    i = 0
    while i < len(parts):
        piece = parts[i]
        if not piece:
            i += 1
            continue
        fields = piece.split("\t", 2)
        if len(fields) < 3:
            i += 1
            continue
        added, removed, path = fields
        if path == "":
            # rename/copy: next two NUL-separated parts are oldpath, newpath
            if i + 2 >= len(parts):
                break
            newpath = parts[i + 2]
            entries.append((added, removed, newpath))
            i += 3
        else:
            entries.append((added, removed, path))
            i += 1
    return entries


def collect_diff(env: Env) -> list[tuple[str, str]]:
    """Return list of (file_path, unified_diff_text) for reviewable files."""
    numstat = git("diff", "--numstat", "-z", f"{env.base_sha}..{env.head_sha}")
    reviewable: list[str] = []
    skipped_notes: list[str] = []
    for added, removed, path in _parse_numstat_z(numstat):
        if added == "-" and removed == "-":
            skipped_notes.append(f"{path} (binary)")
            continue
        if should_skip_path(path):
            skipped_notes.append(f"{path} (generated/vendored)")
            continue
        try:
            total = int(added) + int(removed)
        except ValueError:
            total = 0
        if total > MAX_FILE_DIFF_LINES:
            skipped_notes.append(f"{path} ({total} lines, too large)")
            continue
        reviewable.append(path)

    if skipped_notes:
        print("[claude-review] skipped files:")
        for n in skipped_notes:
            print(f"  - {n}")

    diffs: list[tuple[str, str]] = []
    for path in reviewable:
        patch = git(
            "diff",
            "--no-color",
            f"{env.base_sha}..{env.head_sha}",
            "--",
            path,
        )
        if patch.strip():
            diffs.append((path, annotate_patch(patch)))
    return diffs


def chunk_diffs(diffs: list[tuple[str, str]]) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_size = 0
    for path, patch in diffs:
        block = f"\n\n===== FILE: {path} =====\n{patch}"
        if current_size + len(block) > MAX_INPUT_CHARS_PER_CHUNK and current:
            chunks.append("".join(current))
            current = []
            current_size = 0
        current.append(block)
        current_size += len(block)
    if current:
        chunks.append("".join(current))
    return chunks


def call_claude(client: Anthropic, model: str, chunk: str) -> dict[str, Any]:
    user_msg = (
        "Review the following MR diff. Do a Phase 1 scan and Phase 2 filter "
        "as specified in your instructions, then respond via the emit_review "
        "tool.\n" + chunk
    )
    thinking_budget = int(os.environ.get(
        "CLAUDE_THINKING_BUDGET", DEFAULT_THINKING_BUDGET
    ))
    kwargs: dict[str, Any] = dict(
        model=model,
        max_tokens=thinking_budget + RESPONSE_TOKEN_BUDGET,
        system=SYSTEM_PROMPT,
        tools=[EMIT_REVIEW_TOOL],
        # Extended thinking disallows any form of forced tool use. `auto`
        # lets Claude choose — with one tool defined and the system prompt
        # explicitly instructing to call it, this reliably triggers it.
        tool_choice={"type": "auto"},
        messages=[{"role": "user", "content": user_msg}],
    )
    if thinking_budget > 0:
        kwargs["thinking"] = {
            "type": "enabled",
            "budget_tokens": thinking_budget,
        }
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = client.messages.create(**kwargs)
        except (RateLimitError, APIStatusError) as exc:
            status = getattr(exc, "status_code", None)
            if attempt >= 3 or (status and status < 500 and status not in (408, 429)):
                raise
            time.sleep(2 ** attempt)
            continue
        for block in resp.content:
            if block.type == "tool_use" and block.name == "emit_review":
                return block.input
        return {"comments": [], "summary": "(model returned no structured output)"}


SEVERITY_BADGE = {
    "high": "High severity",
    "medium": "Medium severity",
    "low": "Low severity",
}


def marker(head_sha: str) -> str:
    return f"<!-- claude-review:{head_sha[:12]} -->"


def hidden_meta(env: Env, fingerprint: str | None = None) -> str:
    """Invisible HTML-comment footer carrying the markers used for dedupe."""
    parts = [marker(env.head_sha)]
    if fingerprint:
        parts.append(f"<!-- fp:{fingerprint} -->")
    return "\n\n" + " ".join(parts)


def gitlab_headers(env: Env) -> dict[str, str]:
    return {"PRIVATE-TOKEN": env.gitlab_token}


def list_existing_discussions(env: Env) -> list[dict[str, Any]]:
    url = f"{env.api_url}/projects/{env.project_id}/merge_requests/{env.mr_iid}/discussions"
    results: list[dict[str, Any]] = []
    page = 1
    while True:
        r = requests.get(
            url,
            headers=gitlab_headers(env),
            params={"per_page": 100, "page": page},
            timeout=30,
        )
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        results.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return results


def existing_markers(discussions: list[dict[str, Any]]) -> set[str]:
    seen: set[str] = set()
    for d in discussions:
        for note in d.get("notes", []):
            body = note.get("body", "")
            if "<!-- claude-review:" in body:
                start = body.find("<!-- claude-review:") + len("<!-- claude-review:")
                end = body.find(" -->", start)
                if end > 0:
                    seen.add(body[start:end].strip())
    return seen


def comment_fingerprint(c: dict[str, Any]) -> str:
    raw = f"{c['file']}|{c['line']}|{c['body']}"
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


def _valid_comment(c: Any) -> bool:
    return (
        isinstance(c, dict)
        and isinstance(c.get("file"), str)
        and isinstance(c.get("line"), int)
        and isinstance(c.get("body"), str)
        and c.get("severity") in ("low", "medium", "high")
    )


def post_inline(env: Env, comment: dict[str, Any]) -> str:
    """Post a review comment. Returns 'inline', 'fallback', or 'failed'."""
    url = f"{env.api_url}/projects/{env.project_id}/merge_requests/{env.mr_iid}/discussions"
    badge = SEVERITY_BADGE.get(comment["severity"], comment["severity"].title())
    body = (
        f"**Claude review** · {badge}\n\n"
        f"{comment['body']}"
        f"{hidden_meta(env, comment_fingerprint(comment))}"
    )
    data = {
        "body": body,
        "position[base_sha]": env.base_sha,
        "position[start_sha]": env.base_sha,
        "position[head_sha]": env.head_sha,
        "position[position_type]": "text",
        "position[new_path]": comment["file"],
        "position[new_line]": comment["line"],
    }
    r = requests.post(url, headers=gitlab_headers(env), data=data, timeout=30)
    if r.status_code in (200, 201):
        return "inline"
    print(f"[claude-review] inline post failed ({r.status_code}) for "
          f"{comment['file']}:{comment['line']} — falling back to note")
    badge = SEVERITY_BADGE.get(comment["severity"], comment["severity"].title())
    try:
        post_note(
            env,
            f"**Claude review** · {badge} · `{comment['file']}:{comment['line']}`\n\n"
            f"{comment['body']}",
        )
        return "fallback"
    except requests.RequestException as exc:
        print(f"[claude-review] fallback note failed: {exc}", file=sys.stderr)
        return "failed"


def post_note(env: Env, body: str) -> None:
    url = f"{env.api_url}/projects/{env.project_id}/merge_requests/{env.mr_iid}/notes"
    full = f"{body}{hidden_meta(env)}"
    r = requests.post(
        url, headers=gitlab_headers(env), data={"body": full}, timeout=30,
    )
    r.raise_for_status()


def main() -> int:
    title = os.environ.get("CI_MERGE_REQUEST_TITLE", "")
    if title.lower().startswith(("draft:", "wip:")):
        print(f"[claude-review] MR is Draft ({title!r}), skipping review")
        return 0

    try:
        env = load_env()
    except Exception as exc:
        print(f"[claude-review] env error: {exc}", file=sys.stderr)
        return 0

    try:
        existing = existing_markers(list_existing_discussions(env))
        if env.head_sha[:12] in existing:
            print("[claude-review] already reviewed this SHA, exiting")
            return 0

        diffs = collect_diff(env)
        if not diffs:
            post_note(env, "_No reviewable changes in this MR._")
            return 0

        total_chars = sum(len(p) for _, p in diffs)
        print(f"[claude-review] {len(diffs)} files, ~{total_chars} chars, "
              f"model={env.model}")

        chunks = chunk_diffs(diffs)
        client = Anthropic(api_key=env.anthropic_key)

        all_comments: list[dict[str, Any]] = []
        summaries: list[str] = []
        for i, chunk in enumerate(chunks, 1):
            print(f"[claude-review] chunk {i}/{len(chunks)} "
                  f"({len(chunk)} chars)")
            result = call_claude(client, env.model, chunk)
            all_comments.extend(result.get("comments", []))
            s = result.get("summary", "").strip()
            if s:
                summaries.append(s)

        # drop malformed entries from the model
        valid_comments: list[dict[str, Any]] = []
        for c in all_comments:
            if _valid_comment(c):
                valid_comments.append(c)
            else:
                print(f"[claude-review] dropping malformed comment: {c!r}",
                      file=sys.stderr)

        # dedupe within this run
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for c in valid_comments:
            fp = comment_fingerprint(c)
            if fp in seen:
                continue
            seen.add(fp)
            unique.append(c)

        inline = [c for c in unique if c["severity"] in ("medium", "high")]
        low_notes = [c for c in unique if c["severity"] == "low"]

        inline_count = 0
        fallback_count = 0
        for c in inline:
            try:
                result = post_inline(env, c)
            except requests.RequestException as exc:
                print(f"[claude-review] post error: {exc}", file=sys.stderr)
                continue
            if result == "inline":
                inline_count += 1
            elif result == "fallback":
                fallback_count += 1

        summary_lines = [
            "## Claude review",
            "",
            f"**Model** `{env.model}` · **Commit** `{env.head_sha[:12]}`",
            "",
            f"| Inline | Fallback | Nits |",
            f"| ---: | ---: | ---: |",
            f"| {inline_count} | {fallback_count} | {len(low_notes)} |",
        ]
        if summaries:
            summary_lines += ["", "### Overview", *summaries]
        if low_notes:
            summary_lines += ["", "### Nits"]
            for c in low_notes:
                summary_lines.append(
                    f"- `{c['file']}:{c['line']}` — {c['body']}"
                )
        post_note(env, "\n".join(summary_lines))
        return 0

    except Exception as exc:
        print(f"[claude-review] fatal: {exc}", file=sys.stderr)
        try:
            post_note(
                env,
                f"_Claude review failed: `{type(exc).__name__}`. "
                f"See job log for details._",
            )
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
