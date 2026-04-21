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
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

import requests
from anthropic import Anthropic, APIStatusError, RateLimitError

DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_TOKENS_PER_CALL = 8000
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

Rules:
- Only flag real, actionable issues. Do not comment on style preferences or
  restate what the code does.
- Prioritize: security (auth, injection, secrets, SSRF, deserialization),
  correctness (logic bugs, race conditions, missing error handling at
  boundaries), and data integrity (DB migrations, schema changes).
- Use severity: "high" for bugs/security risks, "medium" for likely issues,
  "low" for polish/nits. Only high/medium will be posted inline; low goes
  into the summary.
- For each inline comment, give the file path exactly as shown in the diff
  and the NEW file line number (the line as it appears in the added/modified
  version). Only comment on lines present in the diff.
- Keep each comment body short: the problem in one sentence, the fix in one
  sentence, optional one line of code.
- If the MR looks clean, emit zero comments and a short summary saying so.
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
            diffs.append((path, patch))
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
        "Review the following MR diff. Focus on bugs, security, and "
        "correctness. Respond only via the emit_review tool.\n" + chunk
    )
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=MAX_TOKENS_PER_CALL,
                system=SYSTEM_PROMPT,
                tools=[EMIT_REVIEW_TOOL],
                tool_choice={"type": "tool", "name": "emit_review"},
                messages=[{"role": "user", "content": user_msg}],
            )
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


def marker(head_sha: str) -> str:
    return f"<!-- claude-review:{head_sha[:12]} -->"


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
    body = (
        f"{marker(env.head_sha)} `{comment_fingerprint(comment)}`\n"
        f"**[claude · {comment['severity']}]** {comment['body']}"
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
    try:
        post_note(env, f"`{comment['file']}:{comment['line']}` — "
                       f"**[claude · {comment['severity']}]** {comment['body']}")
        return "fallback"
    except requests.RequestException as exc:
        print(f"[claude-review] fallback note failed: {exc}", file=sys.stderr)
        return "failed"


def post_note(env: Env, body: str) -> None:
    url = f"{env.api_url}/projects/{env.project_id}/merge_requests/{env.mr_iid}/notes"
    full = f"{marker(env.head_sha)}\n{body}"
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
            f"**Claude review** (model `{env.model}`, commit `{env.head_sha[:12]}`)",
            "",
            f"- Inline comments: {inline_count}",
        ]
        if fallback_count:
            summary_lines.append(f"- Fallback notes: {fallback_count}")
        summary_lines.append(f"- Low-severity notes: {len(low_notes)}")
        if summaries:
            summary_lines += ["", "### Summary", *summaries]
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
