#!/usr/bin/env python3
"""Drift guard for the project wiki (#873).

The wiki is a separate repository with no pull-request gate, so it can drift from
the code silently - exactly how the Architecture pages once claimed a module split
that was already done. This lints a local wiki checkout against the code tree and
fails on the drift classes the consolidation (#871/#872) removed, so they cannot
creep back:

  1. Broken internal anchors  - a [text](Page#anchor) whose page or heading is gone.
  2. file:line citations      - pinning `Something.cs:123` in prose; the rule is to
                                cite modules and type names, never paths that move.
  3. Dead source links        - a blob/<ref>/<path> link to a file not at that ref.

Check 3 honours the ref the link names (#1780). A link naming the branch the code
checkout is on, or `HEAD`, resolves against that checkout's git INDEX, so a local run
and a CI run reach the same verdict on the same wiki: a file the repository ignores
but a developer still has on disk is not scored live. A link naming any other ref
resolves against that ref as `origin` serves it, fetched once per ref, so a page
citing a file on another release line reads as live exactly when that file is there.
A ref that origin does not have is a finding that names the ref. Point it at a git
work tree; if it is not one, the run says so and falls back to the filesystem.

Usage: wiki-lint.py <wiki_dir> <code_repo_dir>
Exit code 1 (with a report) on any finding; 0 when clean.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# GitHub heading-slug rules: lowercase, drop everything that is not a word char,
# space, or hyphen, then spaces -> hyphens. Good enough for our own headings.
_SLUG_STRIP = re.compile(r"[^\w\- ]")


def slugify(heading: str) -> str:
    text = heading.strip().lower()
    text = _SLUG_STRIP.sub("", text)
    return text.replace(" ", "-")


def page_slug(md_path: Path) -> str:
    # Wiki links address a page by its filename with spaces/hyphens interchangeable.
    return md_path.stem.replace(" ", "-").lower()


def heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            slugs.add(slugify(m.group(1)))
    return slugs


_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
# A markdown link target we treat as an intra-wiki page reference: no scheme, not an
# anchor-only (#...) or a mailto, and not an absolute path.
_EXTERNAL = re.compile(r"^(https?:|mailto:|#|/)")


def check_anchors(wiki: Path) -> list[str]:
    pages = {page_slug(p): p for p in wiki.glob("*.md")}
    slugs_by_page = {s: heading_slugs(p.read_text(encoding="utf-8")) for s, p in pages.items()}
    findings: list[str] = []
    for src, path in pages.items():
        for target in _LINK.findall(path.read_text(encoding="utf-8")):
            target = target.strip()
            if _EXTERNAL.match(target):
                continue
            page, _, anchor = target.partition("#")
            key = page.replace(" ", "-").lower()
            if key not in pages:
                findings.append(f"{path.name}: link to unknown wiki page '{page}'")
                continue
            if anchor and slugify(anchor) not in slugs_by_page[key]:
                findings.append(f"{path.name}: broken anchor '#{anchor}' on page '{page}'")
    return findings


_FILELINE = re.compile(r"[\w./-]+\.cs:\d+")


def check_file_line_citations(wiki: Path) -> list[str]:
    findings: list[str] = []
    for path in wiki.glob("*.md"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for hit in _FILELINE.findall(line):
                findings.append(
                    f"{path.name}:{n}: file:line citation '{hit}' - cite the module/type, not a path that moves"
                )
    return findings


# A source link names a ref and a path; both are read, because a path that is
# right on one release line is dead on another (#1780).
_BLOB = re.compile(r"github\.com/[^/]+/[^/]+/blob/([^/]+)/([^)#\s]+)")
# A ref is fetched only when it reads as a name: letters, digits, dot, underscore and hyphen,
# not starting with a hyphen or a dot. The ref comes out of wiki text and reaches git as an
# argument, and git reads an argument that starts with a hyphen as an option wherever it
# stands, so a link written as blob/--upload-pack=<command>/<path> would otherwise run that
# command on the machine linting. A ref that fails this test is a finding, never a fetch.
_REF_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _git(code: Path, *args: str) -> bytes:
    """Run git in the code tree and return stdout. Raises on a non-zero exit."""
    return subprocess.run(
        ["git", "-C", str(code), *args],
        capture_output=True,
        check=True,
    ).stdout


def _with_parents(paths: set[str]) -> set[str]:
    """The paths plus every directory they imply, so a link to a folder scores live."""
    live = set(paths)
    for path in paths:
        parts = path.split("/")
        live.update("/".join(parts[:i]) for i in range(1, len(parts)))
    return live


def tracked_paths(code: Path) -> set[str] | None:
    """The repo-relative POSIX paths git has in its index, plus every directory they imply.

    Returns None when `code` is not a git work tree, or git is unavailable - the caller then
    falls back to the filesystem and says so, rather than scoring every link dead.
    """
    try:
        out = _git(code, "ls-files", "-z")
    except (OSError, subprocess.SubprocessError):
        return None
    return _with_parents({p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p})


def checked_out_branch(code: Path) -> str | None:
    """The branch the code tree has checked out, or None when detached or not a git tree."""
    try:
        name = _git(code, "rev-parse", "--abbrev-ref", "HEAD").decode("utf-8", "surrogateescape").strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return None if name in ("", "HEAD") else name


def tracked_paths_at(code: Path, ref: str) -> set[str] | None:
    """The paths at `ref` as `origin` serves it, plus the directories they imply.

    The ref is fetched rather than read from a remote-tracking branch, because a CI checkout
    holds one branch at depth 1 and a developer's clone may hold a stale copy of another. The
    fetch is depth-limited only where the checkout is already shallow: `--depth` on a full
    clone would turn it into a shallow one as a side effect of a lint.

    Returns None when origin does not serve the ref, or the fetch fails - the caller then
    reports the link with the ref in the message.
    """
    try:
        shallow = _git(code, "rev-parse", "--is-shallow-repository").strip() == b"true"
        depth = ["--depth", "1"] if shallow else []
        _git(code, "fetch", "--quiet", *depth, "origin", ref)
        sha = _git(code, "rev-parse", "FETCH_HEAD").decode("ascii").strip()
        out = _git(code, "ls-tree", "-r", "-z", "--name-only", sha)
    except (OSError, subprocess.SubprocessError):
        return None
    return _with_parents({p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p})


def check_dead_source_links(wiki: Path, code: Path) -> list[str]:
    # Resolved against the INDEX, not the filesystem. A file the repository ignores can still sit in a
    # developer's working checkout, and .exists() scores it live - so the same wiki linted clean locally
    # and reported findings in CI, where actions/checkout materialises tracked files only (#1152).
    tracked = tracked_paths(code)
    if tracked is None:
        print(
            f"warning: '{code}' is not a readable git work tree - source links are checked against the "
            "filesystem whatever ref they name, so an ignored-but-present file will score live and this "
            "verdict may differ from CI.",
            file=sys.stderr,
        )

    # The checkout answers only for the branch it is on. On a gollum run that is the default branch, so
    # a link naming the other release line was looked up in a tree that never held its file, and the
    # 4.3 line's workflows on main read as dead the moment #1771 moved them off 5.1 (#1780).
    branch = checked_out_branch(code)
    at_ref: dict[str, set[str] | None] = {}

    def paths_at(ref: str) -> set[str] | None:
        if ref not in at_ref:
            at_ref[ref] = tracked_paths_at(code, ref)
        return at_ref[ref]

    def verdict(ref: str, rel: str) -> str | None:
        rel = rel.rstrip("/")
        if tracked is None:
            return None if (code / rel).exists() else "not on disk"
        if ref == "HEAD" or ref == branch:
            return None if rel in tracked else "not in the code tree"
        if not _REF_NAME.fullmatch(ref):
            return f"ref '{ref}' is not a name this check fetches"
        paths = paths_at(ref)
        if paths is None:
            return f"ref '{ref}' could not be fetched from origin"
        return None if rel in paths else f"not at '{ref}'"

    findings: list[str] = []
    for path in wiki.glob("*.md"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for ref, rel in _BLOB.findall(line):
                reason = verdict(ref, rel)
                if reason is not None:
                    findings.append(f"{path.name}:{n}: dead source link '{rel}' ({reason})")
    return findings


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    wiki, code = Path(sys.argv[1]), Path(sys.argv[2])
    findings = (
        check_anchors(wiki)
        + check_file_line_citations(wiki)
        + check_dead_source_links(wiki, code)
    )
    if findings:
        print(f"Wiki lint found {len(findings)} issue(s):\n")
        for f in findings:
            print(f"  - {f}")
        print("\nFix the wiki (or the citation rule in Coding-Standards) and re-run.")
        return 1
    print("Wiki lint: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
