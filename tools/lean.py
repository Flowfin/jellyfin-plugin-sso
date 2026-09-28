#!/usr/bin/env python3
"""Size report for the lean pass (#1886, #1887).

Counts, over the product C# source and the workflow files, what the pass holds
itself to: code lines, comment lines, comment blocks over BLOCK_LIMIT lines,
methods over METHOD_LIMIT code lines, files over FILE_LIMIT code lines, and,
given a base ref, the comment-line delta of a pull request. It reports and
does not gate; the ratchet is #1906.

A count that cannot fail is not a measurement, so the tool first runs a
positive and a negative fixture whose answers are known, one line inside each
limit and one line over it, and refuses to read the tree on a mismatch.

Usage: lean.py [--base REF] [--all] [ROOT]
"""

import re
import subprocess
import sys
from pathlib import Path

BLOCK_LIMIT = 10
METHOD_LIMIT = 60
FILE_LIMIT = 500

PRODUCT_GLOB = "SSO-Auth/**/*.cs"
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/actions/**/*.yml")
EXCLUDED_PARTS = {"bin", "obj"}

_MODIFIER = r"(?:public|private|protected|internal|static|async|override|virtual|abstract|sealed|partial|new|extern|unsafe)"
_SIGNATURE = re.compile(
    r"^\s*(?:" + _MODIFIER + r"\s+)+(?:[\w<>\[\],.?]+\s+)?(?P<name>\w+)\s*(?:<[^>]*>)?\s*\("
)
_STRING = re.compile(r'(?:\$@|@\$|\$|@)?"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')


def classify(lines):
    """Yield (kind, text) per line: 'blank', 'comment' or 'code'."""
    in_block = False
    for raw in lines:
        text = raw.strip()
        if in_block:
            in_block = "*/" not in text
            yield "comment", text
        elif not text:
            yield "blank", text
        elif text.startswith("//"):
            yield "comment", text
        elif text.startswith("/*"):
            in_block = "*/" not in text
            yield "comment", text
        else:
            yield "code", text


def comment_blocks(kinds):
    """Lengths of every maximal run of comment lines."""
    runs, run = [], 0
    for kind in kinds:
        if kind == "comment":
            run += 1
        elif run:
            runs.append(run)
            run = 0
    if run:
        runs.append(run)
    return runs


def _braces(text):
    text = _STRING.sub('""', text)
    text = text.split("//", 1)[0]
    return text.count("{"), text.count("}")


def _outside_verbatim(text, inside):
    """The part of a line outside a multi-line verbatim string, and whether the line ends inside one."""
    if inside:
        i = 0
        while i < len(text):
            if text[i] == '"':
                if i + 1 < len(text) and text[i + 1] == '"':
                    i += 2
                    continue
                return _outside_verbatim(text[i + 1:], False)
            i += 1
        return "", True
    stripped = _STRING.sub('""', text).split("//", 1)[0]
    at = stripped.find('@"')
    if at < 0:
        at = stripped.find('$@"') if '$@"' in stripped else stripped.find('@$"')
    if at < 0:
        return text, False
    return stripped[:at], True


def methods(classified):
    """Yield (name, body code lines) for every brace-bodied method or constructor."""
    depth = 0
    pending = None
    body = None
    inside = False
    for kind, text in classified:
        if kind != "code":
            continue
        # A verbatim string spanning lines is text, not members: braces and signatures inside it count for nothing.
        text, inside = _outside_verbatim(text, inside)
        if body is not None:
            opened, closed = _braces(text)
            depth += opened - closed
            if depth <= body[1]:
                yield body[0], body[2]
                body = None
            else:
                body = (body[0], body[1], body[2] + 1)
            continue
        opened, closed = _braces(text)
        if pending is None:
            match = _SIGNATURE.match(text)
            if match and "=" not in text.split("(", 1)[0]:
                pending = match.group("name")
        if pending is not None:
            if "=>" in text or text.endswith(";"):
                pending = None
            elif opened:
                body = (pending, depth, 0)
                pending = None
                depth += opened - closed
                if depth <= body[1]:
                    yield body[0], 0
                    body = None
                continue
        depth += opened - closed


def measure(lines):
    """Measure one C# file's lines; returns a dict of the counts the report shows."""
    classified = list(classify(lines))
    kinds = [kind for kind, _ in classified]
    blocks = comment_blocks(kinds)
    longs = [(name, count) for name, count in methods(classified) if count > METHOD_LIMIT]
    return {
        "code": kinds.count("code"),
        "comment": kinds.count("comment"),
        "blocks_over": sum(1 for b in blocks if b > BLOCK_LIMIT),
        "longest_block": max(blocks, default=0),
        "long_methods": longs,
    }


def product_files(root):
    for path in sorted(root.glob(PRODUCT_GLOB)):
        if not EXCLUDED_PARTS.intersection(path.parts):
            yield path


def workflow_lines(root):
    code = comment = 0
    for glob in WORKFLOW_GLOBS:
        for path in sorted(root.glob(glob)):
            for text in path.read_text(encoding="utf-8").splitlines():
                text = text.strip()
                if not text:
                    continue
                if text.startswith("#"):
                    comment += 1
                else:
                    code += 1
    return code, comment


def base_comment_lines(root, ref):
    """Comment lines of the product source at REF, read out of git rather than the checkout."""
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-r", "--name-only", ref, "--", "SSO-Auth"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    total = 0
    for name in listing:
        if name.endswith(".cs"):
            blob = subprocess.run(
                ["git", "-C", str(root), "show", f"{ref}:{name}"],
                check=True, capture_output=True, text=True, encoding="utf-8",
            ).stdout
            total += sum(1 for kind, _ in classify(blob.splitlines()) if kind == "comment")
    return total


def fixture(method_lines, block_lines, file_lines):
    """A C# file with one method of METHOD lines, one comment block of BLOCK lines, padded to FILE code lines."""
    out = ["namespace Fixture;", "internal sealed class Sample", "{"]
    out += ["    // block"] * block_lines
    out += ["    public void Run(int x)", "    {"]
    out += ["        x++;"] * method_lines
    out += ["    }"]
    code_so_far = len(out) - block_lines + 1
    out += ["    private int F%d() => %d;" % (i, i) for i in range(max(0, file_lines - code_so_far))]
    out += ["}"]
    return out


def verbatim_fixture(script_lines):
    """A C# file holding a script inside a verbatim string, then one method over METHOD_LIMIT lines."""
    out = ["namespace Fixture;", "internal sealed class Sample", "{", '    private const string Script = @"']
    out += ["async function main() {"] + ["    await sleep(100);"] * script_lines + ["}", '";']
    out += ["    public void Run(int x)", "    {"] + ["        x++;"] * (METHOD_LIMIT + 1) + ["    }", "}"]
    return out


def calibrate():
    over = measure(fixture(METHOD_LIMIT + 1, BLOCK_LIMIT + 1, FILE_LIMIT + 1))
    under = measure(fixture(METHOD_LIMIT, BLOCK_LIMIT, FILE_LIMIT))
    verbatim = measure(verbatim_fixture(METHOD_LIMIT + 1))
    positive = (over["code"] > FILE_LIMIT, over["blocks_over"] == 1, len(over["long_methods"]) == 1)
    negative = (under["code"] == FILE_LIMIT, under["blocks_over"] == 0, under["long_methods"] == [])
    # The script in the string is not a method, and the method after it is still one.
    verbatim_ok = [name for name, _ in verbatim["long_methods"]] == ["Run"]
    if not all(positive) or not all(negative) or not verbatim_ok:
        sys.exit("lean: calibration failed - positive %s, negative %s, verbatim %s" % (positive, negative, verbatim_ok))
    print("lean: calibration ok - one fixture over each limit, one at each limit, one script in a string")


def main(argv):
    base = None
    show_all = False
    root = Path(".")
    args = list(argv)
    while args:
        arg = args.pop(0)
        if arg == "--base":
            base = args.pop(0)
        elif arg == "--all":
            show_all = True
        else:
            root = Path(arg)
    calibrate()

    rows = {path.relative_to(root).as_posix(): measure(path.read_text(encoding="utf-8").splitlines())
            for path in product_files(root)}
    if not rows:
        sys.exit("lean: no product source under %s" % root)
    code = sum(r["code"] for r in rows.values())
    comment = sum(r["comment"] for r in rows.values())
    big_files = sorted((n for n, r in rows.items() if r["code"] > FILE_LIMIT), key=lambda n: -rows[n]["code"])
    long_methods = [(n, m, c) for n, r in rows.items() for m, c in r["long_methods"]]
    blocks_over = sum(r["blocks_over"] for r in rows.values())
    longest = max(rows.items(), key=lambda kv: kv[1]["longest_block"])
    wf_code, wf_comment = workflow_lines(root)

    print()
    print("| Measure | Value |")
    print("|---|---|")
    print("| Product code lines | %d |" % code)
    print("| Product comment lines | %d (%.0f %% of non-blank) |" % (comment, 100.0 * comment / (code + comment)))
    if base is not None:
        before = base_comment_lines(root, base)
        print("| Comment-line delta against %s | %+d |" % (base, comment - before))
    print("| Comment blocks over %d lines | %d |" % (BLOCK_LIMIT, blocks_over))
    print("| Longest comment block | %d lines (%s) |" % (longest[1]["longest_block"], longest[0]))
    print("| Methods over %d code lines | %d |" % (METHOD_LIMIT, len(long_methods)))
    print("| Files over %d code lines | %d |" % (FILE_LIMIT, len(big_files)))
    print("| Workflow comment lines | %d (of %d non-blank) |" % (wf_comment, wf_code + wf_comment))
    if big_files:
        print()
        print("| File over %d code lines | Code | Comment |" % FILE_LIMIT)
        print("|---|---|---|")
        for name in big_files:
            print("| %s | %d | %d |" % (name, rows[name]["code"], rows[name]["comment"]))
    if long_methods:
        print()
        print("| Method over %d code lines | Code lines |" % METHOD_LIMIT)
        print("|---|---|")
        for name, method, count in sorted(long_methods, key=lambda t: -t[2]):
            print("| %s %s | %d |" % (name, method, count))
    if show_all:
        print()
        print("| File | Code | Comment | Blocks over %d | Longest block |" % BLOCK_LIMIT)
        print("|---|---|---|---|---|")
        for name, r in rows.items():
            print("| %s | %d | %d | %d | %d |" % (name, r["code"], r["comment"], r["blocks_over"], r["longest_block"]))
    print()
    print("lean: %d comment lines, %d blocks over %d, %d methods over %d, %d files over %d - reported, not gated"
          % (comment, blocks_over, BLOCK_LIMIT, len(long_methods), METHOD_LIMIT, len(big_files), FILE_LIMIT))


if __name__ == "__main__":
    main(sys.argv[1:])
