#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Add or verify Microsoft copyright headers on repository source files."""

import os
import re
import subprocess
import sys

GO_HEADER = [
    "// Copyright (c) Microsoft Corporation.",
    "// Licensed under the MIT License.",
]
HASH_HEADER = [
    "# Copyright (c) Microsoft Corporation.",
    "# Licensed under the MIT License.",
]
HTML_HEADER = [
    "<!-- Copyright (c) Microsoft Corporation.",
    "Licensed under the MIT License. -->",
]

EXEMPT_NAMES = {
    "LICENSE",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "go.sum",
}
BOILERPLATE = "hack/boilerplate.go.txt"

HASH_EXTS = {".sh", ".py", ".yaml", ".yml", ".dockerfile", ".conf"}
SLASH_EXTS = {".go", ".mod", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
HTML_EXTS = {".html", ".md"}
HASH_NAMES = {".gitignore", ".dockerignore", "Makefile"}

USAGE = "usage: headers.py [check|fix] [path ...]"


def repo_root():
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except (OSError, subprocess.CalledProcessError):
        return os.getcwd()


def repo_files(root):
    out = subprocess.check_output(
        ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    )
    return [
        p
        for p in out.decode().split("\0")
        if p and os.path.isfile(os.path.join(root, p))
    ]


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def write_text(path, lines):
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="\n") as f:
        f.write("\n".join(lines))
        if lines:
            f.write("\n")


def comment_style(path):
    name = os.path.basename(path)
    if name in HASH_NAMES or name.startswith("Dockerfile"):
        return HASH_HEADER
    ext = os.path.splitext(name)[1].lower()
    if ext in SLASH_EXTS:
        return GO_HEADER
    if ext in HASH_EXTS:
        return HASH_HEADER
    if ext in HTML_EXTS:
        return HTML_HEADER
    return None


def header_index(lines, header):
    # Accept the header anywhere in the first 20 lines.
    for i in range(min(len(lines), 20) - len(header) + 1):
        if lines[i : i + len(header)] == header:
            return i
    return -1


COPYRIGHT_RE = re.compile(
    r"(?i)copyright\s*(?:\(c\)|©|\d{4})|all rights reserved|spdx-license-identifier"
)


def is_comment_line(line, header):
    stripped = line.strip()
    if header is GO_HEADER:
        return stripped.startswith(("//", "/*", "*"))
    if header is HASH_HEADER:
        return stripped.startswith("#")
    return stripped.startswith(("<!--", "*"))


def has_copyright(lines, header):
    return any(
        COPYRIGHT_RE.search(line)
        for line in lines[:20]
        if is_comment_line(line, header)
    )


def insertion_index(lines):
    if lines and lines[0].startswith("#!"):
        return 1
    if lines and lines[0].lstrip().lower().startswith("<!doctype"):
        return 1
    return 0


def check_file(path, header):
    lines = read_text(path).splitlines()
    index = header_index(lines, header)
    if index >= 0:
        if index != insertion_index(lines):
            return "placement"
        return None
    if has_copyright(lines, header):
        return "manual"
    return "missing"


def relocate_header(lines, index, header, expected):
    without = lines[:index] + lines[index + len(header) :]
    if index < len(without) and without[index].strip() == "":
        del without[index]

    at = expected
    while at < len(without) and without[at].strip() == "":
        at += 1
    return without[:expected] + list(header) + [""] + without[at:]


def fix_file(path, header):
    lines = read_text(path).splitlines()
    index = header_index(lines, header)
    expected = insertion_index(lines)
    if index >= 0:
        if index == expected:
            return None
        write_text(path, relocate_header(lines, index, header, expected))
        return "relocated"
    if has_copyright(lines, header):
        return "manual"

    at = expected
    # Replace any blank lines at the insertion point with the single blank
    # line that follows the header.
    while at < len(lines) and lines[at].strip() == "":
        at += 1
    write_text(path, lines[:expected] + list(header) + [""] + lines[at:])
    return "updated"


def boilerplate_ok(path):
    try:
        return read_text(path).splitlines() == GO_HEADER
    except OSError:
        return False


def collect_files(paths, root):
    if not paths:
        return [os.path.join(root, p) for p in repo_files(root)]

    files = set()
    for path in paths:
        full = os.path.abspath(path)
        if os.path.isdir(full):
            for dirpath, dirnames, filenames in os.walk(full):
                dirnames.sort()
                for name in sorted(filenames):
                    candidate = os.path.join(dirpath, name)
                    if os.path.isfile(candidate):
                        files.add(candidate)
        elif os.path.isfile(full):
            files.add(full)
        else:
            print("%s: no such file or directory" % path, file=sys.stderr)
    return sorted(files)


def display_path(path, root):
    return os.path.relpath(path, root).replace(os.sep, "/")


def is_exempt(rel):
    return os.path.basename(rel) in EXEMPT_NAMES or rel == BOILERPLATE


def main(argv):
    mode = "check"
    args = list(argv[1:])
    if args and args[0] in ("check", "fix"):
        mode = args.pop(0)
    if args and args[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    if args and args[0].startswith("-"):
        print(USAGE, file=sys.stderr)
        return 2

    root = repo_root()
    files = collect_files(args, root)
    failures = 0

    for path in files:
        rel = display_path(path, root)

        if rel == BOILERPLATE:
            if mode == "check" and not boilerplate_ok(path):
                print("%s: missing or invalid header" % rel)
                failures += 1
            continue

        if is_exempt(rel):
            continue

        header = comment_style(path)
        if header is None:
            continue

        if mode == "check":
            result = check_file(path, header)
            if result == "manual":
                print(
                    "%s: copyright notice present but not the expected Microsoft "
                    "header; manual review required" % rel
                )
                failures += 1
            elif result == "placement":
                print("%s: license header is not in the required position" % rel)
                failures += 1
            elif result == "missing":
                print("%s: missing license header" % rel)
                failures += 1
        else:
            result = fix_file(path, header)
            if result == "updated":
                print("%s: updated" % rel)
            elif result == "relocated":
                print("%s: moved license header to the top" % rel)
            elif result == "manual":
                print(
                    "%s: copyright notice present but not the expected Microsoft "
                    "header; skipped for manual review" % rel
                )
                failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
