#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check that GitHub Actions references are pinned to full commit SHAs.

Every `uses:` entry in a workflow or composite action must reference a remote
action as ``owner/repo@<40-char-sha>`` and carry the human-readable version
in a trailing comment, e.g.::

    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

Local actions (``./path``) are exempt because they are versioned with the
repository itself.
"""

import os
import re
import sys

WORKFLOW_DIR = os.path.join(".github", "workflows")
ACTION_DIR = os.path.join(".github", "actions")

# A full-length SHA is required: 40 lowercase hexadecimal characters.
SHA_REF = re.compile(r"^[^/\s]+/[^@\s]+@([0-9a-f]{40})$")
VERSION_COMMENT = re.compile(r"#\s*v\d[\w.\-+]*\s*$")


def iter_files():
    """Yield the workflow and composite action files to scan."""
    if os.path.isdir(WORKFLOW_DIR):
        for name in sorted(os.listdir(WORKFLOW_DIR)):
            path = os.path.join(WORKFLOW_DIR, name)
            if name.endswith((".yml", ".yaml")) and os.path.isfile(path):
                yield path

    if os.path.isdir(ACTION_DIR):
        for root, dirs, files in os.walk(ACTION_DIR):
            dirs.sort()
            for name in sorted(files):
                if name in ("action.yml", "action.yaml"):
                    yield os.path.join(root, name)


def uses_value(line):
    """Return the value after `uses:` on a line, or None if absent."""
    match = re.match(r"^\s*(?:-\s*)?uses:\s*(\S.*?)\s*$", line)
    if not match:
        return None
    return match.group(1)


def check_file(path, problems):
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            value = uses_value(line)
            if value is None:
                continue

            # Strip an inline comment so the ref itself can be validated.
            ref = value.split("#", 1)[0].strip()
            if not ref:
                continue

            if ref.startswith("./"):
                continue

            match = SHA_REF.match(ref)
            if not match:
                problems.append(
                    "%s:%d: %s is not pinned to a full 40-character commit SHA"
                    % (path, lineno, ref)
                )
                continue

            if not VERSION_COMMENT.search(line):
                problems.append(
                    "%s:%d: %s is missing a trailing `# vX.Y.Z` version comment"
                    % (path, lineno, ref)
                )


def main(argv):
    mode = argv[1] if len(argv) > 1 else "check"
    if mode != "check":
        sys.stderr.write("usage: %s [check]\n" % argv[0])
        return 2

    files = list(iter_files())
    problems = []
    for path in files:
        check_file(path, problems)

    if problems:
        for problem in problems:
            print(problem)
        return 1

    print(
        "ok: all GitHub Actions in %d file(s) are SHA-pinned" % len(files)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
