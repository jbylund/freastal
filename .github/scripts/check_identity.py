"""Fail if any commit in a range carries an email outside the approved allowlist.

A commit's author/committer identity must be @gmail.com or a GitHub-generated
noreply address. A Co-authored-by trailer may additionally reference
noreply@anthropic.com, since that is how Claude attributes its own commits.

This exists because a personal-repo commit once carried a work email: a
squash-merge on GitHub copies each original commit's author into a
Co-authored-by trailer on the squashed commit, so checking author/committer
fields alone is not enough - the trailer must be checked too.
"""

import re
import subprocess
import sys

IDENTITY_ALLOW = (
    re.compile(r"^[^@]+@gmail\.com$", re.IGNORECASE),
    re.compile(r"^[^@]+@users\.noreply\.github\.com$", re.IGNORECASE),
    # GitHub's own committer identity for web-based merges/squashes.
    re.compile(r"^noreply@github\.com$", re.IGNORECASE),
)
TRAILER_ALLOW = IDENTITY_ALLOW + (
    re.compile(r"^noreply@anthropic\.com$", re.IGNORECASE),
)
TRAILER_RE = re.compile(r"^co-authored-by:.*<([^>]+)>", re.IGNORECASE | re.MULTILINE)

RECORD_SEP = "\x02"
FIELD_SEP = "\x01"


def allowed(email, patterns):
    return any(p.match(email) for p in patterns)


def main():
    if len(sys.argv) != 3:
        print("usage: check_identity.py <base-sha> <head-sha>", file=sys.stderr)
        return 2

    base, head = sys.argv[1], sys.argv[2]
    out = subprocess.run(
        [
            "git",
            "log",
            f"--format=%H{FIELD_SEP}%ae{FIELD_SEP}%ce{FIELD_SEP}%B{RECORD_SEP}",
            f"{base}..{head}",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    records = [r for r in out.split(RECORD_SEP) if r.strip("\n")]
    failures = []
    for record in records:
        sha, author_email, committer_email, body = record.strip("\n").split(
            FIELD_SEP, 3
        )

        for label, email in (("author", author_email), ("committer", committer_email)):
            if not allowed(email, IDENTITY_ALLOW):
                failures.append(
                    f"{sha[:12]}: {label} email {email!r} is not @gmail.com or a GitHub noreply address"
                )

        for email in TRAILER_RE.findall(body):
            if not allowed(email, TRAILER_ALLOW):
                failures.append(
                    f"{sha[:12]}: Co-authored-by trailer references disallowed email {email!r}"
                )

    if failures:
        print("Found commit(s) with a disallowed email:\n", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        print(
            "\nOnly @gmail.com and GitHub noreply addresses may appear as a commit's "
            "author/committer identity (Co-authored-by trailers may additionally "
            "reference noreply@anthropic.com). Fix the offending commit(s) and force-push.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: checked {len(records)} commit(s), no disallowed emails found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
