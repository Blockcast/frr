#!/usr/bin/env python3

import pathlib
import re
import sys


HOSTED_LABEL = re.compile(r"\b(?:ubuntu|macos|windows)-(?:latest|\d[\w.-]*)\b", re.IGNORECASE)

# What a GitHub-hosted runner cannot serve: the in-cluster Harbor registry and
# its buildx cache.  Hosted labels are allowed only in a job that touches none
# of these (BLO-55992); frr#16 moved the image builds off hosted runners for
# that cache, not for security.
NEEDS_SELF_HOSTED = re.compile(
    r"registry\.blockcast\.net|harbor|buildx|build-push-action|cache-(?:from|to)\s*:", re.IGNORECASE)
JOB_KEY = re.compile(r"^  [A-Za-z0-9_-]+:\s*$")

# A YAML list item ("- name: ...", "- uses: ...", "- { rel: ... }"). Splitting on
# these gives one chunk per step, which is all the exporter check below needs.
LIST_ITEM = re.compile(r"^\s*-\s", re.MULTILINE)
EXPORTER = re.compile(r"^\s*type=(\w+)")
# A step input such as "outputs: |" or "cache-from: type=...". Block-scalar
# lines ("type=registry,ref=...", "UBUNTU_VERSION=...") never match: the text
# before their first ':' is not a bare key.
INPUT_KEY = re.compile(r"^\s*([A-Za-z0-9_-]+):(.*)$")


def step_exporters(chunk: str) -> list:
    """Lines of one step that declare a buildx `--output` exporter.

    Only the `outputs:` input becomes `--output`, inline or one exporter per
    block-scalar line. `cache-from:`/`cache-to:` use the same `type=...`
    syntax, but `tags:` does not touch cache refs, so counting them made a
    two-line `cache-from: |` read as two unnamed exporters (frr#129).
    """
    exporters, key = [], None
    for line in chunk.splitlines():
        if line.strip().startswith("#"):
            continue
        match = INPUT_KEY.match(line)
        if match:
            key, value = match.group(1), match.group(2)
        else:
            value = line
        if key == "outputs" and EXPORTER.match(value):
            exporters.append(line)
    return exporters


def check_exporter_names(path: pathlib.Path, text: str) -> list:
    """A `tags:` input becomes a global `--tag` that buildx applies to EVERY
    exporter. With one exporter that is harmless; with two, the unqualified
    name meant for the local tar is also handed to the pushing exporter, which
    resolves it against Docker Hub and dies with `insufficient_scope` (frr#78,
    run 34682460908). So a multi-exporter step must name each exporter inline
    and carry no `tags:` of its own.
    """
    violations = []
    for chunk in LIST_ITEM.split(text):
        exporters = step_exporters(chunk)
        if len(exporters) < 2:
            continue
        step = chunk.splitlines()[0].strip()
        for line in exporters:
            if "name=" not in line:
                violations.append(
                    f"{path}: exporter without an inline name= in a multi-exporter step "
                    f"({step}): {line.strip()!r}"
                )
        if re.search(r"^\s*tags:", chunk, re.MULTILINE):
            violations.append(
                f"{path}: step ({step}) combines `tags:` with {len(exporters)} exporters; "
                "`tags:` applies to all of them. Give each exporter its own name= instead."
            )
    return violations


def _active(line: str) -> str:
    return line.split("#", 1)[0]


def check_hosted_labels(path: pathlib.Path, text: str) -> list:
    """A hosted label is refused outside a job, or in a job that uses Harbor
    or a buildx cache/exporter."""
    lines = text.splitlines()
    jobs, in_jobs, start = [], False, None
    for n, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            if start is not None:
                jobs.append((start, n))
                start = None
            in_jobs = line.startswith("jobs:")
        elif in_jobs and JOB_KEY.match(_active(line).rstrip()):
            if start is not None:
                jobs.append((start, n))
            start = n
    if start is not None:
        jobs.append((start, len(lines)))

    violations = []
    for n, line in enumerate(lines):
        match = HOSTED_LABEL.search(_active(line))
        if not match:
            continue
        job = next(((s, e) for s, e in jobs if s <= n < e), None)
        where = f"{path}:{n + 1}: hosted runner label {match.group(0)!r}"
        if job is None:
            violations.append(f"{where} outside a job")
            continue
        uses = NEEDS_SELF_HOSTED.search("\n".join(_active(l) for l in lines[job[0]:job[1]]))
        if uses:
            violations.append(f"{where} in a job that uses {uses.group(0)!r}, which hosted runners cannot reach")
    return violations


def main() -> int:
    violations = []
    workflows = pathlib.Path(".github/workflows")
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        text = path.read_text()
        violations.extend(check_hosted_labels(path, text))
        violations.extend(check_exporter_names(path, text))

    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1

    print("Hosted runner label policy (no Harbor/buildx on hosted): pass")
    print("Multi-exporter name policy: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
