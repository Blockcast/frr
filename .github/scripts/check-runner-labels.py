#!/usr/bin/env python3

import pathlib
import re
import sys


HOSTED_LABEL = re.compile(r"\b(?:ubuntu|macos|windows)-(?:latest|\d[\w.-]*)\b", re.IGNORECASE)

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


def main() -> int:
    violations = []
    workflows = pathlib.Path(".github/workflows")
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        text = path.read_text()
        for line_number, line in enumerate(text.splitlines(), start=1):
            active = line.split("#", 1)[0]
            match = HOSTED_LABEL.search(active)
            if match:
                violations.append(f"{path}:{line_number}: forbidden hosted runner label {match.group(0)!r}")
        violations.extend(check_exporter_names(path, text))

    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1

    print("Hosted runner label policy: pass")
    print("Multi-exporter name policy: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
