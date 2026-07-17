#!/usr/bin/env python3

import pathlib
import re
import sys


HOSTED_LABEL = re.compile(r"\b(?:ubuntu|macos|windows)-(?:latest|\d[\w.-]*)\b", re.IGNORECASE)


def main() -> int:
    violations = []
    workflows = pathlib.Path(".github/workflows")
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            active = line.split("#", 1)[0]
            match = HOSTED_LABEL.search(active)
            if match:
                violations.append(f"{path}:{line_number}: forbidden hosted runner label {match.group(0)!r}")

    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1

    print("Hosted runner label policy: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
