#!/usr/bin/env python3
"""Report and gate on the age of the frr CI buildcache tags in Harbor.

Why this exists
---------------
`github-ci.yml` reads the buildcache on every run but only one workflow writes
it.  A cache that stopped being written looks *identical* to a warm one from
inside CI: every job stays green, builds just silently get slower.  The u22 tag
went unwritten for ~10 days before anyone noticed, and only then as a side
effect of investigating something else.  This script turns "nobody rewrote the
cache" into an explicit, thresholded failure.

It talks to the Harbor v2 API rather than the Docker registry v2 API on
purpose: buildkit registry cache is written with a
`application/vnd.buildkit.cacheconfig.v0` config blob, which carries no
`created` field, so there is no push timestamp to read out of the OCI manifest.
Harbor's artifact record has `push_time`, which is the value we actually want.

Exit codes
----------
0  every requested tag is present and within the freshness budget
1  at least one tag is missing, too old, or (with --baseline) did not advance
2  the probe itself could not run (auth, network, malformed response)

1 and 2 are kept distinct so a Harbor outage does not get read as a stale
cache.  Both are non-green; only the diagnosis differs.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

EXIT_OK = 0
EXIT_STALE = 1
EXIT_PROBE_ERROR = 2

DEFAULT_REGISTRY = "registry.blockcast.net"
DEFAULT_PROJECT = "cache"
DEFAULT_REPOSITORY = "frr-ci"


class ProbeError(Exception):
    """The probe could not determine an answer (as opposed to a bad answer)."""


def parse_push_time(raw: str) -> dt.datetime:
    """Parse a Harbor RFC3339 push_time into an aware UTC datetime.

    Harbor emits nanosecond precision (`...:05.123456789Z`), which
    `datetime.fromisoformat` rejects on Python < 3.11 and accepts only up to
    microseconds later.  Truncate the fractional part to 6 digits.

    Raises ProbeError -- never ValueError/AttributeError -- on anything it
    cannot parse.  This is load-bearing for the exit-code contract above: a
    leaked exception terminates the process with status 1, which is
    indistinguishable from EXIT_STALE, so corrupt Harbor data would be reported
    as a stale cache and send someone to reseed a cache that is fine.
    """
    if not isinstance(raw, str):
        raise ProbeError(
            f"push_time is {type(raw).__name__}, expected string: {raw!r}"
        )
    try:
        text = raw.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        if "." in text:
            head, _, tail = text.partition(".")
            digits = ""
            for ch in tail:
                if ch.isdigit():
                    digits += ch
                else:
                    tail = tail[len(digits):]
                    break
            else:
                tail = ""
            text = f"{head}.{digits[:6]:0<6}{tail}"
        parsed = dt.datetime.fromisoformat(text)
    except (ValueError, TypeError) as exc:
        raise ProbeError(f"unparseable push_time {raw!r}: {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def evaluate(
    observed: dict[str, dt.datetime | None],
    now: dt.datetime,
    max_age_hours: float,
    baseline: dict[str, dt.datetime] | None = None,
) -> list[dict]:
    """Turn observed push times into per-tag verdicts.

    Pure function -- no I/O -- so the decision logic is unit-testable without a
    Harbor instance.  `observed[tag] is None` means the tag was not found.
    """
    results = []
    for tag, push_time in observed.items():
        row: dict = {"tag": tag, "push_time": push_time, "age_hours": None}
        if push_time is None:
            row["status"] = "missing"
            row["detail"] = "tag not present in registry"
            results.append(row)
            continue

        age_hours = (now - push_time).total_seconds() / 3600.0
        row["age_hours"] = age_hours

        prior = (baseline or {}).get(tag)
        if baseline is not None:
            if prior is None:
                # No "before" reading for this tag: it did not exist previously,
                # so any push time at all is an advance.
                row["status"] = "ok"
                row["detail"] = f"seeded (no prior tag); age {age_hours:.1f}h"
            elif push_time <= prior:
                row["status"] = "not_advanced"
                row["detail"] = (
                    f"push_time did not advance: was {prior.isoformat()}, "
                    f"still {push_time.isoformat()}"
                )
            else:
                row["status"] = "ok"
                row["detail"] = (
                    f"advanced {prior.isoformat()} -> {push_time.isoformat()}"
                )
            results.append(row)
            continue

        if age_hours > max_age_hours:
            row["status"] = "stale"
            row["detail"] = (
                f"age {age_hours:.1f}h exceeds budget {max_age_hours:.0f}h"
            )
        else:
            row["status"] = "ok"
            row["detail"] = f"age {age_hours:.1f}h within budget {max_age_hours:.0f}h"
        results.append(row)
    return results


def render_summary(results: list[dict], max_age_hours: float) -> str:
    lines = [
        f"### frr buildcache freshness (budget: {max_age_hours:.0f}h)",
        "",
        "| tag | push_time (UTC) | age | verdict |",
        "| --- | --- | --- | --- |",
    ]
    for row in results:
        push = row["push_time"].isoformat() if row["push_time"] else "—"
        age = f"{row['age_hours']:.1f}h" if row["age_hours"] is not None else "—"
        mark = "✅" if row["status"] == "ok" else "❌"
        lines.append(f"| `{row['tag']}` | {push} | {age} | {mark} {row['detail']} |")
    return "\n".join(lines) + "\n"


def _request_json(url: str, headers: dict[str, str], timeout: int) -> object:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ProbeError(f"HTTP {exc.code} from {url}") from exc
    except urllib.error.URLError as exc:
        raise ProbeError(f"cannot reach {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ProbeError(f"malformed JSON from {url}: {exc}") from exc


def fetch_push_times(
    registry: str,
    project: str,
    repository: str,
    tags: list[str],
    username: str,
    password: str,
    timeout: int = 30,
) -> dict[str, dt.datetime | None]:
    """Look up each tag's push_time via the Harbor v2 artifacts API."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
    # Harbor requires the repository name path-escaped (it may contain slashes).
    repo_path = urllib.parse.quote(repository, safe="")
    observed: dict[str, dt.datetime | None] = {}

    for tag in tags:
        query = urllib.parse.urlencode(
            {"q": f"tags={tag}", "page_size": "1", "with_tag": "true"}
        )
        url = (
            f"https://{registry}/api/v2.0/projects/{project}"
            f"/repositories/{repo_path}/artifacts?{query}"
        )
        payload = _request_json(url, headers, timeout)
        if not isinstance(payload, list):
            raise ProbeError(f"unexpected artifacts payload for {tag}: {payload!r}")
        if not payload:
            observed[tag] = None
            continue
        artifact = payload[0]
        if not isinstance(artifact, dict):
            raise ProbeError(
                f"artifact record for {tag} is {type(artifact).__name__}, "
                f"expected object: {artifact!r}"
            )
        push_time = artifact.get("push_time")
        if not push_time:
            raise ProbeError(f"artifact for {tag} has no push_time field")
        observed[tag] = parse_push_time(push_time)
    return observed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--registry", default=DEFAULT_REGISTRY)
    ap.add_argument("--project", default=DEFAULT_PROJECT)
    ap.add_argument("--repository", default=DEFAULT_REPOSITORY)
    ap.add_argument("--tag", dest="tags", action="append", required=True)
    ap.add_argument("--max-age-hours", type=float, default=72.0)
    ap.add_argument(
        "--report-only",
        action="store_true",
        help="print the table and always exit 0 (for 'before' snapshots)",
    )
    ap.add_argument(
        "--baseline",
        help="JSON file from a previous --json-out run; require each tag to "
             "have advanced past it instead of checking absolute age",
    )
    ap.add_argument("--json-out", help="write observed push times here")
    args = ap.parse_args(argv)

    username = os.environ.get("HARBOR_USERNAME", "")
    password = os.environ.get("HARBOR_PASSWORD", "")
    if not username or not password:
        print(
            "ERROR: HARBOR_USERNAME/HARBOR_PASSWORD must be set to probe Harbor.",
            file=sys.stderr,
        )
        return EXIT_PROBE_ERROR

    try:
        observed = fetch_push_times(
            args.registry, args.project, args.repository, args.tags,
            username, password,
        )
    except ProbeError as exc:
        print(f"ERROR: buildcache probe failed: {exc}", file=sys.stderr)
        return EXIT_PROBE_ERROR

    baseline = None
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                raise ProbeError(
                    f"baseline is {type(raw).__name__}, expected object"
                )
            baseline = {
                tag: parse_push_time(value)
                for tag, value in raw.items()
                if value is not None
            }
        # ProbeError is included deliberately: parse_push_time raises it for a
        # corrupt baseline value, and letting that escape would exit 1 --
        # reporting "cache did not advance" for a seed that in fact succeeded.
        except (OSError, ValueError, ProbeError) as exc:
            print(f"ERROR: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
            return EXIT_PROBE_ERROR

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(
                {t: (v.isoformat() if v else None) for t, v in observed.items()},
                fh,
                indent=2,
            )

    now = dt.datetime.now(dt.timezone.utc)
    results = evaluate(observed, now, args.max_age_hours, baseline)
    summary = render_summary(results, args.max_age_hours)
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary)

    bad = [r for r in results if r["status"] != "ok"]
    if args.report_only:
        for row in bad:
            # A pre-seed reading that is already stale means the guard was
            # needed -- surface it without failing the seeding run that is
            # about to repair it.
            print(f"::warning::buildcache {row['tag']}: {row['detail']}")
        return EXIT_OK

    for row in bad:
        print(f"::error::buildcache {row['tag']}: {row['detail']}")
    return EXIT_STALE if bad else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
