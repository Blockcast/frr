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

It prefers the Harbor v2 API over the Docker registry v2 API: buildkit registry
cache is written with a `application/vnd.buildkit.cacheconfig.v0` config blob,
which carries no `created` field, so there is no push timestamp to read out of
the OCI manifest.  Harbor's artifact record has `push_time`, which is the value
we actually want.

Two surfaces, because Harbor authorizes them separately
-------------------------------------------------------
Harbor gates `/api/v2.0/...` on a *project role* and `/v2/...` on a registry
token scope.  A robot holding only registry push/pull -- which is what the CI
credential is -- can write the cache all day and still get 403 from the
artifacts API (BLO-33101, live since 2026-09-10; the grant needs Harbor admin,
which neither CI nor the agent fleet holds).

So the probe degrades instead of vanishing.  When the Harbor API refuses, it
falls back to `HEAD /v2/<repo>/manifests/<tag>` and reads
`Docker-Content-Digest`, which the pull scope provably reaches.  A digest
carries no timestamp, so absolute age becomes unmeasurable rather than wrong.
It also measures a different thing than `push_time`: whether the cache
*content* changed, not whether anyone rewrote it.  A no-op re-seed on an
unchanged master re-pushes identical content under the same digest, and that is
the successful outcome here, so an unchanged digest is reported as a warning
("unchanged"), never as a failure.  The evidence that the push happened is the
seed job's own result (a failed `cache-to` export fails the build), which the
workflow consumes separately.  A tag that is absent is still a failure.  The two
modes are kept visibly distinct; the fallback never reports an age it did not
measure.

Exit codes
----------
0  every requested tag is present and within the freshness budget (or, with
   --baseline, advanced; in digest mode an unchanged digest is a warning)
1  at least one tag is missing, too old, or (with --baseline, push_time mode)
   did not advance
2  the probe itself could not run (auth, network, malformed response)
3  absolute age was asked for, but only registry digests were readable, and a
   digest carries no time (BLO-33101)

1, 2 and 3 are kept distinct so a Harbor outage does not get read as a stale
cache, and so a caller that can tolerate "age unmeasurable" does not also
swallow a Harbor defect.  All are non-green; only the diagnosis differs.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

EXIT_OK = 0
EXIT_STALE = 1
EXIT_PROBE_ERROR = 2
EXIT_AGE_UNMEASURABLE = 3

# Row statuses that are reported but do not fail the run.  See `evaluate_digests`.
WARN_STATUSES = ("unchanged",)

DEFAULT_REGISTRY = "registry.blockcast.net"
DEFAULT_PROJECT = "cache"
DEFAULT_REPOSITORY = "frr-ci"

# Anything the buildkit cache exporter may write. `image-manifest=true` plus
# `oci-mediatypes=true` (what buildcache-seed.yml sets) yields the OCI manifest;
# the others are listed so a change to those flags does not 404 the fallback.
MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)

# Discriminates a digest baseline from a push_time baseline without changing
# the on-disk `{tag: value}` shape the workflow passes through GITHUB_OUTPUT.
DIGEST_PREFIX = "sha256:"


class ProbeError(Exception):
    """The probe could not determine an answer (as opposed to a bad answer).

    `status` carries the HTTP status when the cause was a response, so callers
    can tell "this credential is not allowed" (401/403 -- the registry fallback
    may still work) from "Harbor answered nonsense" (a Harbor defect, which
    falling back would only hide).
    """

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# Statuses where the Harbor management API refusing says nothing about whether
# the separately-authorized registry surface will. See BLO-33101.
AUTHZ_STATUSES = (401, 403)


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


def render_summary(
    results: list[dict], max_age_hours: float, mode: str = "push_time"
) -> str:
    if mode == "digest":
        header = (
            "### frr buildcache advancement (digest fallback — age NOT measured)"
        )
        col, blurb = "digest", (
            "Harbor's artifacts API refused this credential, so absolute age is "
            "unmeasured; only advancement is asserted. See BLO-33101."
        )
    else:
        header = f"### frr buildcache freshness (budget: {max_age_hours:.0f}h)"
        col, blurb = "push_time (UTC)", None
    lines = [header, ""]
    if blurb:
        lines += [blurb, ""]
    lines += [
        f"| tag | {col} | age | verdict |",
        "| --- | --- | --- | --- |",
    ]
    for row in results:
        if mode == "digest":
            shown = row.get("digest") or "—"
        else:
            shown = row["push_time"].isoformat() if row["push_time"] else "—"
        age = f"{row['age_hours']:.1f}h" if row["age_hours"] is not None else "—"
        if row["status"] == "ok":
            mark = "✅"
        elif row["status"] in WARN_STATUSES:
            mark = "⚠️"
        else:
            mark = "❌"
        lines.append(f"| `{row['tag']}` | {shown} | {age} | {mark} {row['detail']} |")
    return "\n".join(lines) + "\n"


def _request_json(url: str, headers: dict[str, str], timeout: int) -> object:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ProbeError(f"HTTP {exc.code} from {url}", status=exc.code) from exc
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


def _parse_auth_challenge(header: str) -> dict[str, str]:
    """Pull realm/service/scope out of a registry `Www-Authenticate` header.

    Parsed rather than hard-coded so the fallback keeps working if the registry
    host, its token service name, or the scope Harbor demands ever changes --
    the same reason `docker login` does this dance instead of guessing.
    """
    if not header or not header.strip().lower().startswith("bearer "):
        raise ProbeError(f"unsupported registry auth challenge: {header!r}")
    return dict(re.findall(r'(\w+)="([^"]*)"', header))


def _registry_bearer_token(
    challenge: dict[str, str], username: str, password: str, timeout: int
) -> str:
    realm = challenge.get("realm")
    if not realm:
        raise ProbeError(f"registry auth challenge has no realm: {challenge!r}")
    params = {k: challenge[k] for k in ("service", "scope") if challenge.get(k)}
    url = f"{realm}?{urllib.parse.urlencode(params)}" if params else realm
    basic = base64.b64encode(f"{username}:{password}".encode()).decode()
    payload = _request_json(url, {"Authorization": f"Basic {basic}"}, timeout)
    if not isinstance(payload, dict):
        raise ProbeError(f"unexpected token payload from {realm}: {payload!r}")
    # Harbor returns `token`; the OAuth2-shaped alias is accepted by spec.
    token = payload.get("token") or payload.get("access_token")
    if not token or not isinstance(token, str):
        raise ProbeError(f"token service {realm} returned no usable token")
    return token


def _head_manifest(url: str, headers: dict[str, str], timeout: int):
    """One HEAD. Returns the response, or None when the tag is absent (404).

    A 401 is re-raised as-is so the caller can read the challenge off it and
    retry; every other transport failure becomes a ProbeError here so there is
    exactly one place that decides "absent" versus "could not tell".
    """
    req = urllib.request.Request(url, headers=headers, method="HEAD")
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code == 401:
            raise
        raise ProbeError(f"HTTP {exc.code} from {url}", status=exc.code) from exc
    except urllib.error.URLError as exc:
        raise ProbeError(f"cannot reach {url}: {exc.reason}") from exc


def fetch_digests(
    registry: str,
    project: str,
    repository: str,
    tags: list[str],
    username: str,
    password: str,
    timeout: int = 30,
) -> dict[str, str | None]:
    """Look up each tag's manifest digest via the Docker registry v2 API.

    Used when the Harbor management API refuses the read.  Returns None for a
    tag that is absent, which `evaluate_digests` reports as missing -- distinct
    from the probe being unable to run at all.
    """
    name = f"{project}/{repository}"
    base = {"Accept": MANIFEST_ACCEPT}
    observed: dict[str, str | None] = {}

    for tag in tags:
        url = f"https://{registry}/v2/{name}/manifests/{tag}"
        try:
            resp = _head_manifest(url, base, timeout)
        except urllib.error.HTTPError as unauthorized:
            challenge = _parse_auth_challenge(
                unauthorized.headers.get("Www-Authenticate", "")
            )
            token = _registry_bearer_token(challenge, username, password, timeout)
            authed = dict(base, Authorization=f"Bearer {token}")
            try:
                resp = _head_manifest(url, authed, timeout)
            except urllib.error.HTTPError as exc:
                # A second 401 means the token itself was rejected: a real
                # authorization failure, not a challenge to answer again.
                raise ProbeError(
                    f"HTTP {exc.code} from {url} even with a registry token",
                    status=exc.code,
                ) from exc

        if resp is None:
            observed[tag] = None
            continue
        with resp:
            digest = resp.headers.get("Docker-Content-Digest")
        if not digest:
            # Without a digest there is nothing to compare, and recording None
            # would read downstream as "tag absent" -- exit 1 (reseed this!)
            # instead of exit 2 (the probe could not tell).
            raise ProbeError(f"no Docker-Content-Digest header for {tag}")
        observed[tag] = digest
    return observed


def evaluate_digests(
    observed: dict[str, str | None],
    baseline: dict[str, str] | None,
) -> list[dict]:
    """Advancement-only verdicts, for when no push time is obtainable.

    Deliberately a separate function from `evaluate`: a digest supports exactly
    one question (did this change?) and unifying the two would invite an age
    comparison against a value that carries no time.

    An unchanged digest is "unchanged", not "not_advanced": an identical
    re-push and no push at all read the same here, and the former is what a
    successful no-op re-seed produces.  The digest cannot tell them apart, so it
    does not fail on them; the seed job result is the push evidence.
    """
    results = []
    for tag, digest in observed.items():
        row: dict = {"tag": tag, "push_time": None, "age_hours": None,
                     "digest": digest}
        if digest is None:
            row["status"] = "missing"
            row["detail"] = "tag not present in registry"
            results.append(row)
            continue
        prior = (baseline or {}).get(tag)
        if prior is None:
            row["status"] = "ok"
            row["detail"] = f"seeded (no prior tag); digest {digest[:19]}…"
        elif digest == prior:
            row["status"] = "unchanged"
            row["detail"] = (
                f"digest unchanged: still {digest[:19]}… (an identical re-push "
                "reads the same; the seed job result is the push evidence)"
            )
        else:
            row["status"] = "ok"
            row["detail"] = f"advanced {prior[:19]}… -> {digest[:19]}…"
        results.append(row)
    return results


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
        mode = "push_time"
    except ProbeError as exc:
        # Narrow on purpose. The Harbor management API and the registry are
        # authorized separately, so a 401/403 there says nothing about the
        # registry -- but a malformed payload or an unreachable host is a real
        # Harbor fault, and quietly switching surfaces would hide it behind a
        # degraded-but-green run.
        if exc.status not in AUTHZ_STATUSES:
            print(f"ERROR: buildcache probe failed: {exc}", file=sys.stderr)
            return EXIT_PROBE_ERROR
        try:
            observed = fetch_digests(
                args.registry, args.project, args.repository, args.tags,
                username, password,
            )
        except ProbeError as fallback_exc:
            print(f"ERROR: buildcache probe failed: {exc}", file=sys.stderr)
            print(
                f"ERROR: registry digest fallback also failed: {fallback_exc}",
                file=sys.stderr,
            )
            return EXIT_PROBE_ERROR
        mode = "digest"
        print(
            f"::warning::Harbor artifacts API unavailable ({exc}); "
            "falling back to registry manifest digests. Cache advancement is "
            "still measurable; absolute age is not."
        )

    baseline = None
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                raise ProbeError(
                    f"baseline is {type(raw).__name__}, expected object"
                )
            present = [v for v in raw.values() if v is not None]
            baseline_mode = (
                "digest"
                if any(str(v).startswith(DIGEST_PREFIX) for v in present)
                else "push_time"
            )
            if present and baseline_mode != mode:
                # Comparing a digest against a timestamp cannot answer
                # "advanced?", and guessing either way would certify an
                # unmeasured cache.
                raise ProbeError(
                    f"baseline holds {baseline_mode} values but this run could "
                    f"only read {mode}; advancement is not comparable across "
                    "the two surfaces"
                )
            if mode == "digest":
                baseline = {
                    tag: str(value)
                    for tag, value in raw.items()
                    if value is not None
                }
            else:
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
                {
                    t: (v.isoformat() if isinstance(v, dt.datetime) else v)
                    for t, v in observed.items()
                },
                fh,
                indent=2,
            )

    now = dt.datetime.now(dt.timezone.utc)
    if mode == "digest":
        if baseline is None and not args.report_only:
            # The only question left without a baseline is absolute age, and a
            # digest carries no time. Refuse rather than report a cache fresh
            # on the strength of a measurement that was never taken.
            print(
                "ERROR: absolute cache age needs Harbor's push_time, which this "
                "credential cannot read; only registry digests were available. "
                "Advancement (--baseline) is still answerable.",
                file=sys.stderr,
            )
            return EXIT_AGE_UNMEASURABLE
        results = evaluate_digests(observed, baseline)
    else:
        results = evaluate(observed, now, args.max_age_hours, baseline)
    summary = render_summary(results, args.max_age_hours, mode=mode)
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary)

    warned = [r for r in results if r["status"] in WARN_STATUSES]
    bad = [r for r in results if r["status"] not in ("ok", *WARN_STATUSES)]
    if args.report_only:
        for row in warned + bad:
            # A pre-seed reading that is already stale means the guard was
            # needed -- surface it without failing the seeding run that is
            # about to repair it.
            print(f"::warning::buildcache {row['tag']}: {row['detail']}")
        return EXIT_OK

    for row in warned:
        print(f"::warning::buildcache {row['tag']}: {row['detail']}")
    for row in bad:
        print(f"::error::buildcache {row['tag']}: {row['detail']}")
    return EXIT_STALE if bad else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
