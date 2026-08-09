#!/bin/sh

set -eu

workflow=".github/workflows/github-ci.yml"

grep -Fq 'TOPOTEST_WORKERS: "5"' "$workflow"
grep -Fq 'max-parallel: 1' "$workflow"
grep -Fq -- '-e TOPOTEST_WORKERS="${TOPOTEST_WORKERS}"' "$workflow"
grep -Fq 'pytest -n"${TOPOTEST_WORKERS}" --dist=loadfile' "$workflow"

if grep -E 'pytest .*nproc' "$workflow" >/dev/null; then
  echo "topotest concurrency must not be derived from host-visible nproc" >&2
  exit 1
fi

echo "github-ci topotest concurrency cap: PASS"
