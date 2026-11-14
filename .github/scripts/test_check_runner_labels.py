#!/usr/bin/env python3
"""Fixtures for check-runner-labels.py's multi-exporter rule.

Stdlib only. Run: python3 -m unittest discover -s .github/scripts -p 'test_check_runner_labels.py'
"""

import importlib.util
import pathlib
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "check_runner_labels", pathlib.Path(__file__).with_name("check-runner-labels.py"))
labels = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(labels)

PATH = pathlib.Path("wf.yml")


def violations(step: str) -> list:
    return labels.check_exporter_names(PATH, "jobs:\n  b:\n    steps:\n" + step)


class MultiExporterRule(unittest.TestCase):
    def test_two_cache_from_refs_are_not_exporters(self):
        # frr#129: Build-LTTng reads two buildcache refs and exports cacheonly.
        self.assertEqual(violations(
            "      - name: Build docker image (cached)\n"
            "        uses: docker/build-push-action@v6\n"
            "        with:\n"
            "          outputs: type=cacheonly\n"
            "          # Its own cache first, then Build's 24.04 one.\n"
            "          cache-from: |\n"
            "            type=registry,ref=registry.blockcast.net/cache/frr-ci:x-buildcache\n"
            "            type=registry,ref=registry.blockcast.net/cache/frr-ci:amd64_u24-buildcache\n"
        ), [])

    def test_two_unnamed_output_exporters_are_refused(self):
        # frr#78: a global --tag reaches the pushing exporter.
        found = violations(
            "      - name: Build\n"
            "        with:\n"
            "          outputs: |\n"
            "            type=docker,dest=/tmp/img.tar\n"
            "            type=registry,push=true\n"
        )
        self.assertEqual(len(found), 2)
        self.assertTrue(all("without an inline name=" in v for v in found))

    def test_tags_with_two_named_exporters_is_refused(self):
        found = violations(
            "      - name: Build\n"
            "        with:\n"
            "          tags: frr-amd64\n"
            "          outputs: |\n"
            "            type=docker,name=frr-amd64,dest=/tmp/img.tar\n"
            "            type=image,name=registry.blockcast.net/x:y,push=true\n"
        )
        self.assertEqual(len(found), 1)
        self.assertIn("combines `tags:`", found[0])

    def test_two_named_exporters_without_tags_pass(self):
        self.assertEqual(violations(
            "      - name: Build\n"
            "        with:\n"
            "          outputs: |\n"
            "            type=docker,name=frr-amd64,dest=/tmp/img.tar\n"
            "            type=image,name=registry.blockcast.net/x:y,push=true\n"
            "          cache-from: |\n"
            "            type=registry,ref=a\n"
            "            type=registry,ref=b\n"
        ), [])


if __name__ == "__main__":
    unittest.main()
