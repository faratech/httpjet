#!/usr/bin/env python3
"""The packaged lsphp pool's reload client must reach its root-only control socket."""
from pathlib import Path
import unittest

UNIT = Path(__file__).with_name("httpjet-lsphp.service")
CONTROL = "--control-socket /run/httpjet/lsphp-control.sock"


class LsphpUnit(unittest.TestCase):
    def test_reload_client_runs_as_root_while_the_pool_stays_unprivileged(self):
        lines = UNIT.read_text().splitlines()
        self.assertIn("User=www-data", lines)
        starts = [line for line in lines if line.startswith("ExecStart=")]
        reloads = [line for line in lines if line.startswith("ExecReload=")]
        self.assertEqual((len(starts), len(reloads)), (1, 1))
        self.assertTrue(starts[0].startswith("ExecStart=/usr/bin/httpjet "), starts[0])
        self.assertTrue(reloads[0].startswith("ExecReload=+/usr/bin/httpjet lsphp-reload "), reloads[0])
        self.assertIn(CONTROL, starts[0])
        self.assertIn(CONTROL, reloads[0])


if __name__ == "__main__":
    unittest.main()
