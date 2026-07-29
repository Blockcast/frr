# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestMvpnEvents(frrtest.TestMultiOut):
    program = "./test_mvpn_events"


TestMvpnEvents.exit_cleanly()
