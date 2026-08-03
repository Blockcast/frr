# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestMvpnCodec(frrtest.TestMultiOut):
    program = "./test_mvpn_codec"


TestMvpnCodec.exit_cleanly()
