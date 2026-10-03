# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestDimtUmhLc(frrtest.TestMultiOut):
    program = "./test_dimt_umh_lc"


TestDimtUmhLc.exit_cleanly()
