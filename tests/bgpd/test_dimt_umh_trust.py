# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestDimtUmhTrust(frrtest.TestMultiOut):
    program = "./test_dimt_umh_trust"


TestDimtUmhTrust.exit_cleanly()
