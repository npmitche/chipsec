
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

import unittest
# from unittest.mock import patch, Mock, MagicMock, call
from chipsec_main import run
from io import StringIO
from contextlib import redirect_stdout
import os
import re




class TestHalCpu(unittest.TestCase):

    def test_with_module_cpuinfo(self):
        with open("tests\\characterization\\characterize.log") as f:
            EXPECTED_LOG_CPUINFO = f.read()

        os.remove("chipsec\\logs\\characterize.log")
        run("-m common.cpu.cpu_info -l characterize.log")
        with open("chipsec\\logs\\characterize.log") as f:
            filetext = f.read()

        cleaned = re.sub(r"Time elapsed            [.0-9]{5}","", filetext)
        self.assertEqual(cleaned, EXPECTED_LOG_CPUINFO)


if __name__ == '__main__':
    unittest.main()



