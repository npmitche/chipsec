# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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

# To execute: python[3] -m unittest tests.scripts.test_module_id_checker

import unittest
import os
import sys

PATH_TO_SCRIPT_FOLDER = os.path.join("..", "..", "scripts")
PATH_TO_MODULES_FOLDER = os.path.join("..", "..", "chipsec", "modules")

sys.path.append(PATH_TO_SCRIPT_FOLDER)
from module_id_checker import Module_ID_Checker


class Test_Module_ID_Checker(unittest.TestCase):
    def test_hashClassName(self):
        self.assertEqual(Module_ID_Checker().hash_class_name("pmc"),
                         '0x5d9ea90', "Hash_class_name did not return the correct value.")

    def test_find_files_with_pattern(self):
        pattern = r"class Module_ID_Checker:"
        expected = {os.path.join(PATH_TO_SCRIPT_FOLDER, "module_id_checker.py"): ['class Module_ID_Checker:']}
        result = Module_ID_Checker().find_files_with_pattern(PATH_TO_SCRIPT_FOLDER, pattern)
        self.assertEqual(result, expected)

    def test_find_files_with_pattern_multi(self):
        expected = {os.path.join(PATH_TO_SCRIPT_FOLDER, "build_exe_win7-amd64.py"): ['import os'], 
                           os.path.join(PATH_TO_SCRIPT_FOLDER, "build_exe_win7-x86.py"): ['import os'], 
                           os.path.join(PATH_TO_SCRIPT_FOLDER, "module_id_checker.py"): ['import os'], 
                           os.path.join(PATH_TO_SCRIPT_FOLDER, "strip_record_json_of_pcienumeration.py"): ['import os']}
        result = Module_ID_Checker().find_files_with_pattern(PATH_TO_SCRIPT_FOLDER, r"import os")
        self.assertEqual(result, expected)

    def test_find_files_with_pattern_multi_and_find_again(self):
        expected = {os.path.join(PATH_TO_SCRIPT_FOLDER, "module_id_checker.py"): ['def find_files_with_pattern_from_list']}
        result = Module_ID_Checker().find_files_with_pattern(PATH_TO_SCRIPT_FOLDER, r"import os")
        result = Module_ID_Checker().find_files_with_pattern_from_list(result, r"def find_files_with_pattern_from_list")
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()