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


"""
This script verifies if the modules in a given folder have have the correct module ID when it's initialized. 

Usage:
    ``python3 module_id_checker.py [module/folder]``

Examples:
    >>> python3 module_id_checker.py ../chipsec/modules

"""

import os
import re
import sys
from hashlib import sha256


class Module_ID_Checker:
    def main(self, argv):
        folder_path = os.path.join("..", "chipsec", "modules")
        issue_found = False
        if argv and os.path.exists(argv[0]) and os.path.isdir(argv[0]):
            folder_path = argv[0]
        file_paths = self.find_files_with_BaseModule(folder_path)
        files = self.find_files_with_ModuleResult(file_paths)
        for file in file_paths:
            result = self.hash_class_name(file_paths[file][0])
            if file in files:
                expected = files[file][0]
                if expected != result:
                    print(f'{file} does NOT have the correct hash value')
                    print(f"    Found: {result} expected: {expected}")
                    issue_found = True
            else:
                print(f'{file} does not have "ModuleResult" call in init.')
                print(f"    ID perhaps should be: {result}")
                issue_found = True
        if not issue_found:
            print(f"No issues found for the folder {folder_path}!")

    def hash_class_name(self, className: str) -> str:
        return f'0x{sha256(className.encode("utf-8")).hexdigest()[:7]}'

    def find_files_with_pattern(self, folder_path, pattern):
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            raise RuntimeError(f"Folder path {folder_path} does not exist or is not a folder.")
        file_paths = {}
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = self.open_file_and_search(os.path.join(root, file), pattern)
                    if file_path:
                        file_paths[file_path[0]] = file_path[1]
        return file_paths

    def find_files_with_BaseModule(self, folder_path):
        pattern = r'class (.*)\(BaseModule\)'
        matching_files = self.find_files_with_pattern(folder_path, pattern)
        return matching_files
    
    def find_files_with_ModuleResult(self, file_list):
        pattern = r'self.rc_res = ModuleResult\((0x[A-Fa-f0-9]*)'
        matching_files = self.find_files_with_pattern_from_list(file_list, pattern)
        return matching_files

    def open_file_and_search(self, file_path, pattern):
        with open(file_path, 'r') as f:
            content = f.read()
            find_result = re.findall(pattern, content)
            if find_result:
                return (file_path, find_result)
            
    def find_files_with_pattern_from_list(self, file_list, pattern):
        file_paths = {}
        for file in file_list:
            file_path = self.open_file_and_search(file, pattern)
            if file_path:
                file_paths[file_path[0]] = file_path[1]
        return file_paths

if __name__ == "__main__":
    Module_ID_Checker().main(sys.argv[1:])
