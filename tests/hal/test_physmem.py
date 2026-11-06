# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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

import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

from chipsec.hal.common.physmem import Memory
from chipsec.hal.common.uefi import UEFI

PAGE = 0x1000
MB = 0x100000

# EFI memory types
RESERVED, BS_DATA, RT_DATA, CONVENTIONAL, ACPI_NVS, MMIO = 0, 4, 6, 7, 10, 11
EFI_MEMORY_RP = 0x2000


def make_memory(mem_map):
    cs = MagicMock()
    cs.helper.get_memory_map.return_value = mem_map
    return Memory(cs)


class TestReadableRanges(unittest.TestCase):

    def test_no_memory_map_means_unknown(self):
        mem = make_memory(None)

        self.assertIsNone(mem.get_readable_ranges())
        self.assertIsNone(mem.readable_chunks(0, 4 * MB, MB))

    def test_unsafe_types_and_read_protected_regions_are_excluded(self):
        mem = make_memory([
            (RT_DATA, 0x100000, 1, 0),
            (CONVENTIONAL, 0x200000, 1, 0),
            (MMIO, 0x300000, 1, 0),
            (BS_DATA, 0x400000, 1, EFI_MEMORY_RP),
            (ACPI_NVS, 0x500000, 1, 0),
        ])

        self.assertEqual(mem.get_readable_ranges(), [(0x100000, 0x101000), (0x500000, 0x501000)])

    def test_adjacent_readable_descriptors_are_merged(self):
        mem = make_memory([
            (RT_DATA, 0x2000, 1, 0),
            (RESERVED, 0x1000, 1, 0),
            (BS_DATA, 0x3000, 2, 0),
        ])

        self.assertEqual(mem.get_readable_ranges(), [(0x1000, 0x5000)])

    def test_chunks_are_clipped_to_bounds_and_returned_highest_first(self):
        mem = make_memory([
            (RT_DATA, 0, (3 * MB) // PAGE, 0),
            (CONVENTIONAL, 3 * MB, MB // PAGE, 0),
            (RT_DATA, 4 * MB, (2 * MB + 0x8000) // PAGE, 0),
        ])

        chunks = mem.readable_chunks(MB, 6 * MB, MB)

        self.assertEqual(chunks, [(5 * MB, MB), (4 * MB, MB), (2 * MB, MB), (MB, MB)])

    def test_partial_chunks_cover_unaligned_range_ends(self):
        mem = make_memory([(RT_DATA, 0x10000, 3, 0)])

        self.assertEqual(mem.readable_chunks(0, MB, 0x2000), [(0x11000, 0x2000), (0x10000, 0x1000)])


class TestEfiHelperMemoryMap(unittest.TestCase):

    @staticmethod
    def _descriptor(mem_type, start, pages, attr, desc_size=48):
        return struct.pack('<IIQQQQ', mem_type, 0, start, 0, pages, attr).ljust(desc_size, b'\xAA')

    def _helper(self, edk2):
        with patch.dict(sys.modules, {'edk2': edk2}):
            sys.modules.pop('chipsec.helper.efi.efihelper', None)
            from chipsec.helper.efi import efihelper
            helper = efihelper.EfiHelper()
        sys.modules.pop('chipsec.helper.efi.efihelper', None)
        return helper

    def test_descriptors_are_parsed_using_the_reported_stride(self):
        edk2 = MagicMock()
        buf = self._descriptor(RT_DATA, 0x1000, 2, 0x8000000000000000) + self._descriptor(MMIO, 0xFE000000, 16, 1)
        edk2.GetMemoryMap.return_value = (0, buf, 48, 1)

        mem_map = self._helper(edk2).get_memory_map()

        self.assertEqual(mem_map, [(RT_DATA, 0x1000, 2, 0x8000000000000000), (MMIO, 0xFE000000, 16, 1)])

    def test_failed_call_means_unknown(self):
        edk2 = MagicMock()
        edk2.GetMemoryMap.return_value = (5, b'', 48, 1)

        self.assertIsNone(self._helper(edk2).get_memory_map())

    def test_older_python_efi_without_binding_means_unknown(self):
        edk2 = MagicMock(spec=['readmem'])

        self.assertIsNone(self._helper(edk2).get_memory_map())


class TestEfiTableScan(unittest.TestCase):

    def _uefi(self, chunks, smram_base=8 * MB, tseg=(0, 0)):
        cs = MagicMock()
        cs.hals.cpu.get_SMRAM.return_value = (smram_base, 0, 0)
        cs.hals.cpu.get_TSEG.return_value = (tseg[0], tseg[1], 0)
        cs.hals.memory.readable_chunks.return_value = chunks
        cs.hals.memory.read_physical_mem.side_effect = lambda pa, size: b'\x00' * size
        hal = UEFI.__new__(UEFI)
        hal.cs = cs
        return hal, cs

    def _reads(self, cs):
        return [c.args for c in cs.hals.memory.read_physical_mem.call_args_list]

    def test_scan_reads_only_memory_map_chunks(self):
        hal, cs = self._uefi([(6 * MB, 0x8000), (3 * MB, MB)])

        (found, *_rest) = hal.find_EFI_System_Table()

        self.assertFalse(found)
        cs.hals.memory.readable_chunks.assert_called_once_with(MB, 8 * MB, MB)
        self.assertEqual(self._reads(cs), [(6 * MB, 0x8000), (3 * MB, MB)])

    def test_scan_falls_back_to_full_sweep_without_memory_map(self):
        hal, cs = self._uefi(None, smram_base=5 * MB)

        hal.find_EFI_System_Table()

        self.assertEqual(self._reads(cs), [(4 * MB, MB), (3 * MB, MB), (2 * MB, MB)])

    def test_tseg_chunks_are_still_skipped(self):
        hal, cs = self._uefi([(6 * MB, MB), (5 * MB, MB)], tseg=(6 * MB, 7 * MB))

        hal.find_EFI_System_Table()

        self.assertEqual(self._reads(cs), [(5 * MB, MB)])


if __name__ == '__main__':
    unittest.main()
