# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Check Memory Remapping Configuration

Reference:
    - `Preventing & Detecting Xen Hypervisor Subversions <http://www.invisiblethingslab.com/resources/bh08/part2-full.pdf>`_ by Joanna Rutkowska & Rafal Wojtczuk

Usage:
  ``chipsec_main -m common.remap``

Example:
    >>> chipsec_main.py -m common.remap

Registers used:
    - PCI0.0.0_REMAPBASE
    - PCI0.0.0_REMAPLIMIT
    - PCI0.0.0_REMAPBASEMC1
    - PCI0.0.0_REMAPLIMITMC1
    - PCI0.0.0_TOUUD
    - PCI0.0.0_TOLUD
    - PCI0.0.0_TSEGMB

.. note::
    - This module will only run on Core platforms.

"""

from chipsec.module_common import BaseModule, HWCONFIG, SMM
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BIT32, ALIGNED_1MB
from chipsec.library.exceptions import RegisterNotFoundError
from typing import Tuple

_MODULE_NAME = 'remap'

TAGS = [SMM, HWCONFIG]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'REMAP']

_REMAP_ADDR_MASK = 0x7FFFF00000
_TOLUD_MASK = 0xFFFFF000


class remap(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.is_core():
            rbase_exist = self.cs.register.is_defined('PCI0.0.0_REMAPBASE')
            rlimit_exist = self.cs.register.is_defined('PCI0.0.0_REMAPLIMIT')
            touud_exist = self.cs.register.is_defined('PCI0.0.0_TOUUD')
            tolud_exist = self.cs.register.is_defined('PCI0.0.0_TOLUD')
            tseg_exist = self.cs.register.is_defined('PCI0.0.0_TSEGMB')
            if rbase_exist and rlimit_exist and touud_exist and tolud_exist and tseg_exist:
                return True
            self.logger.log_important('Required register definitions not defined for platform.  Skipping module.')
        else:
            self.logger.log_important('Not a Core (client) platform.  Skipping module.')

        return False

    def is_ibecc_enabled(self) -> bool:
        if self.cs.register.is_defined('IBECC_ACTIVATE'):
            edsr = self.cs.register.read_field('IBECC_ACTIVATE', 'IBECC_EN')
            if edsr == 1:
                return True
            else:
                self.logger.log_verbose('IBECC is not enabled!')
        else:
            self.logger.log_verbose('IBECC is not defined!')
        return False

    def get_remap_registers(self, base_reg: str, limit_reg: str) -> Tuple[int, int]:
        if self.cs.register.is_defined(base_reg) and self.cs.register.is_defined(limit_reg):
            base = self.cs.register.read(base_reg)
            limit = self.cs.register.read(limit_reg)
            return base, limit
        raise RegisterNotFoundError('Required register definitions not defined for platform.')

    def check_remap_config(self) -> int:
        is_warning = False
        remapMC0Found = True
        remapMC1Found = True

        try:
            remapbase, remaplimit = self.get_remap_registers('PCI0.0.0_REMAPBASE', 'PCI0.0.0_REMAPLIMIT')
        except RegisterNotFoundError:
            remapbase, remaplimit = 0, 0
            remapMC0Found = False
        try:
            remapbasemc1, remaplimitmc1 = self.get_remap_registers('PCI0.0.0_REMAPBASEMC1', 'PCI0.0.0_REMAPLIMITMC1')
        except RegisterNotFoundError:
            remapMC1Found = False

        touud = self.cs.register.read('PCI0.0.0_TOUUD')
        tolud = self.cs.register.read('PCI0.0.0_TOLUD')
        tsegmb = self.cs.register.read('PCI0.0.0_TSEGMB')
        self.logger.log('[*] Registers:')
        self.logger.log(f'[*]   TOUUD     : 0x{touud:016X}')
        if remapMC0Found:
            self.logger.log(f'[*]   REMAPLIMIT: 0x{remaplimit:016X}')
            self.logger.log(f'[*]   REMAPBASE : 0x{remapbase:016X}')
        if remapMC1Found:
            self.logger.log(f'[*]   REMAPLIMITMC1: 0x{remaplimitmc1:016X}')
            self.logger.log(f'[*]   REMAPBASEMC1: 0x{remapbasemc1:016X}')
        self.logger.log(f'[*]   TOLUD     : 0x{tolud:08X}')
        self.logger.log(f'[*]   TSEGMB    : 0x{tsegmb:08X}')
        self.logger.log('')

        if remapMC0Found and self.cs.register.is_all_ffs('PCI0.0.0_REMAPBASE', remapbase) and self.cs.register.is_all_ffs('PCI0.0.0_REMAPLIMIT', remaplimit) and remapMC1Found:
            remapbase_register = 'PCI0.0.0_REMAPBASEMC1'
            remaplimit_register = 'PCI0.0.0_REMAPLIMITMC1'
            remapbase, remaplimit = remapbasemc1, remaplimitmc1
        else:
            remapbase_register = 'PCI0.0.0_REMAPBASE'
            remaplimit_register = 'PCI0.0.0_REMAPLIMIT'

        ia_untrusted = 0
        remapbase_lock = 0
        remaplimit_lock = 0
        if self.cs.register.has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            ia_untrusted = self.cs.register.read_field('MSR_BIOS_DONE', 'IA_UNTRUSTED')
        if self.cs.register.has_field(remapbase_register, 'LOCK'):
            remapbase_lock = remapbase & 0x1
        if self.cs.register.has_field(remaplimit_register, 'LOCK'):
            remaplimit_lock = remaplimit & 0x1
        touud_lock = touud & 0x1
        tolud_lock = tolud & 0x1
        remapbase &= _REMAP_ADDR_MASK
        remaplimit &= _REMAP_ADDR_MASK
        touud &= _REMAP_ADDR_MASK
        tolud &= _TOLUD_MASK
        tsegmb &= _TOLUD_MASK
        self.logger.log('[*] Memory Map:')
        self.logger.log(f'[*]   Top Of Upper Memory: 0x{touud:016X}')
        self.logger.log(f'[*]   Remap Limit Address: 0x{(remaplimit | 0xFFFFF):016X}')
        self.logger.log(f'[*]   Remap Base Address : 0x{remapbase:016X}')
        self.logger.log(f'[*]   4GB                : 0x{BIT32:016X}')
        self.logger.log(f'[*]   Top Of Low Memory  : 0x{tolud:016X}')
        self.logger.log(f'[*]   TSEG (SMRAM) Base  : 0x{tsegmb:016X}')
        self.logger.log('')

        if self.cs.register.is_all_ffs(remapbase_register, remapbase) or self.cs.register.is_all_ffs(remaplimit_register, remaplimit):
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.CONFIGURATION)
            self.logger.log('[!]   Memory Remap status is Unknown')
            return self.result.getReturnCode(res)

        remap_ok = True

        self.logger.log('[*] Checking memory remap configuration..')

        if remapbase == remaplimit:
            self.logger.log('[!]   Memory Remap status is Unknown')
            is_warning = True
        elif remapbase > remaplimit:
            self.logger.log('[*]   Memory Remap is disabled')
        else:
            self.logger.log('[*]   Memory Remap is enabled')
            remaplimit_addr = (remaplimit | 0xFFFFF)
            if self.is_ibecc_enabled():
                ok = (remaplimit_addr > touud) and (remapbase < touud)
            else:
                ok = ((remaplimit_addr + 1) == touud)
            remap_ok = remap_ok and ok
            if ok:
                self.logger.log_good('  Remap window configuration is correct: REMAPBASE <= REMAPLIMIT < TOUUD')
            else:
                self.logger.log_bad('  Remap window configuration is not correct')

        ok = (0 == tolud & ALIGNED_1MB) and \
             (0 == touud & ALIGNED_1MB) and \
             (0 == remapbase & ALIGNED_1MB) and \
             (0 == remaplimit & ALIGNED_1MB)
        remap_ok = remap_ok and ok
        if ok:
            self.logger.log_good('  All addresses are 1MB aligned')
        else:
            self.logger.log_bad('  Not all addresses are 1MB aligned')

        self.logger.log('[*] Checking if memory remap configuration is locked..')
        ok = (0 != touud_lock) or (0 != ia_untrusted)
        remap_ok = remap_ok and ok
        if ok:
            self.logger.log_good('  TOUUD is locked')
        else:
            self.logger.log_bad('  TOUUD is not locked')

        ok = (0 != tolud_lock) or (0 != ia_untrusted)
        remap_ok = remap_ok and ok
        if ok:
            self.logger.log_good('  TOLUD is locked')
        else:
            self.logger.log_bad('  TOLUD is not locked')

        if self.cs.register.has_field(remapbase_register, 'LOCK') and self.cs.register.has_field(remaplimit_register, 'LOCK'):
            ok = ((0 != remapbase_lock) and (0 != remaplimit_lock)) or (0 != ia_untrusted)
            remap_ok = remap_ok and ok
            if ok:
                self.logger.log_good('  REMAPBASE and REMAPLIMIT are locked')
            else:
                self.logger.log_bad('  REMAPBASE and REMAPLIMIT are not locked')

        if remap_ok:
            if is_warning:
                self.logger.log_warning('Most Memory Remap registers are configured correctly and locked')
                self.logger.log('[!] Manual verification of REMAP BASE and LIMIT register values may be needed.')
                res = ModuleResult.WARNING
                self.result.setStatusBit(self.result.status.VERIFY)
            else:
                res = ModuleResult.PASSED
                self.result.setStatusBit(self.result.status.SUCCESS)
                self.logger.log_passed('Memory Remap is configured correctly and locked')
        else:
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.CONFIGURATION)
            self.result.setStatusBit(self.result.status.LOCKS)
            self.logger.log_failed('Memory Remap is not properly configured/locked. Remap attack may be possible')

        return self.result.getReturnCode(res)

    def run(self, _) -> int:
        self.logger.start_test('Memory Remapping Configuration')

        self.res = self.check_remap_config()
        return self.res
