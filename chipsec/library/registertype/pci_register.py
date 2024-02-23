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


from typing import Any, Dict, List, Optional
from chipsec.exceptions import CSReadError
from chipsec.library.registertype.baseregister import BaseRegister

from chipsec.logger import logger
from chipsec.library.device import Device


class PciRegister(BaseRegister):
    def read(self, cpu_thread: int = 0, bus: Optional[int] = None, do_check: bool = True) -> int:
        '''Returns PCI register value'''
        reg_value = 0
        if bus is not None:
            b = Device.get_first(bus)
        else:
            b = Device.get_first_bus(self.definition)
        d = self.definition['dev']
        f = self.definition['fun']
        o = self.definition['offset']
        size = self.definition['size']
        if do_check and self.cs.consistency_checking:
            if self.cs.pci.get_DIDVID(b, d, f) == (0xFFFF, 0xFFFF):
                raise CSReadError(f'PCI Device is not available ({b}:{d}.{f})')
        reg_value = self.cs.pci.read(b, d, f, o, size)
        return reg_value

    def write(self, reg_value: int, cpu_thread: int = 0, bus: Optional[int] = None) -> bool:
        '''Writes PCI register value'''
        if bus is not None:
            b = bus
        else:
            b = Device.get_first_bus(self.definition)
        d = self.definition['dev']
        f = self.definition['fun']
        o = self.definition['offset']
        size = self.definition['size']
        self.cs.pci.write(b, d, f, o, reg_value, size)
        return True

    def get_def(self) -> Dict[str, Any]:
        '''Return complete register definition'''
        reg_def = self.cs.Cfg.REGISTERS[self.name]
        if "device" in reg_def:
            dev_name = reg_def["device"]
            if dev_name in self.cs.Cfg.CONFIG_PCI:
                dev = self.cs.Cfg.CONFIG_PCI[dev_name]
                reg_def['bus'] = Device.get_first_bus(dev)
                reg_def['dev'] = dev['dev']
                reg_def['fun'] = dev['fun']
        return reg_def

    def print(self, reg_val: int, bus: Optional[int] = None, cpu_thread: int = 0) -> str:
        '''Prints configuration register'''
        reg = self.get_def()
        reg_str = ''
        reg_width = reg["size"] * 2
        reg_val_str = f'0x{reg_val:0{reg_width:d}X}'

        if bus is not None:
            b = bus
        else:
            b = Device.get_first_bus(reg)
        d = reg['dev']
        f = reg['fun']
        o = reg['offset']

        reg_str = f'[*] {self.name} = {reg_val_str} << {reg["desc"]} (b:d.f {b:02d}:{d:02d}.{f:d} + 0x{o:X})'

        reg_str += self._fields_str(reg, reg_val)
        logger().log(reg_str)
        return reg_str
