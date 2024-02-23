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
from chipsec.library.register import RegisterType
from chipsec.library.registertype.baseregister import BaseRegister


from chipsec.library.defines import is_all_ones


class PciRegister(BaseRegister):
    def read(self, cpu_thread: int = 0, bus: Optional[int] = None, do_check: bool = True) -> int:
        pass

    def write(self, reg_value: int, cpu_thread: int=0, bus: Optional[int]=None) -> bool:
        pass
    
    def write_all(self, reg_values: List[int], cpu_thread: int=0) -> bool:
        pass
    
    def _get_def(self) -> Dict[str, Any]:
        pass
        
    def is_device_enabled(self, bus: Optional[int]=None) -> bool:
        '''Checks if device is defined in the XML config'''
        if self.name in self.cs.Cfg.REGISTERS:
            reg = self.get_def()
            rtype = reg['type']
            if (rtype == RegisterType.MMCFG) or (rtype == RegisterType.PCICFG):
                if bus is not None:
                    b = bus
                else:
                    b = self.cs.device.get_first_bus(reg)
                d = reg['dev']
                f = reg['fun']
                return self.cs.pci.is_enabled(b, d, f)
            elif (rtype == RegisterType.MMIO):
                bar_name = reg['bar']
                return self.cs.mmio.is_MMIO_BAR_enabled(bar_name, bus)
        return False
    
    def read_all(self, cpu_thread: int=0) -> List[int]:
        '''Reads all configuration register instances (by name)'''
        values = []
        bus_data = self.get_bus()
        reg = self.get_def()
        rtype = reg['type']
        if RegisterType.MSR == rtype:
            topology = self.cs.cpu.get_cpu_topology()
            if 'scope' in reg.keys() and reg['scope'] == "packages":
                packages = topology['packages']
                threads_to_use = [packages[p][0] for p in packages]
            elif 'scope' in reg.keys() and reg['scope'] == "cores":
                cores = topology['cores']
                threads_to_use = [cores[p][0] for p in cores]
            else:  # Default to threads
                threads_to_use = range(self.cs.helper.get_threads_count())
            for t in threads_to_use:
                values.append(self.read(t))
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO]:
            if bus_data:
                for bus in bus_data:
                    values.append(self.read(cpu_thread, bus))
        else:
            values.append(self.read(cpu_thread))
        return values
    
    def write_all_single(self, reg_value: int, cpu_thread: int=0) -> bool:
        '''Writes all configuration register instances (by name)'''
        reg = self.get_def()
        rtype = reg['type']
        bus_data = self.get_bus()
        if RegisterType.MSR == rtype:
            topology = self.cs.cpu.get_cpu_topology()
            if 'scope' in reg.keys() and reg['scope'] == "packages":
                packages = topology['packages']
                threads_to_use = [packages[p][0] for p in packages]
            elif 'scope' in reg.keys() and reg['scope'] == "cores":
                cores = topology['cores']
                threads_to_use = [cores[p][0] for p in cores]
            else:  # Default to threads
                threads_to_use = range(self.cs.helper.get_threads_count())
            for t in threads_to_use:
                self.write(reg_value, t)
        elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
            for bus in bus_data:
                self.write(reg_value, cpu_thread, bus)
        else:
            self.write(reg_value)
        return True


    
    
    def print(self, reg_val: int, bus: Optional[int]=None, cpu_thread: int=0) -> str:
        pass
    
    def print_all(self, cpu_thread: int=0) -> str:
        pass
    
    def is_msr(self) -> bool:
        '''Returns True if register is type `msr`'''
        return False

    def is_pci(self) -> bool:
        '''Returns True if register is type `pcicfg` or `mmcfg`'''       
        return True


    def is_all_ffs(self, value: int) -> bool:
        '''Returns True if register value is all 0xFFs'''
        if self.is_msr():
            size = 8
        else:
            size = self.get_def()['size']
        return is_all_ones(value, size)

    def is_field_all_ones(self, field_name: str, value: int) -> bool:
        '''Returns True if field value is all ones'''
        reg_def = self.get_def()
        size = reg_def['FIELDS'][field_name]['size']
        return is_all_ones(value, size, 1)
        