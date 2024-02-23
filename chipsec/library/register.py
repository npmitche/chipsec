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

'''
Main functionality to read/write configuration registers based on their XML configuration
Not Needed?
'''

from typing import Any, Dict, List, Optional
from chipsec.library.registertype.pci_register import PciRegister

from chipsec.logger import logger
from chipsec.library.defines import is_all_ones
from chipsec.exceptions import CSReadError, RegisterTypeNotFoundError
from chipsec.library.registertype.register_factory import RegisterType, RegisterFactory


class Register:
    def __init__(self, cs):
        self.cs = cs

    def factory(self):
        factory = RegisterFactory(self.cs)
        factory.create_all_registers()



    # def get_memory_def(self, reg_def: Dict[str, Any], dev_name: str) -> Dict[str, Any]:
    #     '''Return address access of a MEM register'''
    #     if dev_name in self.cs.Cfg.MEMORY_RANGES:
    #         dev = self.cs.Cfg.MEMORY_RANGES[dev_name]
    #         reg_def['address'] = dev['address']
    #         reg_def['access'] = dev['access']
    #     else:
    #         logger().log_error(f'Memory device {dev_name} not found')
    #     return reg_def

    # def get_indirect_def(self, reg_def: Dict[str, Any], dev_name: str) -> Dict[str, Any]:
    #     '''Return base index data of a IMA register'''
    #     if dev_name in self.cs.Cfg.IMA_REGISTERS:
    #         dev = self.cs.Cfg.IMA_REGISTERS[dev_name]
    #         if ('base' in dev):
    #             reg_def['base'] = dev['base']
    #         else:
    #             reg_def['base'] = "0"
    #         if (dev['index'] in self.cs.Cfg.REGISTERS):
    #             reg_def['index'] = dev['index']
    #         else:
    #             logger().log_error(f'Index register {dev["index"]} not found')
    #         if (dev['data'] in self.cs.Cfg.REGISTERS):
    #             reg_def['data'] = dev['data']
    #         else:
    #             logger().log_error(f'Data register {dev["data"]} not found')
    #     else:
    #         logger().log_error(f'Indirect access device {dev_name} not found')
    #     return reg_def

    # def get_def(self, reg_name: str) -> Dict[str, Any]:
    #     '''Return complete register definition'''
    #     reg_def = self.cs.Cfg.REGISTERS[reg_name]
    #     if "device" in reg_def:
    #         dev_name = reg_def["device"]
    #         if reg_def["type"] in ["pcicfg", "mmcfg"]:
    #             reg_def = self.get_pci_def(reg_def, dev_name)
    #         elif reg_def["type"] == "memory":
    #             reg_def = self.get_memory_def(reg_def, dev_name)
    #         elif reg_def["type"] == "indirect":
    #             reg_def = self.get_indirect_def(reg_def, dev_name)
    #     return reg_def

    

    # def _read_pci(self, bus: Optional[int], reg: Dict[str, Any], rtype: str, do_check: bool) -> int:
    #     '''Returns PCI register value'''
    #     reg_value = 0
    #     if bus is not None:
    #         b = self.cs.get_first(bus)
    #     else:
    #         b = self.cs.get_first_bus(reg)
    #     d = reg['dev']
    #     f = reg['fun']
    #     o = reg['offset']
    #     size = reg['size']
    #     if do_check and self.cs.consistency_checking:
    #         if self.cs.pci.get_DIDVID(b, d, f) == (0xFFFF, 0xFFFF):
    #             raise CSReadError(f'PCI Device is not available ({b}:{d}.{f})')
    #     if RegisterType.PCICFG == rtype:
    #         if 1 == size:
    #             reg_value = self.cs.pci.read_byte(b, d, f, o)
    #         elif 2 == size:
    #             reg_value = self.cs.pci.read_word(b, d, f, o)
    #         elif 4 == size:
    #             reg_value = self.cs.pci.read_dword(b, d, f, o)
    #         elif 8 == size:
    #             reg_value = (self.cs.pci.read_dword(b, d, f, o + 4) << 32) | self.cs.pci.read_dword(b, d, f, o)
    #     elif RegisterType.MMCFG == rtype:
    #         reg_value = self.cs.mmio.read_mmcfg_reg(b, d, f, o, size)
    #     return reg_value

    # def _read_mmio(self, bus: Optional[int], reg: Dict[str, Any]) -> int:
    #     '''Returns MMIO register value'''
    #     _bus = bus
    #     if self.cs.mmio.get_MMIO_BAR_base_address(reg['bar'], _bus)[0] != 0:
    #         reg_value = self.cs.mmio.read_MMIO_BAR_reg(reg['bar'], reg['offset'], reg['size'], _bus)
    #     else:
    #         raise CSReadError(f'MMIO Bar ({reg["bar"]}) base address is 0')
    #     return reg_value

    # def _read_msr(self, cpu_thread: int, reg: Dict[str, Any]) -> int:
    #     '''Returns MSR register value'''
    #     (eax, edx) = self.cs.msr.read_msr(cpu_thread, reg['msr'])
    #     return (edx << 32) | eax

    # def _read_portio(self, reg: Dict[str, Any]) -> int:
    #     '''Returns PORTIO register value'''
    #     port = reg['port']
    #     size = reg['size']
    #     return self.cs.io._read_port(port, size)

    # def _read_iobar(self, reg: Dict[str, Any]) -> int:
    #     '''Returns IOBAR register value'''
    #     if self.cs.iobar.get_IO_BAR_base_address(reg['bar'])[0] != 0:
    #         reg_value = self.cs.iobar.read_IO_BAR_reg(reg['bar'], reg['offset'], reg['size'])
    #     else:
    #         raise CSReadError(f'IO Bar ({reg["bar"]}) base address is 0')
    #     return reg_value

    # def _read_memory(self, reg: Dict[str, Any]) -> int:
    #     '''Returns MEM register value'''
    #     reg_value = 0
    #     if reg['access'] == 'dram':
    #         size = reg['size']
    #         if 1 == size:
    #             reg_value = self.cs.mem.read_physical_mem_byte(reg['address'])
    #         elif 2 == size:
    #             reg_value = self.cs.mem.read_physical_mem_word(reg['address'])
    #         elif 4 == size:
    #             reg_value = self.cs.mem.read_physical_mem_dword(reg['address'])
    #         elif 8 == size:
    #             reg_value = self.cs.mem.read_physical_mem_qword(reg['address'])
    #     elif reg['access'] == 'mmio':
    #         reg_value = self.cs.mmio.read_MMIO_reg(reg['address'], reg['offset'], reg['size'])
    #     return reg_value

    # def _read_ima(self, reg: Dict[str, Any]) -> int:
    #     '''Returns IMA register value'''
    #     self.write(reg['index'], reg['offset'] + reg['base'])
    #     return self.read(reg['data'])

    # def read(self, reg_name: str, cpu_thread: int=0, bus: Optional[int]=None, do_check: bool=True) -> int:
    #     '''Reads configuration register (by name)'''

    #     reg = self.get_def(reg_name)
    #     rtype = reg['type']
    #     reg_value = 0
    #     if (rtype == RegisterType.PCICFG) or (rtype == RegisterType.MMCFG):
    #         reg_value = self._read_pci(bus, reg, rtype, do_check)
    #     elif rtype == RegisterType.MMIO:
    #         reg_value = self._read_mmio(bus, reg)
    #     elif rtype == RegisterType.MSR:
    #         reg_value = self._read_msr(cpu_thread, reg)
    #     elif rtype == RegisterType.PORTIO:
    #         reg_value = self._read_portio(reg)
    #     elif rtype == RegisterType.IOBAR:
    #         reg_value = self._read_iobar(reg)
    #     elif rtype == RegisterType.MSGBUS:
    #         reg_value = self.cs.msgbus.msgbus_reg_read(reg['port'], reg['offset'])
    #     elif rtype == RegisterType.MM_MSGBUS:
    #         reg_value = self.cs.msgbus.mm_msgbus_reg_read(reg['port'], reg['offset'])
    #     elif rtype == RegisterType.MEMORY:
    #         reg_value = self._read_memory(reg)
    #     elif rtype == RegisterType.IMA:
    #         reg_value = self._read_ima(reg)
    #     else:
    #         raise RegisterTypeNotFoundError(f'Register type not found: {rtype}')

    #     return reg_value

    

    # def _write_pci(self, bus: Optional[int], reg: Dict[str, Any], rtype: str, reg_value: int) -> None:
    #     '''Writes PCI register value'''
    #     if bus is not None:
    #         b = bus
    #     else:
    #         b = self.cs.get_first_bus(reg)
    #     d = reg['dev']
    #     f = reg['fun']
    #     o = reg['offset']
    #     size = reg['size']
    #     if RegisterType.PCICFG == rtype:
    #         if 1 == size:
    #             self.cs.pci.write_byte(b, d, f, o, reg_value)
    #         elif 2 == size:
    #             self.cs.pci.write_word(b, d, f, o, reg_value)
    #         elif 4 == size:
    #             self.cs.pci.write_dword(b, d, f, o, reg_value)
    #         elif 8 == size:
    #             self.cs.pci.write_dword(b, d, f, o, (reg_value & 0xFFFFFFFF))
    #             self.cs.pci.write_dword(b, d, f, o + 4, (reg_value >> 32 & 0xFFFFFFFF))
    #     elif RegisterType.MMCFG == rtype:
    #         self.cs.mmio.write_mmcfg_reg(b, d, f, o, size, reg_value)

    # def _write_msr(self, reg: Dict[str, Any], reg_value: int, cpu_thread: int) -> None:
    #     '''Writes MSR register value'''
    #     eax = (reg_value & 0xFFFFFFFF)
    #     edx = ((reg_value >> 32) & 0xFFFFFFFF)
    #     self.cs.msr.write_msr(cpu_thread, reg['msr'], eax, edx)

    # def _write_portio(self, reg: Dict[str, Any], reg_value: int) -> None:
    #     '''Writes PORTIO register value'''
    #     port = reg['port']
    #     size = reg['size']
    #     self.cs.io._write_port(port, reg_value, size)

    # def _write_memory(self, reg: Dict[str, Any], reg_value: int) -> None:
    #     '''Writes MEM register value'''
    #     if reg['access'] == 'dram':
    #         self.cs.mem.write_physical_mem(reg['address'], reg['size'], reg_value)
    #     elif reg['access'] == 'mmio':
    #         self.cs.mmio.write_MMIO_reg(reg['address'], reg['offset'], reg_value, reg['size'])

    # def _write_ima(self, reg: Dict[str, Any], reg_value: int) -> None:
    #     '''Writes IMA register value'''
    #     self.write(reg['index'], reg['offset'] + reg['base'])
    #     self.write(reg['data'], reg_value)

    # def write(self, reg_name: str, reg_value: int, cpu_thread: int=0, bus: Optional[int]=None) -> bool:
    #     '''Writes configuration register (by name)'''
    #     reg = self.get_def(reg_name)
    #     rtype = reg['type']
    #     if (rtype == RegisterType.PCICFG) or (rtype == RegisterType.MMCFG):
    #         self._write_pci(bus, reg, rtype, reg_value)
    #     elif rtype == RegisterType.MMIO:
    #         self.cs.mmio.write_MMIO_BAR_reg(reg['bar'], reg['offset'], reg_value, reg['size'], bus)
    #     elif rtype == RegisterType.MSR:
    #         self._write_msr(reg, reg_value, cpu_thread)
    #     elif rtype == RegisterType.PORTIO:
    #         self._write_portio(reg, reg_value)
    #     elif rtype == RegisterType.IOBAR:
    #         self.cs.iobar.write_IO_BAR_reg(reg['bar'], reg['offset'], reg['size'], reg_value)
    #     elif rtype == RegisterType.MSGBUS:
    #         self.cs.msgbus.msgbus_reg_write(reg['port'], reg['offset'], reg_value)
    #     elif rtype == RegisterType.MM_MSGBUS:
    #         self.cs.msgbus.mm_msgbus_reg_write(reg['port'], reg['offset'], reg_value)
    #     elif rtype == RegisterType.MEMORY:
    #         self._write_memory(reg, reg_value)
    #     elif rtype == RegisterType.IMA:
    #         self._write_ima(reg, reg_value)
    #     else:
    #         raise RegisterTypeNotFoundError(f'Register type not found: {rtype}')
    #     return True

    # def _write_msr_all(self, reg: Dict[str, Any], reg_name: str, reg_values: List[int]) -> bool:
    #     '''Writes values to all instances of an MSR register'''
    #     ret = False
    #     topology = self.cs.cpu.get_cpu_topology()
    #     if 'scope' in reg.keys() and reg['scope'] == "packages":
    #         packages = topology['packages']
    #         threads_to_use = [packages[p][0] for p in packages]
    #     elif 'scope' in reg.keys() and reg['scope'] == "cores":
    #         cores = topology['cores']
    #         threads_to_use = [cores[p][0] for p in cores]
    #     else:  # Default to threads
    #         threads_to_use = range(self.cs.helper.get_threads_count())
    #     if len(reg_values) == len(threads_to_use):
    #         value = 0
    #         for t in threads_to_use:
    #             self.write(reg_name, reg_values[value], t)
    #             value += 1
    #         ret = True
    #     return ret



    # def write_all(self, reg_name: str, reg_values: List[int], cpu_thread: int=0) -> bool:
    #     '''Writes all configuration register instances (by name)'''
    #     reg = self.get_def(reg_name)
    #     rtype = reg['type']
    #     bus_data = self.get_bus(reg_name)
    #     ret = False
    #     if rtype == RegisterType.MSR:
    #         ret = self._write_msr_all(reg, reg_name, reg_values)
    #     elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
    #         ret = self._write_pci_all(reg_name, reg_values, cpu_thread, bus_data)
    #     else:
    #         if len(reg_values) == 1:
    #             ret = self.write(reg_name, reg_values[0])
    #     if not ret and logger().DEBUG:
    #         logger().log("[write_register_all] There is a mismatch in the number of register values and registers to write")
    #     return ret


    # def print(self, reg_name: str, reg_val: int, bus: Optional[int]=None, cpu_thread: int=0) -> str:
    #     '''Prints configuration register'''
    #     reg = self.get_def(reg_name)
    #     rtype = reg['type']
    #     reg_str = ''
    #     reg_width = reg["size"] * 2
    #     reg_val_str = f'0x{reg_val:0{reg_width:d}X}'
    #     if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
    #         if bus is not None:
    #             b = bus
    #         else:
    #             b = self.cs.get_first_bus(reg)
    #         d = reg['dev']
    #         f = reg['fun']
    #         o = reg['offset']
    #         mmcfg_off_str = ''
    #         if RegisterType.MMCFG == rtype:
    #             mmcfg_off = (b * 32 * 8 + d * 8 + f) * 0x1000 + o
    #             mmcfg_off_str += f', MMCFG + 0x{mmcfg_off:X}'
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (b:d.f {b:02d}:{d:02d}.{f:d} + 0x{o:X}{mmcfg_off_str})'
    #     elif RegisterType.MMIO == rtype:
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} ({reg["bar"]} + 0x{reg["offset"]:X})'
    #     elif RegisterType.MSR == rtype:
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (MSR 0x{reg["msr"]:X} Thread 0x{cpu_thread:X})'
    #     elif RegisterType.PORTIO == rtype:
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (I/O port 0x{reg["port"]:X})'
    #     elif RegisterType.IOBAR == rtype:
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (I/O {reg["bar"]} + 0x{reg["offset"]:X})'
    #     elif RegisterType.MSGBUS == rtype or RegisterType.MM_MSGBUS == rtype:
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (msgbus port 0x{reg["port"]:X}, off 0x{reg["offset"]:X})'
    #     elif RegisterType.IMA == rtype:
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]} (indirect access via {reg["index"]}/{reg["data"]}, base 0x{reg["base"]:X}, off 0x{reg["offset"]:X})'
    #     else:
    #         reg_str = f'[*] {reg_name} = {reg_val_str} << {reg["desc"]}'

    #     reg_str += self._fields_str(reg, reg_val)
    #     logger().log(reg_str)
    #     return reg_str

    # def print_all(self, reg_name: str, cpu_thread: int=0) -> str:
    #     '''Prints all configuration register instances'''
    #     reg_str = ''
    #     bus_data = self.get_bus(reg_name)
    #     reg = self.get_def(reg_name)
    #     rtype = reg['type']
    #     if RegisterType.MSR == rtype:
    #         topology = self.cs.cpu.get_cpu_topology()
    #         if 'scope' in reg.keys() and reg['scope'] == "packages":
    #             packages = topology['packages']
    #             threads_to_use = [packages[p][0] for p in packages]
    #         elif 'scope' in reg.keys() and reg['scope'] == "cores":
    #             cores = topology['cores']
    #             threads_to_use = [cores[p][0] for p in cores]
    #         else:  # Default to threads
    #             threads_to_use = range(self.cs.helper.get_threads_count())
    #         for t in threads_to_use:
    #             reg_val = self.read(reg_name, t)
    #             reg_str += self.print(reg_name, reg_val, cpu_thread=t)
    #     elif rtype in [RegisterType.MMCFG, RegisterType.PCICFG, RegisterType.MMIO] and bus_data:
    #         for bus in bus_data:
    #             reg_val = self.read(reg_name, cpu_thread, bus)
    #             reg_str += self.print(reg_name, reg_val, bus)
    #     else:
    #         reg_val = self.read(reg_name, cpu_thread)
    #         reg_str = self.print(reg_name, reg_val)
    #     return reg_str

    
