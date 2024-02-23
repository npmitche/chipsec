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

from chipsec.library.registertype.pci_register import PciRegister

'''
Register Factory
'''


class RegisterType:
    PCICFG = 'pcicfg'
    MMCFG = 'mmcfg'
    MMIO = 'mmio'
    MSR = 'msr'
    PORTIO = 'io'
    IOBAR = 'iobar'
    MSGBUS = 'msgbus'
    MM_MSGBUS = 'mm_msgbus'
    MEMORY = 'memory'
    IMA = 'indirect'


class RegisterFactory:
    def __init__(self, cs) -> None:
        self.cs = cs
        self.Registers = {
            RegisterType.PCICFG: PciRegister,
            # RegisterType.MMCFG: MmcfgRegister,
            # RegisterType.MMIO: MmioRegister,
            # RegisterType.MSR: MsrRegister,
            # RegisterType.PORTIO: PortioRegister,
            # RegisterType.IOBAR: IobarRegister,
            # RegisterType.MSGBUS: MsgbusRegister,
            # RegisterType.MM_MSGBUS: MmmsgbusRegister,
            # RegisterType.MEMORY: MemoryRegister,
            # RegisterType.IMA: ImaRegister,
        }

    def create_all_registers(self):
        for name in self.cs.Cfg.REGISTERS:
            self.reg_factory(name)
        return self.Registers

    def reg_factory(self, reg_name: str): 
        if reg_name not in self.cs.Cfg.REGISTER_OBJS:
            reg_type = self.get_reg_type(reg_name)
            if reg_type in self.Registers:
                self.cs.Cfg.REGISTER_OBJS[reg_name] = self.Registers[reg_type](self.cs, reg_name)

    def get_reg_type(self, reg_name: str):
        return self.cs.Cfg.REGISTERS[reg_name]['type']
