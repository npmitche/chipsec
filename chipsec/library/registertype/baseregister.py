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

from chipsec.logger import logger
from chipsec.library.defines import is_all_ones


class BaseRegister:
    def __init__(self, cs, reg_name):
        self.cs = cs
        self.name = reg_name
        self.definition = self.get_def()

    def get_type(self):
        return self.cs.Cfg.REGISTERS[self.name]["type"]

    def read(self, cpu_thread: int = 0, bus: Optional[int] = None, do_check: bool = True) -> int:
        raise NotImplementedError()

    def write(self, reg_value: int, cpu_thread: int = 0, bus: Optional[int] = None) -> bool:
        raise NotImplementedError()

    def write_all(self, reg_values: List[int], cpu_thread: int = 0) -> bool:
        '''Writes values to all instances of a PCI register'''
        ret = False
        bus_data = self.get_bus()
        bus_len = len(bus_data)
        if len(reg_values) == bus_len:
            for index in range(bus_len):
                self.write(reg_values[index], cpu_thread, bus_data[index])
            ret = True
        return ret

    def get_def(self) -> Dict[str, Any]:
        raise NotImplementedError()

    def is_defined(self) -> bool:
        '''Checks if register is defined in the XML config'''
        try:
            return (self.cs.Cfg.REGISTERS[self.name] is not None)
        except KeyError:
            return False

    def get_bus(self) -> List[int]:
        '''Returns list of buses device/register was discovered on'''
        device = self.cs.Cfg.REGISTERS[self.name].get('device', '')
        if not device:
            if logger().DEBUG:
                logger().log_important(f"No device found for '{self.name}'")
            if 'bus' in self.cs.Cfg.REGISTERS[self.name]:
                return [self.cs.Cfg.REGISTERS[self.name]['bus']]
            else:
                return []
        return self.cs.device.get_bus(device)

    def read_all(self, cpu_thread: int = 0) -> List[int]:
        '''Reads all configuration register instances (by name)'''
        values = []
        bus_data = self.get_bus()
        if bus_data:
            for bus in bus_data:
                values.append(self.read(cpu_thread, bus))
        return values

    def write_all_single(self, reg_value: int, cpu_thread: int = 0) -> bool:
        '''Writes all configuration register instances (by name)'''
        bus_data = self.get_bus()
        if bus_data:
            for bus in bus_data:
                self.write(reg_value, cpu_thread, bus)
        else:
            self.write(reg_value)
        return True

    def read_dict(self) -> Dict[str, Any]:
        '''Returns complete register definition (with values)'''
        reg_value = self.read()
        reg_def = self.get_def()
        result = reg_def
        result['value'] = reg_value
        for f in reg_def['FIELDS']:
            result['FIELDS'][f]['bit'] = field_bit = int(reg_def['FIELDS'][f]['bit'])
            result['FIELDS'][f]['size'] = field_size = int(reg_def['FIELDS'][f]['size'])
            field_mask = 0
            for i in range(field_size):  # TODO: update this routine
                field_mask = (field_mask << 1) | 1
            result['FIELDS'][f]['value'] = (reg_value >> field_bit) & field_mask
        return result

    def get_field_mask(self, reg_field: Optional[str] = None, preserve_field_position: bool = False) -> int:
        '''Returns the field mask for a register field definition (by name)'''
        reg_def = self.get_def()
        if reg_field is not None:
            field_attrs = reg_def['FIELDS'][reg_field]
            mask_start = int(field_attrs['bit'])
            mask = (1 << int(field_attrs['size'])) - 1
        else:
            mask_start = 0
            mask = (1 << (reg_def['size'] * 8)) - 1
        if preserve_field_position:
            return mask << mask_start
        else:
            return mask

    def get_field(self, reg_value: int, field_name: str, preserve_field_position: bool = False) -> int:
        '''Reads the value of the field (by name) of configuration register (by register value)'''
        field_attrs = self.get_def()['FIELDS'][field_name]
        field_bit = int(field_attrs['bit'])
        field_mask = (1 << int(field_attrs['size'])) - 1
        if preserve_field_position:
            return reg_value & (field_mask << field_bit)
        else:
            return (reg_value >> field_bit) & field_mask

    def get_field_all(self, reg_values: List[int], field_name: str, preserve_field_position: bool = False) -> List[int]:
        '''Reads the value of the field (by name) of all configuration register instances (by register value)'''
        values = []
        for reg_value in reg_values:
            values.append(self.get_field(reg_value, field_name, preserve_field_position))
        return values

    def set_field(self, reg_value: int, field_name: str, field_value: int, preserve_field_position: bool = False) -> int:
        '''writes the value of the field (by name) of configuration register (by register value)'''
        field_attrs = self.get_def()['FIELDS'][field_name]
        field_bit = int(field_attrs['bit'])
        field_mask = (1 << int(field_attrs['size'])) - 1
        reg_value &= ~(field_mask << field_bit)  # keep other fields
        if preserve_field_position:
            reg_value |= (field_value & (field_mask << field_bit))
        else:
            reg_value |= ((field_value & field_mask) << field_bit)
        return reg_value

    def set_field_all(self, reg_values: List[int], field_name: str, field_value: int, preserve_field_position: bool = False) -> List[int]:
        '''Writes the value of the field (by name) of all configuration register instances (by register value)'''
        values = []
        for reg_value in reg_values:
            values.append(self.set_field(reg_value, field_name, field_value, preserve_field_position))
        return values

    def read_field(self, field_name: str, preserve_field_position: bool = False, cpu_thread: int = 0, bus: Optional[int] = None) -> int:
        '''Reads the value of the field (by name) of configuration register (by register name)'''
        reg_value = self.read(cpu_thread, bus)
        return self.get_field(reg_value, field_name, preserve_field_position)

    def read_field_all(self, field_name: str, preserve_field_position: bool = False, cpu_thread: int = 0) -> List[int]:
        '''Reads the value of the field (by name) of all configuration register instances (by register name)'''
        reg_values = self.read_all(cpu_thread)
        return self.get_field_all(reg_values, field_name, preserve_field_position)

    def write_field(self, field_name: str, field_value: int, preserve_field_position: bool = False, cpu_thread: int = 0) -> bool:
        '''Writes the value of the field (by name) of configuration register (by register name)'''
        try:
            reg_value = self.read(cpu_thread)
            reg_value_new = self.set_field(reg_value, field_name, field_value, preserve_field_position)
            ret = self.write(reg_value_new, cpu_thread)
        except Exception:
            ret = False
        return ret

    def write_field_all(self, field_name: str, field_value: int, preserve_field_position: bool = False, cpu_thread: int = 0) -> bool:
        '''Writes the value of the field (by name) of all configuration register instances (by register name)'''
        reg_values = self.read_all(cpu_thread)
        reg_values_new = self.set_field_all(reg_values, field_name, field_value, preserve_field_position)
        return self.write_all(reg_values_new, cpu_thread)

    def has_field(self, field_name: str) -> bool:
        '''Checks if the register has specific field'''
        try:
            reg_def = self.get_def()
        except KeyError:
            return False
        if 'FIELDS' not in reg_def:
            return False
        return (field_name in reg_def['FIELDS'])

    def has_all_fields(self, field_list: List[str]) -> bool:
        '''Checks if the register as all fields specified in list'''
        ret = True
        for field in field_list:
            ret = ret and self.has_field(field)
            if not ret:
                break
        return ret

    def _fields_str(self, reg_def: Dict[str, Any], reg_val: int) -> str:
        '''Returns string of all fields of a register and their values.'''
        reg_fields_str = ''
        if 'FIELDS' in reg_def:
            reg_fields_str += '\n'
            # sort fields by their bit position in the register
            sorted_fields = sorted(reg_def['FIELDS'].items(), key=lambda field: int(field[1]['bit']))
            for f in sorted_fields:
                field_attrs = f[1]
                field_bit = int(field_attrs['bit'])
                field_size = int(field_attrs['size'])
                field_mask = 0
                for i in range(field_size):
                    field_mask = (field_mask << 1) | 1
                field_value = (reg_val >> field_bit) & field_mask
                field_desc = f' << {field_attrs["desc"]} ' if (field_attrs['desc'] != '') else ''
                reg_fields_str += f'    [{field_bit:02d}] {f[0]:16} = {field_value:X}{field_desc}\n'

        if reg_fields_str:
            reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str

    def print(self, reg_val: int, bus: Optional[int] = None, cpu_thread: int = 0) -> str:
        raise NotImplementedError()

    def print_all(self, cpu_thread: int = 0) -> str:
        '''Prints all configuration register instances'''
        reg_str = ''
        bus_data = self.get_bus()
        if bus_data:
            for bus in bus_data:
                reg_val = self.read(cpu_thread, bus)
                reg_str += self.print(reg_val, bus)
        else:
            reg_val = self.read(cpu_thread)
            reg_str = self.print(reg_val)
        return reg_str

    def is_all_ffs(self, value: int) -> bool:
        '''Returns True if register value is all 0xFFs'''
        # if self.is_msr():
        #     size = 8
        # else:
        size = self.get_def()['size']
        return is_all_ones(value, size)

    def is_field_all_ones(self, field_name: str, value: int) -> bool:
        '''Returns True if field value is all ones'''
        reg_def = self.get_def()
        size = reg_def['FIELDS'][field_name]['size']
        return is_all_ones(value, size, 1)
