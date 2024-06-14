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

import typing
from chipsec.exceptions import UninitializedRegisterError

from chipsec.parsers import BaseConfigHelper
from chipsec.lib.bits import set_bits, get_bits, make_mask


class BaseConfigRegisterHelper(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super(BaseConfigRegisterHelper, self).__init__(cfg_obj)
        self.name = cfg_obj['name']
        self.instance = cfg_obj['instance'] if 'instance' in cfg_obj else None
        self.value = None
        self.desc = cfg_obj['desc']
        if 'default' in cfg_obj:
            self.default = cfg_obj['default']
        else:
            self.default = None
        self.fields = cfg_obj['FIELDS']

    def read(self):
        """Read the object"""
        raise NotImplementedError()

    def write(self, value):
        """Write the object"""
        raise NotImplementedError()

    def set_value(self, value):
        self.value = value

    def set_field(self, field_name: str, field_value: int) -> None:
        field_attrs = self.fields[field_name]
        bit = field_attrs['bit']
        size = field_attrs['size']
        self.value = set_bits(bit, size, self.value, field_value)
        return self.value

    def get_field(self, field_name: str, preserve_field_position: typing.Optional[bool] = False) -> int:
        if self.value is None:
            self.read()
        field_attrs = self.fields[field_name]
        field_bit = field_attrs['bit']
        field_size = field_attrs['size']
        return get_bits(self.value, field_bit, field_size, preserve_field_position)

    def has_field(self, field_name):
        return self.fields.get(field_name, None) is not None

    def get_mask(self):
        mask = make_mask(self.size * 8)
        return mask

    def get_field_mask(self, reg_field: str, preserve_field_position: typing.Optional[bool] = False) -> int:
        field_attrs = self.fields[reg_field]
        mask_start = 0
        size = field_attrs['size']
        if preserve_field_position:
            mask_start = field_attrs['bit']
        mask = make_mask(size, mask_start)
        return mask

    def write_field(self, field_name, field_value, update_value=False):
        if update_value:
            self.read()
        if self.value is None:
            raise UninitializedRegisterError()
        new_value = self.set_field(field_name, field_value)
        self.write(new_value)

    def read_field(self, field_name: str, preserve_field_position: typing.Optional[bool] = False) -> int:
        self.read()
        return self.get_field(field_name, preserve_field_position)

    def _register_fields_str(self, verbose=False) -> str:
        reg_fields_str = ''
        if self.fields:
            reg_fields_str += '\n'
            # sort fields by their bit position in the register
            sorted_fields = sorted(self.fields.items(), key=lambda field: field[1]['bit'])
            for f in sorted_fields:
                field_attrs = f[1]
                field_bit = field_attrs['bit']
                field_size = field_attrs['size']
                field_mask = 0
                for _ in range(field_size):
                    field_mask = (field_mask << 1) | 1
                field_desc = (' << ' + field_attrs['desc'] + ' ') if (field_attrs['desc'] != '') else ''
                field_default = f'(default: {field_attrs["default"]})' if 'default' in field_attrs and verbose else ''
                field_access = f'(access: {field_attrs["access"]})' if 'access' in field_attrs and verbose else ''
                if self.value is not None:
                    field_value = (self.value >> field_bit) & field_mask
                    reg_fields_str += (f'    [{field_bit:02d}] {f[0]:16} = {field_value:X}{field_access}{field_default}{field_desc}\n')

        if '' != reg_fields_str:
            reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str
